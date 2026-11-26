#!/usr/bin/env bash
set -euo pipefail
umask 077

# Run from the checkout root. The private directory must be outside it.
if [ "$#" -ne 2 ]; then
    echo "Usage from checkout root: routeros-lab.sh start|stop private-directory" >&2
    exit 2
fi
action=$1
lab=$(realpath -m -- "$2")
repo=$(pwd -P)
test -f "$repo/tests/interop/routeros-console.py"
case "$lab/" in "$repo/"*|*,*) echo "Choose a private directory outside the checkout" >&2; exit 2 ;; esac

stop_process() {
    local pid attached
    pid=$(sudo cat "$lab/$1.pid" 2>/dev/null) || return 0
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    attached=$(sudo ip netns identify "$pid" 2>/dev/null) || return 0
    if [ "$attached" = "$namespace" ]; then
        sudo kill -TERM "$pid"
    fi
}

stop_lab() {
    stop_process http
    stop_process qemu
    sudo ip netns del "$namespace"
}

if [ "$action" = stop ]; then
    namespace=$(cat "$lab/namespace")
    [[ "$namespace" =~ ^chr16-[0-9a-f]{8}$ ]] || exit 2
    stop_lab
    exit
fi
test "$action" = start
mkdir -- "$lab"
mkdir "$lab/transfer"
namespace="chr16-$(openssl rand -hex 4)"
printf '%s\n' "$namespace" > "$lab/namespace"
cd "$lab"

image=chr-7.25.2.img
curl -fsSL --retry 2 --max-time 120 \
    "https://download.mikrotik.com/routeros/7.25.2/$image.zip" -o "$image.zip"
printf '%s  %s\n' b0df0acb3f2070fb94d9e30bd8a8566bb622034786bb4f759f837cf2aa05bacb "$image.zip" | sha256sum -c
unzip -q "$image.zip" "$image"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -sha256 -subj /CN=OVPN-CHR-Lab-CA \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout ca.key -out transfer/ca.pem > certificates.log 2>&1
for role in server client; do
    eku=clientAuth
    common=chr-lab-client
    if [ "$role" = server ]; then eku=serverAuth; common=vpn.lab.test; fi
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$common" \
        -keyout "$role.key" -out "$role.csr" >> certificates.log 2>&1
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=DNS:%s\n' \
        "$eku" "$common" > "$role.ext"
    openssl x509 -req -sha256 -days 7 -in "$role.csr" -CA transfer/ca.pem -CAkey ca.key \
        -CAcreateserial -extfile "$role.ext" -out "$role.pem" >> certificates.log 2>&1
done
cp server.key server.pem transfer/
{ printf 'chr-lab-user\n'; openssl rand -hex 18; } > auth
openssl rand -hex 18 > admin

sudo ip netns add "$namespace"
trap 'stop_lab' ERR
sudo ip -n "$namespace" link set lo up
sudo ip netns exec "$namespace" ip tuntap add dev chr16tap mode tap
sudo ip -n "$namespace" address add 192.0.2.1/24 dev chr16tap
sudo ip -n "$namespace" link set chr16tap up
sudo ip netns exec "$namespace" qemu-system-x86_64 -machine accel=kvm:tcg -m 512 -smp 2 \
    -display none -monitor none -serial "unix:$lab/console.sock,server=on,wait=off" \
    -drive "file=$lab/$image,format=raw,if=virtio" -snapshot \
    -netdev tap,id=lab,ifname=chr16tap,script=no,downscript=no -device virtio-net-pci,netdev=lab \
    -daemonize -pidfile "$lab/qemu.pid" > qemu.log 2>&1
sudo chown "$(id -u):$(id -g)" "$lab/console.sock"
sudo ip netns exec "$namespace" sh -c '
    umask 077
    nohup python3 -m http.server 18880 --bind 192.0.2.1 --directory "$1/transfer" > "$1/http.log" 2>&1 </dev/null &
    echo $! > "$1/http.pid"
' sh "$lab"

echo '/ip address add address=192.0.2.2/24 interface=ether1' > network.rsc
# Give the guest services time to initialize before using the first-login console.
sleep 20
python3 "$repo/tests/interop/routeros-console.py" "$lab" network.rsc
sudo ip netns exec "$namespace" ping -q -c 2 -W 1 192.0.2.2
cat > provision.rsc <<'EOF'
/tool fetch url=http://192.0.2.1:18880/ca.pem dst-path=ca.pem
/tool fetch url=http://192.0.2.1:18880/server.pem dst-path=server.pem
/tool fetch url=http://192.0.2.1:18880/server.key dst-path=server.key
/certificate import file-name=ca.pem passphrase=""
/certificate import file-name=server.pem passphrase=""
/certificate import file-name=server.key passphrase=""
/certificate set [find where common-name="OVPN-CHR-Lab-CA"] trusted=yes
/certificate set [find where common-name="vpn.lab.test"] name=labserver trusted=yes
/ip pool add name=chr16pool ranges=10.61.0.2-10.61.0.10
/ppp profile add name=ovpnlab local-address=10.61.0.1 remote-address=chr16pool
EOF
printf '/ppp secret add name=chr-lab-user password=%s service=ovpn profile=ovpnlab\n' "$(sed -n '2p' auth)" >> provision.rsc
for spec in '1194 tcp AES-256-GCM aes256-gcm' '1195 udp AES-256-GCM aes256-gcm' \
    '1196 tcp AES-128-GCM aes128-gcm' '1197 udp AES-128-GCM aes128-gcm'; do
    read -r port network cipher router_cipher <<< "$spec"
    printf '/interface/ovpn-server/server/add name=lab%s port=%s protocol=%s mode=ip default-profile=ovpnlab certificate=labserver tls-version=only-1.2 cipher=%s auth=null require-client-certificate=yes disabled=no\n' \
        "$port" "$port" "$network" "$router_cipher" >> provision.rsc
    protocol=udp4
    if [ "$network" = tcp ]; then protocol=tcp4-client; fi
    {
        printf 'client\ndev tun\nremote 192.0.2.2 %s %s\nremote-cert-tls server\nverify-x509-name vpn.lab.test name\ntls-version-min 1.2\ntls-version-max 1.2\nauth-user-pass\ndata-ciphers %s\n' \
            "$port" "$protocol" "$cipher"
        for name in ca cert key; do
            printf '<%s>\n' "$name"
            case "$name" in ca) cat transfer/ca.pem ;; cert) cat client.pem ;; key) cat client.key ;; esac
            printf '</%s>\n' "$name"
        done
    } > "$port.ovpn"
    sed 's/^data-ciphers /compat-fixed-aead /' "$port.ovpn" > "$port-fixed.ovpn"
done
python3 "$repo/tests/interop/routeros-console.py" "$lab" provision.rsc
stop_process http
trap - ERR
echo "CHR lab ready in namespace $namespace"
