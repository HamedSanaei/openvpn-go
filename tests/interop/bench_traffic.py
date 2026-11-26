"""Generate a fixed UDP echo workload in the isolated client namespace."""

import json
import socket
import struct
import sys
import time


def run(host, port, count):
    size = 1200
    filler = bytes((i % 251 for i in range(size - 4)))
    received = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.connect((host, port))
        start = time.monotonic()
        for base in range(0, count, 32):
            end = min(base + 32, count)
            for seq in range(base, end):
                sock.send(struct.pack("!I", seq) + filler)
            deadline = time.monotonic() + (0.15 if count == 1 else 0.04)
            batch_received = 0
            while batch_received < end - base:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data = sock.recv(size + 1)
                except (TimeoutError, ConnectionRefusedError):
                    break
                if len(data) != size or data[4:] != filler:
                    raise ValueError("wrong echo payload")
                (seq,) = struct.unpack("!I", data[:4])
                if seq >= end or seq in received:
                    raise ValueError("invalid echo sequence")
                received.add(seq)
                if seq >= base:
                    batch_received += 1
        return {
            "sent": count,
            "received": len(received),
            "seconds": time.monotonic() - start,
        }


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))))
