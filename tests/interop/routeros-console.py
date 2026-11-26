"""Drive a disposable CHR serial console without printing router output."""

import pathlib
import re
import socket
import sys
import time


def run(lab, commands):
    ansi = re.compile(rb"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|.)")
    prompt = rb"\[admin@[^]\r\n]+\]\s*>"
    password = (lab / "admin").read_text().strip()
    with socket.socket(socket.AF_UNIX) as console:
        console.connect(str(lab / "console.sock"))
        console.settimeout(0.4)

        def send(line):
            console.sendall(line.encode() + b"\r")

        def wait(pattern, seconds, stage, quiet=False, pulse=False):
            out = bytearray()
            limit = time.monotonic() + seconds
            next_pulse = time.monotonic() + 5
            while time.monotonic() < limit and len(out) < 128 * 1024:
                try:
                    part = console.recv(8192)
                except TimeoutError:
                    if quiet and re.search(pattern, ansi.sub(b"", out), re.I):
                        return ansi.sub(b"", out)
                    if pulse and time.monotonic() >= next_pulse:
                        send("")
                        next_pulse = time.monotonic() + 5
                    continue
                if not part:
                    break
                out.extend(part)
                clean = ansi.sub(b"", out)
                if not quiet and re.search(pattern, clean, re.I):
                    return clean
            raise SystemExit(f"CHR console response deadline during {stage}")

        marker = lab / "admin-configured"
        send("")
        banner = wait(rb"login:\s*$|" + prompt, 45, "boot", quiet=True, pulse=True)
        if not re.search(prompt, banner, re.I):
            send("admin")
            wait(rb"password:\s*$", 12, "login", quiet=True)
            send(password if marker.exists() else "")
            state = wait(rb"software license|new password\s*>|login failure|" + prompt, 12, "authentication", quiet=True)
            if b"login failure" in state.lower():
                raise SystemExit("CHR rejected the lab console login")
            if b"software license" in state.lower():
                send("n")
                state = wait(rb"new password\s*>|" + prompt, 12, "license prompt")
            if b"new password" in state.lower():
                send(password)
                wait(rb"(repeat|confirm|retype|again).*password\s*>", 12, "password confirmation")
                send(password)
                wait(prompt, 12, "post-login prompt")
                marker.touch(mode=0o600)

        for number, line in enumerate(commands.read_text().splitlines(), 1):
            send(line)
            result = wait(prompt + rb"[ \r\n]*$", 20, f"command {number}", quiet=True)
            if re.search(
                rb"(failure:|syntax error|bad command name|expected end of command|input does not match)",
                result, re.I,
            ):
                raise SystemExit(f"CHR rejected lab command {number}")
    print("CHR lab commands completed")


if __name__ == "__main__":
    run(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
