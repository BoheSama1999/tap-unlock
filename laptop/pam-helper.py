#!/usr/bin/python3 -I
import json
import os
import pwd
import socket
import subprocess
import sys

SOCKET_PATH = "/run/tap-unlock/pam.sock"
HARD_TIMEOUT = 20


def command_of(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return "?"
    return " ".join(arg.decode(errors="replace") for arg in raw.split(b"\0") if arg)[:200]


def notify(user, title, body, seconds):
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return
    bus = f"/run/user/{pw.pw_uid}/bus"
    if not os.path.exists(bus):
        return
    subprocess.Popen(
        ["setpriv", f"--reuid={pw.pw_uid}", f"--regid={pw.pw_gid}", "--init-groups",
         "env", f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}",
         "notify-send", "-a", "Tap Unlock", "-i", "dialog-password", "-t", str(seconds * 1000), title, body],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)


def main():
    if os.environ.get("PAM_TYPE") != "auth":
        return 1
    user = os.environ.get("PAM_USER", "")
    service = os.environ.get("PAM_SERVICE", "")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(HARD_TIMEOUT)
            sock.connect(SOCKET_PATH)
            sock.sendall(json.dumps({"user": user, "service": service}).encode())
            replies = sock.makefile("r")
            first = replies.readline().split()
            if first[:1] != ["WAIT"]:
                return 1
            seconds = int(first[1]) if len(first) > 1 else 10
            print(f"贴一下手机确认（{seconds} 秒内），否则改用密码…", flush=True)
            if service == "sudo":
                notify(user, "sudo 等待贴手机确认", command_of(os.getppid()), seconds)
            return 0 if replies.readline().strip() == "OK" else 1
    except (OSError, ValueError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
