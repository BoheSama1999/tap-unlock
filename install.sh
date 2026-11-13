#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo "must run as root (pkexec/sudo)" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
TARGET=${1:-${SUDO_USER:-}}
[ -n "$TARGET" ] || [ -z "${PKEXEC_UID:-}" ] || TARGET=$(id -nu "$PKEXEC_UID")
[ -n "$TARGET" ] && [ "$TARGET" != root ] || { echo "usage: $0 <desktop-user>" >&2; exit 1; }
id "$TARGET" >/dev/null

LIB=/usr/local/lib/tap-unlock
MARK="# tap-unlock"
PAM_LINE="auth       sufficient   pam_exec.so quiet seteuid stdout $LIB/pam-helper"

install -Dm644 "$HERE/laptop/tapunlock_protocol.py" "$LIB/tapunlock_protocol.py"
install -Dm755 "$HERE/laptop/tapunlockd.py" "$LIB/tapunlockd.py"
install -Dm755 "$HERE/laptop/pam-helper.py" "$LIB/pam-helper"
install -Dm644 "$HERE/laptop/system/tap-unlock.service" /etc/systemd/system/tap-unlock.service
install -Dm644 "$HERE/laptop/system/sysusers.conf" /etc/sysusers.d/tap-unlock.conf
install -Dm644 "$HERE/laptop/system/50-tap-unlock.rules" /etc/polkit-1/rules.d/50-tap-unlock.rules
install -dm755 /etc/tap-unlock /etc/tap-unlock/keys
[ -f /etc/tap-unlock/tap-unlock.conf ] ||
    printf 'TAPUNLOCK_USER=%s\nTAPUNLOCK_WAIT=10\n' "$TARGET" > /etc/tap-unlock/tap-unlock.conf
systemd-sysusers /etc/sysusers.d/tap-unlock.conf

systemctl daemon-reload
systemctl enable tap-unlock.service
systemctl restart tap-unlock.service

add_pam_line() {
    grep -qx "$MARK" "$1" && return 0
    cp -p "$1" "$1.tap-unlock.bak"
    awk -v mark="$MARK" -v line="$PAM_LINE" '
        !done && !/^#%PAM/ { print mark; print line; done = 1 }
        { print }
        END { if (!done) { print mark; print line } }' "$1" > "$1.tap-unlock.new"
    chmod 644 "$1.tap-unlock.new"
    mv "$1.tap-unlock.new" "$1"
}

add_pam_line /etc/pam.d/sudo
if [ ! -e /etc/pam.d/polkit-1 ]; then
    cp -p /usr/lib/pam.d/polkit-1 /etc/pam.d/polkit-1
    touch /etc/tap-unlock/.created-pam-polkit-1
fi
add_pam_line /etc/pam.d/polkit-1

echo "installed for user $TARGET; put the phone public key in /etc/tap-unlock/keys/<name>.pem"
