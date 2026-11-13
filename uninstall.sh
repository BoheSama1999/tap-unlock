#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo "must run as root (pkexec/sudo)" >&2; exit 1; }

MARK="# tap-unlock"

drop_pam_line() {
    [ -f "$1" ] && grep -qx "$MARK" "$1" || return 0
    sed -i "/^$MARK\$/,+1d" "$1"
}

drop_pam_line /etc/pam.d/sudo
drop_pam_line /etc/pam.d/polkit-1
rm -f /etc/pam.d/sudo.tap-unlock.bak /etc/pam.d/polkit-1.tap-unlock.bak
if [ -e /etc/tap-unlock/.created-pam-polkit-1 ]; then
    rm -f /etc/pam.d/polkit-1
fi

systemctl disable --now tap-unlock.service 2>/dev/null || true
rm -f /etc/systemd/system/tap-unlock.service /etc/sysusers.d/tap-unlock.conf \
      /etc/polkit-1/rules.d/50-tap-unlock.rules
rm -rf /usr/local/lib/tap-unlock /etc/tap-unlock
systemctl daemon-reload
userdel tapunlock 2>/dev/null || true
echo "tap-unlock removed"
