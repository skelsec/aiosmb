#!/bin/sh
set -eu

username="${AIOSMB_SAMBA_USERNAME:-aiosmbtest}"
password="${AIOSMB_SAMBA_PASSWORD:-Aiosmb-Test-Only-1!}"
workgroup="${AIOSMB_SAMBA_WORKGROUP:-AIOSMB}"
share="${AIOSMB_SAMBA_SHARE:-interop}"

case "$username" in
    *[!A-Za-z0-9_.-]* | "") echo "invalid test username" >&2; exit 2 ;;
esac
case "$workgroup" in
    *[!A-Za-z0-9_-]* | "") echo "invalid test workgroup" >&2; exit 2 ;;
esac
case "$share" in
    *[!A-Za-z0-9_.-]* | "") echo "invalid test share name" >&2; exit 2 ;;
esac
if [ -z "$password" ]; then
    echo "test password must not be empty" >&2
    exit 2
fi

if ! id "$username" >/dev/null 2>&1; then
    adduser \
        --disabled-password \
        --gecos "" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        "$username" >/dev/null
fi

printf '%s\n%s\n' "$password" "$password" \
    | smbpasswd -s -a "$username" >/dev/null

install -d -m 0700 -o "$username" -g "$username" /srv/samba/interop
sed \
    -e "s/@WORKGROUP@/${workgroup}/g" \
    -e "s/@SHARE@/${share}/g" \
    /etc/samba/smb.conf.template > /etc/samba/smb.conf

testparm -s /etc/samba/smb.conf >/dev/null
rm -f /run/samba/smbd.pid

exec smbd --foreground --no-process-group --debug-stdout
