#!/bin/sh
# Dedicated authorized test-server setup. Not shipped in the application APK.
set -eu
gate() {
    [ "$(id -u)" = 0 ] || return 1
    grep -Eq '^ID=(ubuntu|debian|"ubuntu"|"debian")$' /etc/os-release || return 1
    [ -d /usr/local/x-ui ] && [ -x /usr/local/x-ui/x-ui ] || return 1
    [ -f /etc/x-ui/x-ui.db ] && [ -r /etc/x-ui/x-ui.db ] || return 1
    [ "$(systemctl is-active -- x-ui.service 2>/dev/null)" = active ] || return 1
    [ -d /var/tmp ] && [ ! -L /var/tmp ] && [ "$(stat -c %u /var/tmp)" = 0 ] || return 1
    command -v apt-get >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 || return 1
}
intent_gate() {
    intent=/var/tmp/velum-test-sqlite-192-0-2-169-v1
    if [ -e "$intent" ] || [ -L "$intent" ]; then
        [ -d "$intent" ] && [ ! -L "$intent" ] && [ "$(stat -c %u "$intent")" = 0 ] && [ "$(stat -c %a "$intent")" = 700 ] &&
        [ -d "$intent/complete" ] && [ ! -L "$intent/complete" ] && [ "$(stat -c %u "$intent/complete")" = 0 ] && [ "$(stat -c %a "$intent/complete")" = 700 ] || return 1
    fi
}
case "${1:-}" in
    preflight)
        gate || { printf 'SETUP_BLOCKED\n'; exit 70; }
        intent_gate || { printf 'SETUP_PRIOR_INTENT\n'; exit 73; }
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 --version >/dev/null 2>&1 || { printf 'SETUP_BLOCKED\n'; exit 70; }
            printf 'SETUP_ALREADY_READY\n'
        else
            printf 'SETUP_SQLITE_MISSING\n'
        fi
        ;;
    install)
        gate || { printf 'SETUP_BLOCKED\n'; exit 70; }
        if command -v sqlite3 >/dev/null 2>&1; then printf 'SETUP_BLOCKED\n'; exit 70; fi
        umask 077
        # Atomic permanent intent: no deletion/retry after partial or unknown execution.
        mkdir /var/tmp/velum-test-sqlite-192-0-2-169-v1 2>/dev/null || { printf 'SETUP_PRIOR_INTENT\n'; exit 73; }
        if timeout -k 10s 240s sh -c '
            export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
            apt-get -o DPkg::Lock::Timeout=0 -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update &&
            apt-get -o DPkg::Lock::Timeout=0 -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 --no-install-recommends --no-upgrade --no-remove -y install sqlite3
        ' >/dev/null 2>&1; then
            sqlite3 --version >/dev/null 2>&1 || { printf 'SETUP_INSTALL_UNVERIFIED\n'; exit 74; }
            gate || { printf 'SETUP_INSTALL_UNVERIFIED\n'; exit 74; }
            mkdir /var/tmp/velum-test-sqlite-192-0-2-169-v1/complete 2>/dev/null || { printf 'SETUP_INSTALL_UNVERIFIED\n'; exit 74; }
            printf 'SETUP_INSTALLED\n'
        else
            printf 'SETUP_INSTALL_UNVERIFIED\n'
            exit 74
        fi
        ;;
    readback)
        gate || { printf 'SETUP_BLOCKED\n'; exit 70; }
        intent_gate || { printf 'SETUP_PRIOR_INTENT\n'; exit 73; }
        command -v sqlite3 >/dev/null 2>&1 && sqlite3 --version >/dev/null 2>&1 || { printf 'SETUP_BLOCKED\n'; exit 70; }
        printf 'SETUP_READY\n'
        ;;
    *) exit 64 ;;
esac
