#!/bin/sh
# Commands are issued only through an authenticated SSH connection on a reviewed endpoint.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
action=$1
port=$2
token=$3
unit=velum-ssh-port.service
unit_file=/etc/systemd/system/$unit
stage_timer=velum-ssh-port-stage
restore_timer=velum-ssh-restore-22
lock=/run/velum-ssh-port.lock
close_state=/run/velum-ssh-close-22
config=/etc/ssh/sshd_config
sshd=/usr/sbin/sshd

reply() { printf 'VELUM_SSH_PORT:%s\n' "$1"; }
fail() { reply "$1"; exit 1; }
case "$port" in ''|*[!0-9]*) fail BAD_PORT;; esac
[ "${#port}" -le 5 ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$port" -ne 22 ] || fail BAD_PORT
case "$token" in *[!0-9a-f]*|'') fail INVALID;; esac
[ "${#token}" -eq 32 ] || fail INVALID
[ "$(id -u)" = 0 ] || fail ROOT_REQUIRED
[ -d /run/systemd/system ] && [ -x "$sshd" ] && [ -f "$config" ] || fail UNSUPPORTED
grep -Eq '^ID=(ubuntu|debian|"ubuntu"|"debian")$' /etc/os-release || fail UNSUPPORTED
command -v flock >/dev/null && command -v ss >/dev/null && command -v systemd-run >/dev/null || fail UNSUPPORTED
[ ! -L "$lock" ] || fail UNSUPPORTED
exec 9>"$lock"
flock -w 5 9 || fail BUSY
incoming=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk 'NF == 4 {print $4}')
case "$action" in
    prepare) [ "$incoming" = 22 ] || fail WRONG_PORT ;;
    persist|close|finish) [ "$incoming" = "$port" ] || fail WRONG_PORT ;;
    *) fail INVALID ;;
esac

unit_contents() {
    cat <<UNIT
# Managed by VELUM SSH port migration
[Unit]
Description=OpenSSH on the verified VELUM port $port
After=network.target
[Service]
Type=exec
TimeoutStartSec=15
TimeoutStopSec=15
ExecStartPre=/usr/bin/mkdir -p -m 0755 /run/sshd
ExecStartPre=$sshd -t -f $config -p $port -o PidFile=/run/velum-ssh-port.pid
ExecStart=$sshd -D -f $config -p $port -o PidFile=/run/velum-ssh-port.pid
KillMode=process
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
}

owned_file() {
    [ -f "$unit_file" ] && [ ! -L "$unit_file" ] && unit_contents | cmp -s - "$unit_file"
}
owned_definition() {
    owned_file &&
        [ "$(systemctl show --value -p FragmentPath "$unit")" = "$unit_file" ] &&
        [ -z "$(systemctl show --value -p DropInPaths "$unit")" ]
}
owned_listener() {
    owned_definition && systemctl is-active --quiet "$unit" || return 1
    pid=$(systemctl show --value -p MainPID "$unit") || return 1
    case "$pid" in ''|0|*[!0-9]*) return 1;; esac
    listeners=$(ss -H -ltnp "sport = :$port") || return 1
    printf '%s\n' "$listeners" | awk -v pid="$pid" '
        NF && !index($0,"pid=" pid ",") {exit 1}
        NF {found=1}
        END {if (!found) exit 1}'
}

# Tools that guess the SSH port from ssh.service or sshd_config (Debian fail2ban defaults, the 3x-ui
# IP-limit jail) would otherwise guard port 22 and could ban the operator on the new port.
# Drop-ins are written even when fail2ban is not installed yet, so a later install picks them up.
fail2ban_dropins() {
    mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/action.d || return 1
    printf '%s\n' "# Managed by VELUM SSH port migration: OpenSSH listens on $port via $unit" \
        "[sshd]" "port = $port" \
        "journalmatch = _SYSTEMD_UNIT=$unit + _COMM=sshd + _COMM=sshd-session" \
        >/etc/fail2ban/jail.d/velum-ssh-port.local || return 1
    printf '%s\n' "# Managed by VELUM SSH port migration: an IP-limit ban never blocks SSH on $port" \
        "[Init]" "exemptports = $port,%(known/exemptports)s" \
        >/etc/fail2ban/action.d/3x-ipl.local || return 1
    chmod 0644 /etc/fail2ban/jail.d/velum-ssh-port.local /etc/fail2ban/action.d/3x-ipl.local || return 1
    if systemctl is-active --quiet fail2ban.service; then
        fail2ban-client reload >/dev/null 2>&1 || systemctl restart fail2ban.service || return 1
    fi
}

standard_config() {
    [ "$(systemctl show --value -p Id ssh.service)" = ssh.service ] || fail UNSUPPORTED
    fragment=$(systemctl show --value -p FragmentPath ssh.service) || fail UNSUPPORTED
    case "$fragment" in /lib/systemd/system/ssh.service|/usr/lib/systemd/system/ssh.service) ;; *) fail CUSTOM_CONFIG ;; esac
    user=$(systemctl show --value -p User ssh.service) || fail UNSUPPORTED
    case "$user" in ''|root) ;; *) fail CUSTOM_CONFIG ;; esac
    dropins=$(systemctl show --value -p DropInPaths ssh.service) || fail UNSUPPORTED
    for dropin in $dropins; do
        case "$dropin" in
            /etc/systemd/system/ssh.service.d/00-socket.conf|/usr/lib/systemd/system/ssh.service.d/00-socket.conf|/lib/systemd/system/ssh.service.d/00-socket.conf)
                # The Ubuntu socket drop-in may change unit dependencies, but not daemon settings.
                awk '
                    {sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "")}
                    $0 == "" || $0 ~ /^#/ || $0 == "[Unit]" {next}
                    $0 == "Requires=ssh.socket" || $0 == "After=ssh.socket" {next}
                    {exit 1}' "$dropin" || fail CUSTOM_CONFIG ;;
            *) fail CUSTOM_CONFIG ;;
        esac
    done
    command=$(systemctl show --value -p ExecStart ssh.service) || fail UNSUPPORTED
    case "$command" in
        *'argv[]=/usr/sbin/sshd -D ;'*|*'argv[]=/usr/sbin/sshd -D $SSHD_OPTS ;'*) ;;
        *) fail CUSTOM_CONFIG ;;
    esac
    env=$(systemctl show --value -p Environment ssh.service) || fail UNSUPPORTED
    case "$env" in ''|SSHD_OPTS=) ;; *) fail CUSTOM_CONFIG ;; esac
    env_files=$(systemctl show --value -p EnvironmentFiles ssh.service) || fail UNSUPPORTED
    case "$env_files" in ''|'/etc/default/ssh (ignore_errors=yes)') ;; *) fail CUSTOM_CONFIG ;; esac
    pass_env=$(systemctl show --value -p PassEnvironment ssh.service) || fail UNSUPPORTED
    [ -z "$pass_env" ] || fail CUSTOM_CONFIG
    if [ -f /etc/default/ssh ]; then
        defaults=$(sed 's/#.*$//; s/[[:space:]]//g; /^$/d' /etc/default/ssh) || fail CUSTOM_CONFIG
        case "$defaults" in ''|'SSHD_OPTS='|'SSHD_OPTS=""'|"SSHD_OPTS=''") ;; *) fail CUSTOM_CONFIG ;; esac
    fi
    # The port may not silently change authentication rules in an included Match LocalPort block.
    for file in "$config" /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$file" ] || continue
        awk -v main="$config" '
            {sub(/#.*/, "")}
            tolower($1) == "include" &&
                (FILENAME != main || NF != 2 || $2 != "/etc/ssh/sshd_config.d/*.conf") {exit 1}
            tolower($1) == "match" && tolower($0) ~ /localport/ {exit 1}' "$file" || fail CUSTOM_CONFIG
    done
}

effective_listeners() {
    old_config=$("$sshd" -T -f "$config" 2>/dev/null) || fail CONFIG_CHECK
    new_config=$("$sshd" -T -f "$config" -p "$port" 2>/dev/null) || fail CONFIG_CHECK
    addresses() {
        printf '%s\n' "$1" | awk -v p="$2" '
            $1 == "port" && $2 != p {exit 1}
            $1 == "listenaddress" {
                if ($2 !~ (":" p "$")) exit 1
                sub(":" p "$","",$2); print $2; found=1
            }
            END {if (!found) exit 1}'
    }
    old_addresses=$(addresses "$old_config" 22) || fail CUSTOM_CONFIG
    new_addresses=$(addresses "$new_config" "$port") || fail CUSTOM_CONFIG
    [ "$old_addresses" = "$new_addresses" ] || fail CUSTOM_CONFIG
}

old_listener() {
    service_active=no
    socket_active=no
    if systemctl is-active --quiet ssh.service; then service_active=yes; fi
    if systemctl is-active --quiet ssh.socket; then socket_active=yes; fi
    [ "$service_active$socket_active" != nono ] || fail OLD_NOT_FOUND
    old_pid=$(systemctl show --value -p MainPID ssh.service) || fail UNSUPPORTED
    case "$old_pid" in ''|*[!0-9]*) fail UNSUPPORTED;; esac
    if [ "$socket_active" = yes ]; then
        [ "$(systemctl show --value -p Id ssh.socket)" = ssh.socket ] || fail CUSTOM_CONFIG
        streams=$(systemctl show --value -p Listen ssh.socket) || fail CUSTOM_CONFIG
        # Support the wildcard sockets OpenSSH ships: one dual-stack [::]:22 (older Debian/Ubuntu) or,
        # from the Ubuntu 24.04 sshd-socket-generator, separate 0.0.0.0:22 + [::]:22 with BindIPv6Only=ipv6-only.
        # Custom bind addresses stay untouched.
        bind_mode=$(systemctl show --value -p BindIPv6Only ssh.socket) || fail CUSTOM_CONFIG
        case "$bind_mode" in
            both) ;;
            default|'') [ "$(cat /proc/sys/net/ipv6/bindv6only 2>/dev/null)" = 0 ] || bind_mode=ipv6-only ;;
            ipv6-only) ;;
            *) fail CUSTOM_CONFIG ;;
        esac
        printf '%s\n' "$streams" | awk -v mode="$bind_mode" '
            {for(i=1;i<=NF;i++) if($i!="(Stream)") {
                if($i!="[::]:22" && $i!="*:22" && $i!="0.0.0.0:22") exit 1
                if($i=="0.0.0.0:22") v4=1; else v6=1
            }}
            END {if(!v6 || (mode=="ipv6-only" && !v4)) exit 1}' || fail CUSTOM_CONFIG
        printf '%s\n' "$old_addresses" | awk '$0!="0.0.0.0" && $0!="[::]" {exit 1}' || fail CUSTOM_CONFIG
    fi
    listeners=$(ss -H -ltnp) || fail UNSUPPORTED
    printf '%s\n' "$listeners" | awk -v pid="$old_pid" -v sock="$socket_active" '
        NF {
            sshd=(pid!="0" && index($0,"pid=" pid ","))
            socket=(sock=="yes" && index($0,"pid=1,"))
            if (sshd && $4 !~ /:22$/) exit 1
            if ($4 ~ /:22$/) {
                if (!sshd && !socket) exit 1
                rest=$0
                while (match(rest,/pid=[0-9]+,/)) {
                    who=substr(rest,RSTART+4,RLENGTH-5)
                    if (who!=pid && !(sock=="yes" && who=="1")) exit 1
                    rest=substr(rest,RSTART+RLENGTH)
                }
                found=1
            }
        }
        END {if (!found) exit 1}' || fail CUSTOM_CONFIG
}

case "$action" in
    prepare)
        standard_config
        effective_listeners
        old_listener
        if [ -e "$unit_file" ] || [ -L "$unit_file" ]; then
            owned_file || fail OTHER_MIGRATION
            if owned_listener; then
                if systemctl is-enabled --quiet "$unit" || systemctl is-active --quiet "$stage_timer.timer"; then
                    reply READY; exit 0
                fi
                fail OTHER_MIGRATION
            fi
            systemctl is-enabled --quiet "$unit" && fail OTHER_MIGRATION
        else
            [ "$(systemctl show --value -p LoadState "$unit")" = not-found ] || fail OTHER_MIGRATION
        fi
        occupied=$(ss -H -ltn "sport = :$port") || fail UNSUPPORTED
        [ -z "$occupied" ] || fail PORT_BUSY
        systemctl is-active --quiet "$stage_timer.timer" && fail BUSY
        if ! owned_file; then
            tmp=$(mktemp "$unit_file.XXXXXX") || fail CONFIG_WRITE
            trap 'rm -f "$tmp"' EXIT
            unit_contents >"$tmp" && chmod 0644 "$tmp" && ln "$tmp" "$unit_file" || fail CONFIG_WRITE
        fi
        # systemd < 250 drops a transient timer's service on daemon-reload ("Unit to trigger vanished"),
        # so the definition is loaded first and the timer is created after the last reload.
        systemctl daemon-reload || { rm -f "$unit_file"; systemctl daemon-reload; fail START_FAILED; }
        owned_definition || fail OTHER_MIGRATION
        # Before the service is enabled, the server owns the timeout, even if Android disconnects.
        digest=$(unit_contents | sha256sum | awk '{print $1}')
        systemd-run --quiet --unit="$stage_timer" --on-active=180s /bin/sh -c '
            exec 9>"$1"
            flock 9 || exit 1
            file=$2; digest=$3; unit=$4
            [ -f "$file" ] && [ ! -L "$file" ] || exit 0
            [ "$(sha256sum "$file" | awk "{print \$1}")" = "$digest" ] || exit 0
            systemctl is-enabled --quiet "$unit" && exit 0
            if systemctl is-active --quiet "$unit"; then
                [ "$(systemctl show --value -p FragmentPath "$unit")" = "$file" ] || exit 1
                [ -z "$(systemctl show --value -p DropInPaths "$unit")" ] || exit 1
                systemctl stop "$unit" || exit 1
            fi
            rm -f "$file" && systemctl daemon-reload
        ' restore "$lock" "$unit_file" "$digest" "$unit" 9>&- || { rm -f "$unit_file"; systemctl daemon-reload; fail TIMER_FAILED; }
        systemctl start "$unit" && owned_listener || fail START_FAILED
        reply READY
        ;;
    persist)
        owned_listener || fail NEW_NOT_VERIFIED
        if ! systemctl is-enabled --quiet "$unit"; then
            systemctl is-active --quiet "$stage_timer.timer" || fail STAGE_EXPIRED
            systemctl enable --quiet "$unit" && systemctl is-enabled --quiet "$unit" || fail START_FAILED
            systemctl stop "$stage_timer.timer" >/dev/null 2>&1 || :
            systemctl reset-failed "$stage_timer.timer" "$stage_timer.service" >/dev/null 2>&1 || :
        fi
        # Best effort: the new port already works; a fail2ban problem must not undo it.
        fail2ban_dropins || :
        reply SAVED
        ;;
    close)
        owned_listener && systemctl is-enabled --quiet "$unit" || fail NEW_NOT_VERIFIED
        [ ! -e "$close_state" ] && [ ! -L "$close_state" ] && ! systemctl is-active --quiet "$restore_timer.timer" || fail BUSY
        standard_config
        effective_listeners
        old_listener
        service_enabled=$(systemctl is-enabled ssh.service 2>/dev/null || :)
        case "$service_enabled" in enabled|disabled) ;; *) fail CUSTOM_CONFIG ;; esac
        socket_enabled=absent
        if [ "$(systemctl show --value -p LoadState ssh.socket)" = loaded ]; then
            socket_enabled=$(systemctl is-enabled ssh.socket 2>/dev/null || :)
            case "$socket_enabled" in enabled|disabled) ;; *) fail CUSTOM_CONFIG ;; esac
        fi
        # Keep boot enablement until the new port has been reached again from Android.
        # The timer also restores enablement if disabling the old units only partially succeeds.
        systemd-run --quiet --unit="$restore_timer" --on-active=120s /bin/sh -c '
            exec 9>"$1"
            flock 9 || exit 1
            [ -f "$2" ] || exit 0
            read -r current service_enabled socket_enabled service_active socket_active <"$2"
            [ "$current" = "$3" ] || exit 0
            restored=yes
            [ "$socket_enabled" != enabled ] || systemctl enable --quiet ssh.socket || restored=no
            [ "$service_enabled" != enabled ] || systemctl enable --quiet ssh.service || restored=no
            [ "$socket_active" != yes ] || systemctl start ssh.socket || restored=no
            [ "$service_active" != yes ] || systemctl start ssh.service || restored=no
            [ "$restored" = yes ] && rm -f "$2"
        ' restore "$lock" "$close_state" "$token" 9>&- || fail TIMER_FAILED
        umask 077
        printf '%s %s %s %s %s\n' "$token" "$service_enabled" "$socket_enabled" "$service_active" "$socket_active" >"$close_state" || fail CONFIG_WRITE
        if [ "$socket_active" = yes ]; then systemctl stop ssh.socket || fail CLOSE_PENDING; fi
        if [ "$service_active" = yes ]; then systemctl stop ssh.service || fail CLOSE_PENDING; fi
        # ssh.service may remove its runtime directory on stop. The new unit never owns it.
        mkdir -p -m 0755 /run/sshd || fail CLOSE_PENDING
        occupied=$(ss -H -ltn 'sport = :22') || fail CLOSE_PENDING
        [ -z "$occupied" ] && owned_listener || fail CLOSE_PENDING
        reply CLOSED_PENDING
        ;;
    finish)
        owned_listener && systemctl is-enabled --quiet "$unit" || fail NEW_NOT_VERIFIED
        [ -f "$close_state" ] && systemctl is-active --quiet "$restore_timer.timer" || fail STAGE_EXPIRED
        read -r current service_enabled socket_enabled service_active socket_active <"$close_state" || fail CLOSE_PENDING
        [ "$current" = "$token" ] || fail CLOSE_PENDING
        occupied=$(ss -H -ltn 'sport = :22') || fail CLOSE_PENDING
        [ -z "$occupied" ] || fail CLOSE_PENDING
        # Old systemd drops transient rollback timers on daemon-reload. Keep the timer alive
        # until both persistent changes and removal of the rollback state have succeeded.
        if [ "$socket_enabled" = enabled ]; then systemctl disable --no-reload --quiet ssh.socket || fail CLOSE_PENDING; fi
        if [ "$service_enabled" = enabled ]; then systemctl disable --no-reload --quiet ssh.service || fail CLOSE_PENDING; fi
        rm "$close_state" || fail CLOSE_PENDING
        systemctl stop "$restore_timer.timer" >/dev/null 2>&1 || :
        systemctl reset-failed "$restore_timer.timer" "$restore_timer.service" >/dev/null 2>&1 || :
        systemctl daemon-reload >/dev/null 2>&1 || :
        fail2ban_dropins || :
        reply CLOSED
        ;;
esac
