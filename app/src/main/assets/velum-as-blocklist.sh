#!/bin/sh
# Managed by VELUM. Blocks the networks published by https://github.com/C24Be/AS_Network_List
# Usage: velum-as-blocklist status | install <vk:0|1> | update | apply | remove
set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
action=${1:-status}
self=/usr/local/sbin/velum-as-blocklist
state=/var/lib/velum-as-blocklist
conf=$state/config
source_url=https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists
table=velum_blocklist
unit_dir=/etc/systemd/system
lists=$state
work=

reply() { printf 'VELUM_BL:%s\n' "$1"; }
info() { printf 'VELUM_BL_INFO:%s=%s\n' "$1" "$2"; }
cleanup() { [ -n "$work" ] && rm -rf "$work"; return 0; }
fail() { cleanup; reply "$1"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

case "$action" in status|install|update|apply|remove) ;; *) fail INVALID ;; esac
if [ "$(id -u)" != 0 ]; then
    if [ -f "$0" ] && have sudo && sudo -n true 2>/dev/null; then
        exec sudo -n env SSH_CONNECTION="${SSH_CONNECTION:-}" sh "$0" "$@"
    fi
    fail ROOT_REQUIRED
fi

# The address this SSH session came from; empty when run by the timer or at boot.
client=${SSH_CONNECTION:-}
client=${client%% *}
case "$client" in *[!0-9a-fA-F.:]*) client= ;; esac

read_conf() { [ -f "$conf" ] && sed -n "s/^$1=//p" "$conf" | head -n 1; }
backend=$(read_conf backend)
vk=$(read_conf vk)
case "$backend" in nft|ipset) ;; *) backend= ;; esac
[ "$vk" = 1 ] || vk=0

os_name() {
    ( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-}}" ) | tr -cd 'A-Za-z0-9 ._()/-' | cut -c1-60
}

package_manager() {
    for candidate in apt-get dnf yum apk pacman zypper; do
        have "$candidate" && { printf '%s' "$candidate"; return 0; }
    done
    return 1
}

install_packages() {
    case "$(package_manager)" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null 2>&1 || {
                apt-get update -q >/dev/null 2>&1
                DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null 2>&1
            } ;;
        dnf) dnf install -y -q "$@" >/dev/null 2>&1 ;;
        yum) yum install -y -q "$@" >/dev/null 2>&1 ;;
        apk) apk add --no-cache "$@" >/dev/null 2>&1 ;;
        pacman) pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1 ;;
        zypper) zypper -n install "$@" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

# nftables must be reachable from this kernel and new enough for overlapping prefixes.
nft_works() {
    have nft || return 1
    nft list tables >/dev/null 2>&1 || return 1
    printf 'table inet velum_probe {\n set s {\n  type ipv4_addr\n  flags interval\n  auto-merge\n }\n}\n' |
        nft -c -f - >/dev/null 2>&1
}
ipset_works() { have ipset && have iptables && ipset list -n >/dev/null 2>&1; }

backend_works() {
    case "$backend" in nft) nft_works ;; ipset) ipset_works ;; *) return 1 ;; esac
}

# What this server can use right now, without installing anything.
available_backend() {
    if nft_works; then printf nft; elif ipset_works; then printf ipset; else printf none; fi
}

choose_backend() {
    backend=$(available_backend)
    [ "$backend" != none ] && return 0
    install_packages nftables
    nft_works && { backend=nft; return 0; }
    install_packages ipset iptables
    ipset_works && { backend=ipset; return 0; }
    backend=
    return 1
}

fetch() {
    if have curl; then curl -fsSL --connect-timeout 10 --max-time 60 --retry 2 -o "$2" "$1"
    else wget -q -T 20 -O "$2" "$1"; fi
}

# Only well-formed prefixes survive, so a damaged or hostile download cannot inject firewall
# commands; very wide prefixes are refused so one bad line cannot cut the server off the internet.
clean4() {
    grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$' "$1" 2>/dev/null |
        awk -F/ '{ split($1, o, "."); if (o[1] > 255 || o[2] > 255 || o[3] > 255 || o[4] > 255) next
                   if (NF == 1 || $2 >= 8) print }' | sort -u
}
clean6() {
    grep -iE '^[0-9a-f:]+(/[0-9]{1,3})?$' "$1" 2>/dev/null | grep ':' |
        awk -F/ 'NF == 1 || ($2 >= 16 && $2 <= 128)' | sort -u
}
count() { if [ -f "$1" ]; then grep -c . "$1"; else printf 0; fi; }

in_list4() {
    awk -v ip="$1" '
        function n(a,  p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
        BEGIN { t = n(ip) }
        { split($0, c, "/"); bits = (c[2] == "" ? 32 : c[2]); size = 2 ^ (32 - bits)
          if (int(t / size) == int(n(c[1]) / size)) { found = 1; exit } }
        END { exit found ? 0 : 1 }' "$2"
}

nft_set() {
    printf '  set %s {\n    type %s\n    flags interval\n    auto-merge\n' "$1" "$2"
    if [ -s "$3" ]; then printf '    elements = { '; tr '\n' ',' < "$3"; printf ' }\n'; fi
    printf '  }\n'
}

apply_nft() {
    rules=$state/rules.nft
    {
        printf 'table inet %s\ndelete table inet %s\ntable inet %s {\n' "$table" "$table" "$table"
        nft_set gov4 ipv4_addr "$lists/gov4.txt"
        nft_set gov6 ipv6_addr "$lists/gov6.txt"
        if [ "$vk" = 1 ]; then
            nft_set vk4 ipv4_addr "$lists/vk4.txt"
            nft_set vk6 ipv6_addr "$lists/vk6.txt"
        fi
        printf '  chain input { type filter hook input priority -10; policy accept;\n'
        printf '    ct state new ip saddr @gov4 counter drop\n    ct state new ip6 saddr @gov6 counter drop\n  }\n'
        printf '  chain forward { type filter hook forward priority -10; policy accept;\n'
        printf '    ct state new ip saddr @gov4 counter drop\n    ct state new ip6 saddr @gov6 counter drop\n'
        [ "$vk" = 1 ] && printf '    ip daddr @vk4 counter reject\n    ip6 daddr @vk6 counter reject\n'
        printf '  }\n'
        if [ "$vk" = 1 ]; then
            printf '  chain output { type filter hook output priority -10; policy accept;\n'
            printf '    ip daddr @vk4 counter reject\n    ip6 daddr @vk6 counter reject\n  }\n'
        fi
        printf '}\n'
    } > "$rules.new" || return 1
    # One transaction: either the whole new table is live or the previous one stays.
    nft -c -f "$rules.new" >/dev/null 2>&1 && nft -f "$rules.new" >/dev/null 2>&1 || { rm -f "$rules.new"; return 1; }
    mv -f "$rules.new" "$rules"
}

ipt4() { iptables -w "$@" 2>/dev/null; }
ipt6() { ip6tables -w "$@" 2>/dev/null; }
has_v6() { have ip6tables && [ -f /proc/net/if_inet6 ]; }

load_ipset() { # name family file
    ipset create "$1-new" hash:net family "$2" maxelem 262144 -exist || return 1
    ipset flush "$1-new" || return 1
    if [ -s "$3" ]; then sed "s/^/add $1-new /" "$3" | ipset restore -exist || return 1; fi
    ipset create "$1" hash:net family "$2" maxelem 262144 -exist || return 1
    ipset swap "$1-new" "$1" && ipset destroy "$1-new"
}

hook_chain() { # ipt-function chain parent
    "$1" -C "$3" -j "$2" || "$1" -I "$3" 1 -j "$2"
}
unhook_chain() {
    while "$1" -C "$3" -j "$2"; do "$1" -D "$3" -j "$2" || break; done
    "$1" -F "$2"; "$1" -X "$2"; return 0
}

apply_ipset_family() { # ipt-function suffix family
    load_ipset "velum-gov$2" "$3" "$lists/gov$2.txt" || return 1
    "$1" -N VELUM_BL_IN; "$1" -F VELUM_BL_IN || return 1
    "$1" -A VELUM_BL_IN -m set --match-set "velum-gov$2" src -m conntrack --ctstate NEW -j DROP || return 1
    hook_chain "$1" VELUM_BL_IN INPUT || return 1
    hook_chain "$1" VELUM_BL_IN FORWARD || return 1
    if [ "$vk" = 1 ]; then
        load_ipset "velum-vk$2" "$3" "$lists/vk$2.txt" || return 1
        "$1" -N VELUM_BL_OUT; "$1" -F VELUM_BL_OUT || return 1
        "$1" -A VELUM_BL_OUT -m set --match-set "velum-vk$2" dst -j REJECT || return 1
        hook_chain "$1" VELUM_BL_OUT OUTPUT || return 1
        hook_chain "$1" VELUM_BL_OUT FORWARD || return 1
    else
        unhook_chain "$1" VELUM_BL_OUT OUTPUT
        unhook_chain "$1" VELUM_BL_OUT FORWARD
        ipset destroy "velum-vk$2" 2>/dev/null
    fi
    return 0
}

apply_ipset() {
    apply_ipset_family ipt4 4 inet || return 1
    if has_v6; then apply_ipset_family ipt6 6 inet6 || return 1; fi
    return 0
}

apply_rules() {
    case "$backend" in nft) apply_nft ;; ipset) apply_ipset ;; *) return 1 ;; esac
}

remove_rules() {
    have nft && nft delete table inet "$table" 2>/dev/null
    if have iptables; then
        for chain in VELUM_BL_IN VELUM_BL_OUT; do
            for parent in INPUT FORWARD OUTPUT; do
                unhook_chain ipt4 "$chain" "$parent"
                have ip6tables && unhook_chain ipt6 "$chain" "$parent"
            done
        done
    fi
    if have ipset; then
        for name in velum-gov4 velum-gov6 velum-vk4 velum-vk6; do
            ipset destroy "$name" 2>/dev/null; ipset destroy "$name-new" 2>/dev/null
        done
    fi
    return 0
}

rules_active() {
    case "$backend" in
        nft) nft list table inet "$table" >/dev/null 2>&1 ;;
        ipset) ipt4 -C INPUT -j VELUM_BL_IN ;;
        *) return 1 ;;
    esac
}

client_listed6() {
    case "$backend" in
        nft) nft get element inet "$table" gov6 "{ $client }" >/dev/null 2>&1 ;;
        ipset) ipset test velum-gov6 "$client" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

dropped() {
    case "$backend" in
        nft) nft list table inet "$table" 2>/dev/null | awk '
            /saddr @gov/ { for (i = 1; i < NF; i++) if ($i == "packets") sum += $(i + 1) } END { printf "%d", sum }' ;;
        ipset) { ipt4 -nvxL VELUM_BL_IN; has_v6 && ipt6 -nvxL VELUM_BL_IN; } |
            awk '$3 == "DROP" { sum += $1 } END { printf "%d", sum }' ;;
        *) printf 0 ;;
    esac
}

schedule() {
    if [ -d /run/systemd/system ]; then
        cat > "$unit_dir/velum-as-blocklist.service" <<UNIT
# Managed by VELUM AS blocklist
[Unit]
Description=VELUM AS blocklist: restore the cached rules
After=network.target nftables.service netfilter-persistent.service ufw.service firewalld.service docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$self apply
[Install]
WantedBy=multi-user.target
UNIT
        cat > "$unit_dir/velum-as-blocklist-update.service" <<UNIT
# Managed by VELUM AS blocklist
[Unit]
Description=VELUM AS blocklist: refresh the lists
After=network-online.target
[Service]
Type=oneshot
ExecStart=$self update
UNIT
        cat > "$unit_dir/velum-as-blocklist-update.timer" <<UNIT
# Managed by VELUM AS blocklist
[Unit]
Description=VELUM AS blocklist: daily refresh
[Timer]
OnCalendar=daily
RandomizedDelaySec=3h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable velum-as-blocklist.service >/dev/null 2>&1
        systemctl enable --now velum-as-blocklist-update.timer >/dev/null 2>&1
        return 0
    fi
    if [ -d /etc/local.d ]; then
        printf '#!/bin/sh\n# Managed by VELUM AS blocklist\n%s apply >/dev/null 2>&1\n' "$self" > /etc/local.d/velum-as-blocklist.start
        chmod 755 /etc/local.d/velum-as-blocklist.start
        have rc-update && rc-update add local default >/dev/null 2>&1
    fi
    for daily in /etc/periodic/daily /etc/cron.daily; do
        if [ -d "$daily" ]; then
            printf '#!/bin/sh\n# Managed by VELUM AS blocklist\n%s update >/dev/null 2>&1\n' "$self" > "$daily/velum-as-blocklist"
            chmod 755 "$daily/velum-as-blocklist"
            break
        fi
    done
    return 0
}

unschedule() {
    if [ -d /run/systemd/system ]; then
        systemctl disable --now velum-as-blocklist-update.timer >/dev/null 2>&1
        systemctl disable velum-as-blocklist.service >/dev/null 2>&1
    fi
    rm -f "$unit_dir/velum-as-blocklist.service" "$unit_dir/velum-as-blocklist-update.service" \
        "$unit_dir/velum-as-blocklist-update.timer" /etc/local.d/velum-as-blocklist.start \
        /etc/periodic/daily/velum-as-blocklist /etc/cron.daily/velum-as-blocklist
    [ -d /run/systemd/system ] && systemctl daemon-reload >/dev/null 2>&1
    return 0
}

schedule_kind() {
    if [ -f "$unit_dir/velum-as-blocklist-update.timer" ]; then
        if systemctl is-active --quiet velum-as-blocklist-update.timer 2>/dev/null; then printf timer; else printf stopped; fi
    elif [ -f /etc/periodic/daily/velum-as-blocklist ] || [ -f /etc/cron.daily/velum-as-blocklist ]; then printf cron
    else printf none; fi
}

other_firewalls() {
    found=
    have ufw && ufw status 2>/dev/null | grep -q 'Status: active' && found="$found ufw"
    have firewall-cmd && firewall-cmd --state >/dev/null 2>&1 && found="$found firewalld"
    have docker && found="$found docker"
    printf '%s' "${found# }"
}

report() {
    info os "$(os_name)"
    if [ -x "$self" ] && [ -n "$backend" ]; then info installed 1; else info installed 0; fi
    if [ -n "$backend" ]; then info backend "$backend"; else info backend "$(available_backend)"; fi
    if rules_active; then info active 1; else info active 0; fi
    info vk "$vk"
    info gov4 "$(count "$state/gov4.txt")"
    info gov6 "$(count "$state/gov6.txt")"
    info vk4 "$(count "$state/vk4.txt")"
    info vk6 "$(count "$state/vk6.txt")"
    info updated "$(cat "$state/updated" 2>/dev/null | tr -cd '0-9' | cut -c1-12)"
    info dropped "$(dropped)"
    info auto "$(schedule_kind)"
    info firewalls "$(other_firewalls)"
    info package_manager "$(package_manager || printf none)"
}

download_lists() {
    work=$(mktemp -d) || fail TEMP
    have curl || have wget || install_packages curl || fail NO_DOWNLOADER
    fetch "$source_url/blacklist-v4.txt" "$work/gov4.raw" || fail DOWNLOAD
    fetch "$source_url/blacklist-v6.txt" "$work/gov6.raw" || : > "$work/gov6.raw"
    clean4 "$work/gov4.raw" > "$work/gov4.txt"
    clean6 "$work/gov6.raw" > "$work/gov6.txt"
    [ "$(count "$work/gov4.txt")" -ge 50 ] || fail BAD_LIST
    if [ "$vk" = 1 ]; then
        fetch "$source_url/blacklist-vk-v4.txt" "$work/vk4.raw" || fail DOWNLOAD
        fetch "$source_url/blacklist-vk-v6.txt" "$work/vk6.raw" || : > "$work/vk6.raw"
        clean4 "$work/vk4.raw" > "$work/vk4.txt"
        clean6 "$work/vk6.raw" > "$work/vk6.txt"
        [ "$(count "$work/vk4.txt")" -ge 5 ] || fail BAD_LIST
    fi
    # Refuse before touching the firewall if the admin's own address is on the list.
    case "$client" in
        *.*.*.*) in_list4 "$client" "$work/gov4.txt" && fail YOUR_IP_LISTED ;;
    esac
    return 0
}

refresh() {
    download_lists
    lists=$work
    apply_rules || fail APPLY
    case "$client" in
        *:*) if client_listed6; then remove_rules; fail YOUR_IP_LISTED; fi ;;
    esac
    for name in gov4 gov6 vk4 vk6; do
        if [ -f "$work/$name.txt" ]; then cp -f "$work/$name.txt" "$state/$name.txt"; else rm -f "$state/$name.txt"; fi
    done
    date +%s > "$state/updated"
    lists=$state
    cleanup; work=
}

if [ "$action" != status ]; then
    lock=/run/velum-as-blocklist.lock
    if have flock && [ ! -L "$lock" ]; then
        exec 9>"$lock"
        flock -w 20 9 || fail BUSY
    fi
fi

case "$action" in
    status)
        report
        reply OK ;;
    install)
        case "${2:-0}" in 1) vk=1 ;; *) vk=0 ;; esac
        if ! backend_works; then
            previous=$backend
            choose_backend || fail NO_FIREWALL
            # The saved method stopped working: drop its leftovers before switching.
            [ -n "$previous" ] && [ "$previous" != "$backend" ] && remove_rules
        fi
        mkdir -p "$state" && chmod 700 "$state" || fail STATE
        if [ "$0" != "$self" ]; then
            [ -f "$0" ] || fail INVALID
            mkdir -p "${self%/*}" && cp -f "$0" "$self" && chmod 700 "$self" || fail STATE
        fi
        refresh
        printf 'backend=%s\nvk=%s\n' "$backend" "$vk" > "$conf"
        schedule
        report
        reply INSTALLED ;;
    update)
        [ -n "$backend" ] || fail NOT_INSTALLED
        refresh
        report
        reply UPDATED ;;
    apply)
        [ -n "$backend" ] && [ -s "$state/gov4.txt" ] || fail NOT_INSTALLED
        apply_rules || fail APPLY
        reply APPLIED ;;
    remove)
        unschedule
        remove_rules
        rm -rf "$state"
        rm -f "$self"
        backend=
        vk=0
        report
        reply REMOVED ;;
esac
