#!/usr/bin/env bash
set -euo pipefail

PORTS=(80 443)
KNOWN_WEB_SERVICES=(nginx apache2 httpd caddy lighttpd)

is_listening() {
    ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)$1\$"
}

identify_listener() {
    sudo -n ss -tlnp 2>/dev/null \
        | awk -v port=":$1" '$4 ~ port"$" { print; exit }' \
        | grep -oE 'users:\(\("[^"]+"' \
        | sed -E 's/^users:\(\("//; s/"$//' \
        | head -1
}

is_known_service() {
    local name="$1"
    for svc in "${KNOWN_WEB_SERVICES[@]}"; do
        [[ "$name" == "$svc" ]] && return 0
    done
    return 1
}

stop_service() {
    local svc="$1"
    if ! sudo -n systemctl is-active --quiet "$svc" 2>/dev/null; then
        return 1
    fi
    echo "  -> stopping systemd service: $svc"
    sudo -n systemctl disable --now "$svc" 2>&1 | sed 's/^/     /'
}

for port in "${PORTS[@]}"; do
    is_listening "$port" || continue

    pname=$(identify_listener "$port" || true)

    if [[ -z "$pname" ]]; then
        cat >&2 <<EOF
ERROR: host port :$port is held but cannot be identified without sudo.
       Run: sudo ss -tlnp '( sport = :$port )'
       Then stop the offending process and retry.
EOF
        exit 1
    fi

    echo "host :$port is held by non-docker process: $pname"

    if is_known_service "$pname" && stop_service "$pname"; then
        :
    else
        cat >&2 <<EOF
ERROR: :$port is held by '$pname' which is not a known auto-stoppable web service.
       Stop it manually before retrying. Suggested:
         sudo systemctl stop $pname   # if it's a systemd service
       Or identify the process:
         sudo lsof -nP -iTCP:$port -sTCP:LISTEN
EOF
        exit 1
    fi

    if is_listening "$port"; then
        echo "ERROR: :$port still bound after attempting to stop '$pname'" >&2
        exit 1
    fi
done
