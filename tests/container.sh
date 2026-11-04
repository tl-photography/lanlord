#!/bin/sh
# Security checks of the built image: user, shell, package manager, setuid files, start with all restrictions,
# response headers and clean stop.
# Usage: tests/container.sh <image>
set -eu

image=${1:?usage: tests/container.sh <image>}
name=lanlord-test-$$
port=18080
failed=0

pass() { echo "ok   $1"; }
fail() {
    echo "FAIL $1"
    failed=1
}

# Data directory with the example settings, readable for any uid.
data=$(mktemp -d)
cp "$(dirname "$0")/../examples/lanlord.toml" "$data/lanlord.toml"
chmod 755 "$data"
chmod 644 "$data/lanlord.toml"

cleanup() {
    docker rm -f "$name" > /dev/null 2>&1 || true
    rm -rf "$data"
}
trap cleanup EXIT

# File list of the image, read from outside: the image has no shell to run checks in.
created=$(docker create "$image")
files=$(docker export "$created" | tar -tv)
docker rm "$created" > /dev/null

user=$(docker image inspect "$image" --format '{{.Config.User}}')
case $user in
    "" | root | 0 | 0:* | root:*) fail "runs as a non-root user ($user)" ;;
    *) pass "runs as a non-root user ($user)" ;;
esac

if printf '%s\n' "$files" | grep -Eq ' (bin|usr/bin|sbin)/(sh|bash|ash|busybox)$'; then
    fail "has no shell"
else
    pass "has no shell"
fi

if printf '%s\n' "$files" | grep -Eq '/(apk|apt|apt-get|dpkg|rpm)$'; then
    fail "has no package manager"
else
    pass "has no package manager"
fi

if printf '%s\n' "$files" | grep -Eq '^-..[sS]|^-.....[sS]'; then
    fail "has no setuid or setgid files"
else
    pass "has no setuid or setgid files"
fi

docker run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges \
    -v "$data:/data:ro" -p "127.0.0.1:$port:8080" "$image" > /dev/null

wait_healthy() {
    for _ in $(seq 30); do
        docker exec "$1" /lanlord healthcheck && return 0
        sleep 1
    done
    return 1
}

if wait_healthy "$name"; then
    pass "starts read-only, without capabilities and new privileges"
else
    fail "starts read-only, without capabilities and new privileges"
fi

headers=$(curl -fsS -D - -o /dev/null "http://127.0.0.1:$port/" || true)
for header in content-security-policy x-content-type-options x-frame-options referrer-policy cache-control; do
    if printf '%s\n' "$headers" | grep -qi "^$header:"; then
        pass "sends $header"
    else
        fail "sends $header"
    fi
done

start=$(date +%s)
docker stop -t 10 "$name" > /dev/null
duration=$(($(date +%s) - start))
exit_code=$(docker inspect "$name" --format '{{.State.ExitCode}}')
if [ "$duration" -le 3 ] && [ "$exit_code" -eq 0 ]; then
    pass "stops on SIGTERM within 3 s with exit code 0"
else
    fail "stops on SIGTERM within 3 s with exit code 0 (${duration} s, exit $exit_code)"
fi

# Like docker run --user or PUID/PGID in compose files: no passwd entry for this uid.
docker rm "$name" > /dev/null
docker run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges \
    -v "$data:/data:ro" --user 12345:12345 "$image" > /dev/null
if wait_healthy "$name"; then
    pass "runs as an arbitrary uid:gid"
else
    fail "runs as an arbitrary uid:gid"
fi

if [ "$failed" -ne 0 ]; then
    docker logs "$name" 2>&1 | tail -20
    exit 1
fi
