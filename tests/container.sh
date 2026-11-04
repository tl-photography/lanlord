#!/bin/sh
# Security checks of the built image: user, package manager, setuid files, start with all restrictions,
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

cleanup() {
    docker rm -f "$name" > /dev/null 2>&1 || true
}
trap cleanup EXIT

in_image() {
    docker run --rm --entrypoint sh "$image" -c "$1"
}

user=$(docker image inspect "$image" --format '{{.Config.User}}')
if [ -n "$user" ] && [ "$user" != root ] && [ "$user" != 0 ]; then
    pass "runs as a non-root user ($user)"
else
    fail "runs as a non-root user ($user)"
fi

if [ -z "$(in_image 'command -v apk || true')" ]; then
    pass "has no package manager"
else
    fail "has no package manager"
fi

setuid=$(in_image 'find / -xdev -perm /6000 -type f 2>/dev/null | wc -l')
if [ "$setuid" -eq 0 ]; then
    pass "has no setuid or setgid files"
else
    fail "has no setuid or setgid files ($setuid found)"
fi

docker run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges \
    -p "127.0.0.1:$port:8080" "$image" > /dev/null

healthy=false
for _ in $(seq 30); do
    if docker exec "$name" lanlord healthcheck; then
        healthy=true
        break
    fi
    sleep 1
done
if $healthy; then
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

if [ "$failed" -ne 0 ]; then
    docker logs "$name" 2>&1 | tail -20
    exit 1
fi
