#!/usr/bin/env bash
# Disposable GitHub Actions runners in Multipass VMs. A stopped base VM holds Docker, build tools and the runner;
# every job runs in a fresh clone of it, registered for that one job, and the clone is deleted afterwards. Only the
# config file and the token file stay. The VMs reach the internet, but not the local network or the host.
#
# Jobs go to GitHub's runners first. While `run` is active, jobs that wait too long for them are moved here: the
# repository variable RUNNER, which the workflows use in `runs-on`, is set to this runner's label for a while.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: runner.sh COMMAND CONFIG

  prepare  build the base VM: Ubuntu with Docker, build tools and the runner, then stop it
  run      take jobs one at a time, each in a fresh clone of the base VM, until stopped; move jobs that
           wait too long for GitHub's runners here
  once     take one job in a fresh clone of the base VM
  status   show the VMs and the runners registered on GitHub
  clean    delete the VMs, the runners on GitHub and the firewall rules
EOF
}

die() {
    echo "runner.sh: $*" >&2
    exit 1
}

# Reads KEY=value lines; nothing in the file is executed.
load_config() {
    local file=$1 line key value
    [[ -r $file ]] || die "cannot read $file"
    REPO="" TOKEN_FILE="" NAME="lanlord-runner" LABELS="lanlord" CPUS=4 MEMORY=8G DISK=40G IMAGE=24.04
    BRIDGE=mpqemubr0 BLOCK="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10" WAIT=10 BACK_AFTER=30
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        [[ $line =~ ^([A-Z_]+)=(.*)$ ]] || die "$file: cannot read: $line"
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        value=${value%\"}
        value=${value#\"}
        case $key in
        REPO | TOKEN_FILE | NAME | LABELS | CPUS | MEMORY | DISK | IMAGE | BRIDGE | BLOCK | WAIT | BACK_AFTER)
            printf -v "$key" '%s' "$value"
            ;;
        *) die "$file: unknown setting $key" ;;
        esac
    done <"$file"
    [[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "REPO must be owner/name"
    [[ $NAME =~ ^[a-z][a-z0-9-]*$ ]] || die "NAME may hold lowercase letters, digits and -"
    [[ $LABELS =~ ^[A-Za-z0-9_.,-]+$ ]] || die "LABELS is a comma-separated list"
    [[ $WAIT =~ ^[1-9][0-9]*$ && $BACK_AFTER =~ ^[1-9][0-9]*$ ]] || die "WAIT and BACK_AFTER are minutes"
    LABEL=${LABELS%%,*}
    if [[ $TOKEN_FILE == "~/"* ]]; then
        TOKEN_FILE=$HOME/${TOKEN_FILE#"~/"}
    fi
    [[ -r $TOKEN_FILE ]] || die "cannot read the token file $TOKEN_FILE"
    [[ $(stat -c %a "$TOKEN_FILE") == 600 ]] || die "$TOKEN_FILE must have mode 0600"
    BASE=$NAME-base
}

need() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null || die "$tool is missing"
    done
}

# A call to the GitHub API for the repository, with an optional JSON body; the token never shows up in the process
# list.
api() {
    local method=$1 path=$2 body=${3:-}
    local args=(-fsS -X "$method" -H "Accept: application/vnd.github+json")
    if [[ -n $body ]]; then
        args+=(-H "Content-Type: application/json" --data "$body")
    fi
    curl "${args[@]}" -H @<(printf 'Authorization: Bearer %s\n' "$(<"$TOKEN_FILE")") \
        "https://api.github.com/repos/$REPO$path"
}

# The VMs reach the internet through the host, but no private network and nothing on the host except DHCP and DNS.
firewall() {
    local nets net v4="" v6=""
    read -ra nets <<<"$BLOCK"
    for net in "${nets[@]}"; do
        if [[ $net == *:* ]]; then v6+="$net, "; else v4+="$net, "; fi
    done
    {
        echo "table inet lanlord_runner"
        echo "delete table inet lanlord_runner"
        echo "table inet lanlord_runner {"
        echo "  chain forward {"
        echo "    type filter hook forward priority -1; policy accept;"
        [[ -n $v4 ]] && echo "    iifname \"$BRIDGE\" ip daddr { ${v4%, } } drop"
        [[ -n $v6 ]] && echo "    iifname \"$BRIDGE\" ip6 daddr { ${v6%, } } drop"
        echo "  }"
        echo "  chain input {"
        echo "    type filter hook input priority -1; policy accept;"
        echo "    iifname \"$BRIDGE\" ct state established,related accept"
        echo "    iifname \"$BRIDGE\" udp dport { 53, 67, 547 } accept"
        echo "    iifname \"$BRIDGE\" tcp dport 53 accept"
        echo "    iifname \"$BRIDGE\" meta l4proto ipv6-icmp accept"
        echo "    iifname \"$BRIDGE\" drop"
        echo "  }"
        echo "}"
    } | sudo nft -f -
}

# Runs as root in the base VM, with the runner version and architecture as arguments.
provision() {
    cat <<'EOF'
set -euo pipefail
version=$1 arch=$2
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq --no-install-recommends docker.io build-essential pkg-config git curl jq ca-certificates unzip \
    python3 python3-pip python3-venv
useradd --create-home --shell /bin/bash runner
usermod -aG docker runner
echo 'runner ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/runner
chmod 0440 /etc/sudoers.d/runner
install -d -o runner -g runner /opt/actions-runner
cd /opt/actions-runner
curl -fsSL "https://github.com/actions/runner/releases/download/v${version}/actions-runner-linux-${arch}-${version}.tar.gz" |
    sudo -u runner tar xz
./bin/installdependencies.sh
apt-get clean
EOF
}

prepare() {
    local version arch
    case $(uname -m) in
    x86_64) arch=x64 ;;
    aarch64) arch=arm64 ;;
    *) die "no runner for $(uname -m)" ;;
    esac
    version=$(curl -fsS https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name | ltrimstr("v")')
    [[ $version =~ ^[0-9.]+$ ]] || die "cannot find the latest runner version"
    if multipass info "$BASE" >/dev/null 2>&1; then
        multipass delete --purge "$BASE"
    fi
    multipass launch "$IMAGE" --name "$BASE" --cpus "$CPUS" --memory "$MEMORY" --disk "$DISK"
    multipass exec "$BASE" -- sudo bash -s -- "$version" "$arch" < <(provision)
    multipass stop "$BASE"
    echo "Base VM $BASE ready with runner $version."
}

CURRENT=""
WATCHER=""

# Runs with a job that waits for LABEL since more than MINUTES.
stuck_runs() {
    local label=$1 minutes=$2 cutoff status run
    cutoff=$(date -u -d "-$minutes minutes" +%Y-%m-%dT%H:%M:%SZ)
    for status in queued in_progress; do
        for run in $(api GET "/actions/runs?status=$status&per_page=100" | jq -r '.workflow_runs[].id'); do
            if api GET "/actions/runs/$run/jobs?per_page=100" |
                jq -e --arg label "$label" --arg cutoff "$cutoff" \
                    'any(.jobs[]; .status == "queued" and .created_at <= $cutoff and (.labels | index($label)))' \
                    >/dev/null; then
                echo "$run"
            fi
        done
    done
}

# Cancels a run and runs its unfinished jobs again, so they are queued for the runner RUNNER names now.
requeue() {
    local run=$1 _
    api POST "/actions/runs/$run/cancel" >/dev/null || api POST "/actions/runs/$run/force-cancel" >/dev/null || return 0
    for _ in $(seq 30); do
        [[ $(api GET "/actions/runs/$run" | jq -r .status) == completed ]] && break
        sleep 10
    done
    api POST "/actions/runs/$run/rerun-failed-jobs" >/dev/null || true
    echo "Run $run queued again."
}

# Sets where jobs go: to the runners with this label, or with an empty label to GitHub's runners.
route() {
    if [[ -n $1 ]]; then
        api PATCH /actions/variables/RUNNER "{\"name\":\"RUNNER\",\"value\":\"$1\"}" >/dev/null 2>&1 ||
            api POST /actions/variables "{\"name\":\"RUNNER\",\"value\":\"$1\"}" >/dev/null
        echo "Jobs go to $1."
    else
        api DELETE /actions/variables/RUNNER >/dev/null 2>&1 || true
        echo "Jobs go to GitHub's runners."
    fi
}

# Moves jobs here when GitHub's runners keep them waiting, and back to GitHub after BACK_AFTER minutes.
watch_queue() {
    local since="" run
    set +e
    while true; do
        sleep 60
        if [[ -z $since ]]; then
            for run in $(stuck_runs ubuntu-latest "$WAIT"); do
                if [[ -z $since ]]; then
                    route "$LABEL"
                    since=$(date +%s)
                fi
                requeue "$run"
            done
        elif (($(date +%s) - since >= BACK_AFTER * 60)); then
            route ""
            since=""
        fi
    done
}

# Stops moving jobs here, and gives jobs that wait for this runner back to GitHub.
stop_watch() {
    local run
    [[ -n $WATCHER ]] || return 0
    kill "$WATCHER" 2>/dev/null || true
    WATCHER=""
    route ""
    for run in $(stuck_runs "$LABEL" 0); do
        requeue "$run"
    done
}

# Deletes the VM of the current job and its runner on GitHub, if still registered.
finish() {
    local vm=$CURRENT id
    [[ -n $vm ]] || return 0
    CURRENT=""
    multipass delete --purge "$vm" >/dev/null 2>&1 || true
    id=$(api GET "/actions/runners?per_page=100" | jq -r --arg name "$vm" '.runners[] | select(.name == $name) | .id') || true
    if [[ -n $id ]]; then
        api DELETE "/actions/runners/$id" >/dev/null || true
    fi
}

job() {
    local vm token
    multipass info "$BASE" >/dev/null 2>&1 || die "no base VM, run: runner.sh prepare CONFIG"
    vm=$NAME-$(date +%Y%m%d-%H%M%S)
    CURRENT=$vm
    multipass clone "$BASE" --name "$vm" >/dev/null
    multipass start "$vm"
    token=$(api POST /actions/runners/registration-token | jq -r .token)
    [[ -n $token && $token != null ]] || die "no registration token: does the token have Administration write access?"
    # The token goes in through stdin, not on the host's command line; it works only once and for an hour.
    multipass exec "$vm" -- sudo -u runner bash -s <<EOF || true
set -euo pipefail
cd /opt/actions-runner
./config.sh --unattended --ephemeral --url "https://github.com/$REPO" --token "$token" --name "$vm" --labels "$LABELS"
exec ./run.sh
EOF
    finish
}

status() {
    multipass list --format json | jq -r --arg name "$NAME" \
        '.list[] | select(.name | startswith($name + "-")) | "\(.name)\t\(.state)"'
    api GET "/actions/runners?per_page=100" | jq -r --arg name "$NAME" \
        '.runners[] | select(.name | startswith($name + "-")) | "\(.name)\t\(.status)\tbusy: \(.busy)"'
}

clean() {
    local vm id
    for vm in $(multipass list --format json | jq -r --arg name "$NAME" '.list[] | select(.name | startswith($name + "-")) | .name'); do
        multipass delete --purge "$vm"
    done
    for id in $(api GET "/actions/runners?per_page=100" | jq -r --arg name "$NAME" '.runners[] | select(.name | startswith($name + "-")) | .id'); do
        api DELETE "/actions/runners/$id" >/dev/null
    done
    sudo nft delete table inet lanlord_runner 2>/dev/null || true
}

main() {
    [[ $# -eq 2 ]] || {
        usage >&2
        exit 2
    }
    need multipass jq curl nft sudo
    load_config "$2"
    trap 'finish; stop_watch' EXIT
    trap 'exit 130' INT TERM
    case $1 in
    prepare) prepare ;;
    run)
        firewall
        watch_queue &
        WATCHER=$!
        while true; do job; done
        ;;
    once)
        firewall
        job
        ;;
    status) status ;;
    clean) clean ;;
    *)
        usage >&2
        exit 2
        ;;
    esac
}

main "$@"
