#!/usr/bin/env bash
# Run ONLY in an explicitly authorized, disposable systemd Linux VM.
set -euo pipefail
if [[ "${1:-}" != --isolated-vm || $# != 2 || "$(id -u)" != 0 ]]; then
  echo "requires root, --isolated-vm and a compiled enforcer path" >&2; exit 2
fi
[[ "$(cat /proc/1/comm)" == systemd ]]
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]]
[[ "$(findmnt -n -o FSTYPE --target /sys/fs/bpf)" == bpf ]]
root="$(cd "$(dirname "$0")/.." && pwd)"
binary="$(realpath "$2")"
[[ -f "$binary" && -x "$binary" ]]
# Refuse any pre-existing guarded workload or boot marker. Never take over
# a configured host. The CI job is disposable even if a test is interrupted.
shopt -s nullglob
existing=(/sys/fs/cgroup/gavel-agent-* /sys/fs/bpf/gavel-agents/gavel-agent-* /run/gavel-guarded-lifecycle/*.recovery.json /run/gavel-guarded-lifecycle/boot-ready.json)
(( ${#existing[@]} == 0 )) || { echo "unexpected pre-existing guarded state"; exit 1; }
tmp="$(mktemp -d /run/gavel-systemd-proof-XXXXXXXX)"
chmod 0755 "$tmp"
boot="gavel-ci-boot-$$.service"
work="gavel-ci-workload-$$.service"
fixture="/sys/fs/cgroup/gavel-agent-$$"
unitdir=/run/systemd/system
made_fixture=0
cleanup() {
  local status=$?
  trap - EXIT
  journalctl -b -u "$boot" -u "$work" --no-pager || true
  systemctl stop "$work" "$boot" || status=1
  systemctl reset-failed "$work" "$boot" || true
  rm -f "$unitdir/$work" "$unitdir/$boot"
  systemctl daemon-reload || status=1
  if (( made_fixture )); then rmdir "$fixture" || status=1; fi
  rm -f /run/gavel-guarded-lifecycle/boot-ready.json
  rm -rf -- "$tmp"
  exit "$status"
}
trap cleanup EXIT
install -m 0755 -o root -g root "$binary" "$tmp/gavel-enforcer"
install -d -m 0700 -o 421347 -g 421347 "$tmp/payload"
printf '%s\n' 'GAVEL_CGROUP_PATH=/sys/fs/cgroup' > "$tmp/recovery.env"
printf '%s\n' 'GAVEL_CGROUP_PATH=/sys/fs/cgroup' 'GAVEL_AGENT_UID=421347' 'GAVEL_AGENT_GID=421347' 'GAVEL_MACHINE_KEY=' 'GAVEL_BLOCKED_IPS=127.0.0.2' > "$tmp/workload.env"
chmod 0600 "$tmp/"*.env
# Exercise the shipped unit dependency and command lines. Names, fixture
# paths, and workload Type=oneshot are test-only substitutions to make
# systemctl synchronously report the payload outcome.
sed -e "s|/usr/local/bin/gavel-enforcer|$tmp/gavel-enforcer|g" \
    -e "s|/etc/gavel/recovery.env|$tmp/recovery.env|g" \
    "$root/deploy/systemd/gavel-guarded-boot.service" > "$unitdir/$boot"
sed -e "s|gavel-guarded-boot.service|$boot|g" \
    -e "s|/usr/local/bin/gavel-enforcer|$tmp/gavel-enforcer|g" \
    -e "s|/etc/gavel/guarded-workload.env|$tmp/workload.env|g" \
    -e "s|/opt/gavel/workload|/usr/bin/touch $tmp/payload/ran|g" \
    -e 's/^Type=simple$/Type=oneshot/' \
    "$root/deploy/systemd/gavel-guarded-workload.service.example" > "$unitdir/$work"
systemd-analyze verify "$unitdir/$boot" "$unitdir/$work"
systemctl daemon-reload
mkdir "$fixture"
made_fixture=1
if systemctl start "$work"; then
  echo "SECURITY FAILURE: workload start succeeded with unresolved boot state"; exit 1
fi
[[ ! -e "$tmp/payload/ran" && -d "$fixture" ]]
[[ ! -e /run/gavel-guarded-lifecycle/boot-ready.json ]]
[[ "$(systemctl show -p Result --value "$boot")" == exit-code ]]
echo "SYSTEMD PROOF: failed required boot service prevented dependent payload; unknown cgroup preserved"
rmdir "$fixture"
made_fixture=0
systemctl reset-failed "$boot" "$work" || true
systemctl start "$work"
[[ -f "$tmp/payload/ran" ]]
[[ "$(stat -c %u "$tmp/payload/ran")" == 421347 ]]
[[ "$(systemctl is-active "$boot")" == active ]]
[[ -f /run/gavel-guarded-lifecycle/boot-ready.json ]]
residual=(/sys/fs/cgroup/gavel-agent-* /sys/fs/bpf/gavel-agents/gavel-agent-* /run/gavel-guarded-lifecycle/*.recovery.json)
(( ${#residual[@]} == 0 ))
echo "SYSTEMD PROOF: successful required boot service admitted unprivileged guarded workload; no residual cgroup or pins"
