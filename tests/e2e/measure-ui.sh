#!/usr/bin/env bash
# Times the UI suite against a throwaway single site, for comparing two images on the same
# machine (the .NET 11 plan's step 5: before and after the migration). One warm-up run is
# not counted. Reports each run's wall time, the site's memory (peak and at the end, from
# docker stats), and server-side request times from ASP.NET Core's request log; the Blazor
# circuit's own WebSocket is left out, since it lasts as long as a page is open.
# Usage: measure-ui.sh <image> [runs, default 3]. Needs Docker, curl, node and this folder's
# npm packages. Uses port 8096 and the compose project harpo-measure; removes both after.
set -euo pipefail
IMAGE=${1:?usage: measure-ui.sh <image> [runs]}
RUNS=${2:-3}
DIR=$(cd "$(dirname "$0")" && pwd)
NAME=harpo-measure
PORT=8096
STATS=$(mktemp)
cleanup() {
  [ -n "${SAMPLER:-}" ] && kill "$SAMPLER" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
  rm -f "$STATS"
}
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker volume rm "$NAME-data" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" -v "$NAME-data:/data" \
  -e Harpo__SiteId=main -e Harpo__MasterKey=measure-master-key -e Auth__Mode=Development \
  -e Auth__DevUsers__0__Username=alice -e Auth__DevUsers__0__Password=alice -e Auth__DevUsers__0__IsSiteAdmin=true \
  -e Auth__DevUsers__1__Username=bob -e Auth__DevUsers__1__Password=bob \
  -e Auth__DevUsers__2__Username=carol -e Auth__DevUsers__2__Password=carol \
  -e Harpo__Export__AllGroupsEnabled=true \
  -e Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics=Information \
  "$IMAGE" >/dev/null
for _ in $(seq 1 90); do docker logs "$NAME" 2>&1 | grep -q 'Now listening' && break; sleep 1; done

ui() {
  (cd "$DIR" && HARPO_BASE_URL="http://localhost:$PORT" HARPO_USER=alice HARPO_PASSWORD=alice \
    HARPO_DB_ENCRYPTED=false node ui.e2e.js >/dev/null 2>&1)
}
ui || { echo "the warm-up run failed" >&2; exit 1; }
idle_mib() { docker stats --no-stream --format '{{.MemUsage}}' "$NAME" | awk '{print $1}'; }
echo "image:   $IMAGE ($(docker run --rm --entrypoint dotnet "$IMAGE" --list-runtimes | awk '/NETCore/ {print $2}'))"
echo "machine: $(uname -sm), $(docker info --format '{{.NCPU}} CPUs, {{.MemTotal}} bytes') for Docker"
echo "memory after the warm-up: $(idle_mib)"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)

( while :; do docker stats --no-stream --format '{{.MemUsage}}' "$NAME" | awk '{print $1}' >> "$STATS"; done ) &
SAMPLER=$!
for i in $(seq 1 "$RUNS"); do
  start=$(node -e 'console.log(Date.now())')
  ui || { echo "run $i failed" >&2; exit 1; }
  echo "run $i: $(node -e "console.log(((Date.now() - $start) / 1000).toFixed(1))") s"
done
kill "$SAMPLER" 2>/dev/null || true; SAMPLER=

node - "$STATS" <<'EOF'
const fs = require("fs");
const mib = s => { const m = /^([\d.]+)([KMG]i?B)$/.exec(s.trim()); if (!m) return NaN;
  return +m[1] * ({ KiB: 1 / 1024, MiB: 1, GiB: 1024, KB: 1 / 1024, MB: 1, GB: 1024 })[m[2]]; };
const v = fs.readFileSync(process.argv[2], "utf8").split("\n").map(mib).filter(x => !isNaN(x));
console.log(`memory during the runs: peak ${Math.max(...v).toFixed(0)} MiB, at the end ${v[v.length - 1].toFixed(0)} MiB (${v.length} samples)`);
EOF
docker logs --since "$since" "$NAME" 2>&1 | node -e '
const lines = require("fs").readFileSync(0, "utf8").split("\n");
const ms = [];
for (const l of lines) {
  const m = /Request finished \S+ \S+ (\S+) - \d+ .* ([\d.]+)ms$/.exec(l);
  if (m && !m[1].includes("/_blazor")) ms.push(+m[2]);
}
ms.sort((a, b) => a - b);
const q = p => ms[Math.min(ms.length - 1, Math.floor(p * ms.length))].toFixed(1);
console.log(`requests: ${ms.length}, median ${q(0.5)} ms, p95 ${q(0.95)} ms, max ${ms[ms.length - 1].toFixed(1)} ms`);
'
