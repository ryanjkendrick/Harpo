#!/usr/bin/env bash
# Writes database files with a published .NET 10 build of Harpo, for the .NET 11 step-0 interop
# tests: a file the old SQLCipher bundle wrote must open under SQLite3 Multiple Ciphers, and
# rows that are only in the WAL must survive. Each site gets three sign-ins, so UserSessions
# has rows to count; expected.txt records what the old build itself reads back.
# Usage: make.sh [image]   (default ryanjkendrick/harpo:0.7.6). Needs Docker and curl.
set -euo pipefail
IMAGE=${1:-ryanjkendrick/harpo:0.7.6}
OUT=$(cd "$(dirname "$0")" && pwd)
RUN=harpo-fixtures-$$
KEY=net10-fixture-database-key
cleanup() {
  docker ps -aq --filter "name=^$RUN" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "name=^$RUN" | xargs -r docker volume rm >/dev/null 2>&1 || true
}
trap cleanup EXIT

start() { # name, extra -e arguments...
  local n=$1; shift
  docker volume create "$RUN-$n" >/dev/null
  docker run -d --name "$RUN-$n" -p 127.0.0.1::8080 -v "$RUN-$n:/data" \
    -e Harpo__SiteId="$n" -e Harpo__MasterKey=net10-fixture-master-key -e Auth__Mode=Development \
    -e Auth__DevUsers__0__Username=alice -e Auth__DevUsers__0__Password=alice \
    -e Auth__DevUsers__0__IsSiteAdmin=true "$@" "$IMAGE" >/dev/null
  for _ in $(seq 1 90); do docker logs "$RUN-$n" 2>&1 | grep -q 'Now listening' && return; sleep 1; done
  echo "site $n did not start" >&2; docker logs "$RUN-$n" >&2; exit 1
}
sign_in() { # name
  local port jar
  port=$(docker port "$RUN-$1" 8080 | head -1 | sed 's/.*://')
  jar=$(mktemp)
  for _ in 1 2 3; do
    local token
    token=$(curl -s -c "$jar" -b "$jar" "http://127.0.0.1:$port/login" \
      | sed -n 's/.*name="__RequestVerificationToken" value="\([^"]*\)".*/\1/p' | head -1)
    curl -s -o /dev/null -c "$jar" -b "$jar" -X POST "http://127.0.0.1:$port/login" \
      --data-urlencode "_handler=login" --data-urlencode "__RequestVerificationToken=$token" \
      --data-urlencode "Model.Username=alice" --data-urlencode "Model.Password=alice"
    : > "$jar"
  done
  rm -f "$jar"
}
copy_out() { # volume name, files..., then target dir
  local v=$1; shift; local dir=${*: -1}; local files=("${@:1:$#-1}")
  mkdir -p "$OUT/$dir"
  docker run --rm -v "$RUN-$v:/from:ro" -v "$OUT/$dir:/to" alpine:3.22 \
    sh -c "cd /from && cp ${files[*]} /to/ && chmod 644 /to/*"
}

start plain
start encrypted -e Harpo__DatabaseKey=$KEY
sign_in plain
sign_in encrypted

# Rows only in the WAL: freeze the site and copy the file and its WAL as they stand.
docker pause "$RUN-encrypted" >/dev/null
copy_out encrypted harpo.db harpo.db-wal encrypted-wal
docker unpause "$RUN-encrypted" >/dev/null

# Clean files: a stop closes the last connection, which folds the WAL into the file.
docker stop -t 30 "$RUN-plain" "$RUN-encrypted" >/dev/null
copy_out plain harpo.db plain
copy_out encrypted harpo.db encrypted

# What SQLCipher 4 itself reads back, as the reference for the new engine. It reads copies:
# closing a file opened in WAL mode folds the WAL in and deletes it.
docker run --rm -v "$OUT:/src:ro" alpine:3.22 sh -c '
  apk add --no-cache sqlcipher >/dev/null
  mkdir /f && cp -r /src/plain /src/encrypted /src/encrypted-wal /f/
  q() { printf "%s\n" "$2" "SELECT count(*) FROM sqlite_master;" "SELECT count(*) FROM UserSessions;" "SELECT max(MigrationId) FROM __EFMigrationsHistory;" \
        | sqlcipher -batch "$1" 2>&1 | grep -v "^ok$" | tr "\n" " "; }
  cp -r /f/encrypted-wal /tmp/w && rm /tmp/w/harpo.db-wal
  echo "image: '"$IMAGE"'"
  echo "key (encrypted, encrypted-wal): '"$KEY"'"
  echo "columns: sqlite_master rows, UserSessions rows, latest migration"
  echo "plain:                 $(q /f/plain/harpo.db "")"
  echo "encrypted:             $(q /f/encrypted/harpo.db "PRAGMA key = '\'''"$KEY"''\'';")"
  echo "encrypted-wal:         $(q /f/encrypted-wal/harpo.db "PRAGMA key = '\'''"$KEY"''\'';")"
  echo "encrypted-wal, no WAL: $(q /tmp/w/harpo.db "PRAGMA key = '\'''"$KEY"''\'';")"
' > "$OUT/expected.txt"
cat "$OUT/expected.txt"
