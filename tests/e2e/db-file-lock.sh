#!/usr/bin/env bash
# Two Harpos on one database file, as real processes in separate containers, which the
# unit tests cannot set up. Started together, exactly one may run: a key change by one
# used to leave the other healthy on the deleted file, losing all it wrote, so each
# race ends with a sign-in on the winner that must be in the file afterwards.
# Usage: db-file-lock.sh <image>. Needs Docker, curl and the alpine image.
set -u
IMAGE=${1:?usage: db-file-lock.sh <image>}
RUN=harpo-filelock-$$
ENVS=(-e Harpo__SiteId=main -e Harpo__MasterKey=file-lock-test-master-key -e Auth__Mode=Development
  -e Auth__DevUsers__0__Username=alice -e Auth__DevUsers__0__Password=alice -e Auth__DevUsers__0__IsSiteAdmin=true)
UID_GID=1654
KEY=(-e Harpo__DatabaseKey=file-lock-key)
REMOVE=(-e Harpo__DatabaseKey=file-lock-key -e Harpo__RemoveDatabaseEncryption=true)
WAITING="Waiting up to"
passed=0; failed=0
check() { # name, command...
  local name=$1; shift
  if "$@"; then echo "  ok   $name"; passed=$((passed + 1)); else echo "  FAIL $name"; failed=$((failed + 1)); fi
}
cleanup() {
  docker ps -aq --filter "name=^$RUN" | xargs -r docker rm -f >/dev/null 2>&1
  docker volume ls -q --filter "name=^$RUN" | xargs -r docker volume rm >/dev/null 2>&1
}
trap cleanup EXIT

V=$RUN-data
docker volume create "$V" >/dev/null
docker run -d --name "$RUN-hold" -v "$V:/data" alpine:3.22 sh -c 'apk add --no-cache sqlite >/dev/null && touch /tmp/ready; sleep 3600' >/dev/null
for _ in $(seq 1 60); do docker exec "$RUN-hold" test -e /tmp/ready 2>/dev/null && break; sleep 1; done
on() { docker exec -i "$RUN-hold" sh -c "$*"; }

create() { # name, extra -e arguments...
  local c=$RUN-$1; shift
  docker rm -f "$c" >/dev/null 2>&1
  docker create --name "$c" "${ENVS[@]}" "$@" -p 127.0.0.1::8080 -v "$V:/data" "$IMAGE" >/dev/null
}
logs() { docker logs "$RUN-$1" 2>&1; }
status() { docker inspect -f '{{.State.Status}}' "$RUN-$1"; }
listening() { logs "$1" | grep -q 'Now listening'; }
waiting() { logs "$1" | grep -q "$WAITING"; }
exited() { [ "$(status "$1")" = exited ]; }
gone_files() { docker exec "$RUN-$1" sh -c 'ls -l /proc/1/fd | grep harpo.db | grep -c deleted'; }
remove() { docker rm -f "$RUN-$1" >/dev/null 2>&1; }

# Waits for one of the two to be serving and the other to have said it is waiting.
settled() { # a, b
  for _ in $(seq 1 60); do
    { listening "$1" && { waiting "$2" || exited "$2" || listening "$2"; }; } && return 0
    { listening "$2" && { waiting "$1" || exited "$1" || listening "$1"; }; } && return 0
    { exited "$1" && exited "$2"; } && return 1
    sleep 0.5
  done
  return 1
}
# Waits for a container to be serving, or to have exited.
ended() { for _ in $(seq 1 "${2:-120}"); do listening "$1" && return; exited "$1" && return; sleep 0.5; done; }

sign_in() { # container: a write the site must keep
  local port jar html token handler
  port=$(docker port "$RUN-$1" 8080/tcp | head -1 | sed 's/.*://')
  jar=$(mktemp)
  html=$(curl -s -c "$jar" "http://127.0.0.1:$port/login")
  token=$(grep -o 'name="__RequestVerificationToken"[^>]*value="[^"]*"' <<<"$html" | sed -E 's/.*value="([^"]*)"/\1/' | head -1)
  handler=$(grep -oE 'name="_handler"[^>]*value="[^"]*"' <<<"$html" | sed -E 's/.*value="([^"]*)"/\1/' | head -1)
  curl -s -o /dev/null -b "$jar" -c "$jar" -X POST "http://127.0.0.1:$port/login" \
    --data-urlencode "__RequestVerificationToken=$token" --data-urlencode "_handler=$handler" \
    --data-urlencode "Model.Username=alice" --data-urlencode "Model.Password=alice"
  rm -f "$jar"
}
# Sessions in the file, decrypting it first if a key change went through.
sessions() {
  if ! on 'head -c 15 /data/harpo.db' | grep -q 'SQLite format'; then
    create decrypt "${REMOVE[@]}"; docker start "$RUN-decrypt" >/dev/null; ended decrypt; remove decrypt
  fi
  on "sqlite3 /data/harpo.db 'SELECT count(*) FROM UserSessions'"
}
at_least_one() { [ "${1:-0}" -ge 1 ] 2>/dev/null; }

echo "Setting up a plain site"
create seed; docker start "$RUN-seed" >/dev/null; ended seed; remove seed
on "chown -R $UID_GID /data; mkdir -p /tmp/fixture; cp /data/harpo.db* /tmp/fixture/"
restore() { on "rm -f /data/harpo.db*; cp /tmp/fixture/* /data/; chown -R $UID_GID /data"; }

echo "One Harpo adding a key and one not, started together"
race() { # first, second, lead
  restore
  create plain; create keyed "${KEY[@]}"
  docker start "$RUN-$1" >/dev/null; sleep "$3"; docker start "$RUN-$2" >/dev/null
  local name="$1 first by $3 s"
  check "$name: one comes up" settled plain keyed
  winner=plain; loser=keyed; listening keyed && { winner=keyed; loser=plain; }
  check "$name: the $loser one does not" bash -c '! docker logs "$1" 2>&1 | grep -q "Now listening"' _ "$RUN-$loser"
  check "$name: the $winner one is on the real file" [ "$(gone_files "$winner")" = 0 ]
  sign_in "$winner"
  remove "$loser"
  docker stop -t 5 "$RUN-$winner" >/dev/null; remove "$winner"
  check "$name: what the $winner one wrote is in the file" at_least_one "$(sessions)"
}
for lead in 0 0.05 0.1 0.15 0.2 0.3 0.4; do
  race plain keyed "$lead"
  race keyed plain "$lead"
done

echo "Two Harpos adding the same key, started together"
restore
create one "${KEY[@]}"; create two "${KEY[@]}"
docker start "$RUN-one" >/dev/null; docker start "$RUN-two" >/dev/null
check "one comes up" settled one two
winner=one; loser=two; listening two && { winner=two; loser=one; }
check "the other waits, with no false message" waiting "$loser"
check "it has not come up" bash -c '! docker logs "$1" 2>&1 | grep -q "Now listening"' _ "$RUN-$loser"
docker stop -t 5 "$RUN-$winner" >/dev/null
ended "$loser"
check "it starts once the first has stopped" listening "$loser"
check "and says so" bash -c 'docker logs "$1" 2>&1 | grep -q "has let go"' _ "$RUN-$loser"
remove one; remove two

echo "Two Harpos started together on a new volume"
on 'rm -f /data/harpo.db*'
create one; create two
docker start "$RUN-one" >/dev/null; docker start "$RUN-two" >/dev/null
check "one comes up" settled one two
winner=one; loser=two; listening two && { winner=two; loser=one; }
check "the other waits rather than crashing" waiting "$loser"
remove one; remove two

echo "A Harpo that dies lets go"
restore
create site; docker start "$RUN-site" >/dev/null; ended site
check "the site is up" listening site
create next; docker start "$RUN-next" >/dev/null
for _ in $(seq 1 60); do waiting next && break; sleep 0.5; done
check "the next one waits" waiting next
docker kill -s KILL "$RUN-site" >/dev/null
ended next
check "it starts once the first is killed" listening next
remove site; remove next

echo "A second Harpo that outstays its wait"
restore
create site; docker start "$RUN-site" >/dev/null; ended site
sign_in site
create next "${KEY[@]}"; docker start "$RUN-next" >/dev/null
for _ in $(seq 1 90); do exited next && break; sleep 1; done
check "it stops" exited next
check "it says why" bash -c 'docker logs "$1" 2>&1 | grep -q "Another Harpo is using the database"' _ "$RUN-next"
check "the file is still plain" bash -c 'docker exec "$1" head -c 15 /data/harpo.db | grep -q "SQLite format"' _ "$RUN-hold"
check "the site is still running" [ "$(status site)" = running ]
check "it left nothing behind" bash -c '! docker exec "$1" ls /data | grep -q recrypt-tmp' _ "$RUN-hold"
sign_in site
docker stop -t 5 "$RUN-site" >/dev/null; remove site; remove next
check "what the site wrote is in the file" [ "$(sessions)" = 2 ]

echo "A filesystem where locks have no effect"
restore
create site -e DOTNET_SYSTEM_IO_DISABLEFILELOCKING=1; docker start "$RUN-site" >/dev/null; ended site
check "it starts" listening site
check "it warns" bash -c 'docker logs "$1" 2>&1 | grep -q "have no effect on this filesystem"' _ "$RUN-site"
remove site
create site; docker start "$RUN-site" >/dev/null; ended site
check "where they work it does not" bash -c '! docker logs "$1" 2>&1 | grep -q "have no effect"' _ "$RUN-site"
remove site

# These hold no lock file, so only SQLite's lock stands in the way.
hold_file() { # sql to run and stay connected
  on "(printf '%s\n' \"$1\"; sleep 60) | sqlite3 /data/harpo.db >/dev/null 2>&1 &"
  sleep 1
}
unhold() { on 'pkill sleep; pkill sqlite3; true'; sleep 1; }

echo "Something else idle on the file, in WAL mode"
restore
hold_file 'SELECT count(*) FROM sqlite_master;'
create next "${KEY[@]}"; docker start "$RUN-next" >/dev/null; ended next
check "adding a key stops" exited next
check "says the file is in use" bash -c 'docker logs "$1" 2>&1 | grep -q "in use by something else"' _ "$RUN-next"
remove next; unhold

echo "Something else writing to the file, in DELETE mode"
restore
on "sqlite3 /data/harpo.db 'PRAGMA journal_mode=DELETE' >/dev/null; chown -R $UID_GID /data"
hold_file 'BEGIN IMMEDIATE;'
create next "${KEY[@]}"; docker start "$RUN-next" >/dev/null; ended next
check "adding a key stops" exited next
check "says the file is in use" bash -c 'docker logs "$1" 2>&1 | grep -q "in use by something else"' _ "$RUN-next"
remove next; unhold

echo "$passed passed, $failed failed"
[ "$failed" = 0 ]
