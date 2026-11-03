#!/usr/bin/env bash
# Database encryption changes on really full disks, and with a second Harpo on the
# file, which the unit tests cannot set up: real tmpfs volumes and real processes, so
# SQLite does what it does in production. Each change must either finish or stop with
# a message saying what is wrong, and every row must survive, including rows only in
# the WAL. Usage: db-encryption-full-disk.sh <image>. Needs Docker and the alpine image.
set -u
IMAGE=${1:?usage: db-encryption-full-disk.sh <image>}
RUN=harpo-fulldisk-$$
ENVS=(-e Harpo__SiteId=main -e Harpo__MasterKey=full-disk-test-master-key -e Auth__Mode=Development
  -e Auth__DevUsers__0__Username=alice -e Auth__DevUsers__0__Password=alice -e Auth__DevUsers__0__IsSiteAdmin=true)
UID_GID=1654
MARKERS=2000
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

volume() { docker volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt "o=size=$2,uid=$UID_GID,gid=$UID_GID" "$RUN-$1" >/dev/null; echo "$RUN-$1"; }

# A tmpfs volume loses its contents when nothing has it mounted, so a container keeps
# it mounted throughout; commands run there, with the SQLite command-line tool to hand.
hold() {
  docker rm -f "$RUN-hold" >/dev/null 2>&1
  docker run -d --name "$RUN-hold" -v "$1:/data" alpine:3.22 sh -c 'apk add --no-cache sqlite >/dev/null && touch /tmp/ready; sleep 3600' >/dev/null
  for _ in $(seq 1 60); do on 'test -e /tmp/ready' 2>/dev/null && return; sleep 1; done
  echo "the helper container did not get ready" >&2; exit 1
}
on() { docker exec -i "$RUN-hold" sh -c "$*"; }

# Fills the volume until `leave` KB are free (0: until nothing is).
fill() { on "dd if=/dev/zero of=/data/fill bs=1k count=\$(( \$(df -k /data | tail -1 | awk '{print \$4}') - $1 )) 2>/dev/null; chown $UID_GID /data/fill; true"; }
unfill() { on 'rm -f /data/fill'; }

n=0
# Starts Harpo on the volume, waits until it is up or has exited, stops it, leaves its log in $LOG.
start() { # volume, extra -e arguments...
  local v=$1; shift; n=$((n + 1)); local c=$RUN-$n
  docker run -d --name "$c" "${ENVS[@]}" "$@" -v "$v:/data" "$IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    docker logs "$c" 2>&1 | grep -q "Now listening\|Application started" && break
    [ "$(docker inspect -f '{{.State.Status}}' "$c")" = exited ] && break
    sleep 1
  done
  LOG=$(docker logs "$c" 2>&1)
  STATE=$(docker inspect -f '{{.State.Status}}' "$c")
  docker stop -t 3 "$c" >/dev/null 2>&1
  docker rm -f "$c" >/dev/null 2>&1
}
says() { grep -q "$1" <<<"$LOG"; }
silent() { ! grep -q "$1" <<<"$LOG"; }
up() { [ "$STATE" = running ]; }
down() { [ "$STATE" != running ]; }
no_copy() { on 'cd /data && ! ls | grep -q recrypt-tmp'; }
hash_of() { on 'sha256sum /data/harpo.db' | cut -d' ' -f1; }
same() { [ -n "$1" ] && [ "$1" = "$2" ]; }
is_plain() { on 'head -c 15 /data/harpo.db' | grep -q 'SQLite format'; }

# Commits rows that end up only in the WAL, then leaves the files as a kill would: a
# copy taken with the connection still open, restored after it has closed.
rows_in_wal() {
  on "rm -rf /tmp/kept; mkdir /tmp/kept; sqlite3 /data/harpo.db" <<SQL >/dev/null
PRAGMA journal_mode=WAL;
PRAGMA wal_autocheckpoint=0;
CREATE TABLE Marker (x);
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $MARKERS)
INSERT INTO Marker SELECT randomblob(1000) FROM n;
.shell cp /data/harpo.db /data/harpo.db-wal /tmp/kept/
SQL
  on 'cp /tmp/kept/harpo.db /tmp/kept/harpo.db-wal /data/ && rm -f /data/harpo.db-shm; mkdir -p /tmp/fixture; cp /tmp/kept/* /tmp/fixture/; chown -R '$UID_GID' /data'
}
restore_rows_in_wal() { on 'rm -f /data/harpo.db* /data/fill; cp /tmp/fixture/* /data/; chown -R '$UID_GID' /data'; }

# How many of the rows a plain file holds, read from a copy so the WAL stays as it is.
markers() {
  on 'rm -rf /tmp/look; mkdir /tmp/look; cp /data/harpo.db* /tmp/look/; sqlite3 /tmp/look/harpo.db "SELECT count(*) FROM Marker"'
}
markers_all_there() { [ "$(markers)" = "$MARKERS" ]; }

KEY1=(-e Harpo__DatabaseKey=full-disk-key-1)
KEY2=(-e Harpo__DatabaseKey=full-disk-key-2 -e Harpo__PreviousDatabaseKey=full-disk-key-1)
ONLY2=(-e Harpo__DatabaseKey=full-disk-key-2)
REMOVE=(-e Harpo__DatabaseKey=full-disk-key-1 -e Harpo__RemoveDatabaseEncryption=true)

echo "Setting up a site with rows only in the WAL"
V=$(volume a 40m)
hold "$V"
start "$V"
check "a plain site starts" up
rows_in_wal
WAL_KB=$(on 'du -k /data/harpo.db-wal | cut -f1')
echo "  the WAL is $WAL_KB KB"
check "the rows are there to begin with" markers_all_there

# From too little room to fold the WAL in, through room for the copy but not for
# both it and the fold, to plenty. Some of these finish and some stop: what matters
# is that a stop says why, and that no row is lost either way.
echo "Adding a key with rows only in the WAL, at every amount of free space"
for percent in 25 50 75 100 125 150 175 200 250 300; do
  restore_rows_in_wal
  fill $((WAL_KB * percent / 100))
  start "$V" "${KEY1[@]}"
  if up; then
    check "$percent% of the WAL free: says it finished" says "Database encryption complete"
    check "$percent% of the WAL free: leaves no copy" no_copy
    unfill
    start "$V" "${REMOVE[@]}"
    check "$percent% of the WAL free: decrypts again with room" is_plain
  else
    check "$percent% of the WAL free: says the disk is full" says "not enough free disk space to encrypt"
    check "$percent% of the WAL free: leaves no copy" no_copy
    check "$percent% of the WAL free: the file is still plain" is_plain
  fi
  check "$percent% of the WAL free: every row is there" markers_all_there
done

# The case the runs above cannot show, because the copy holds every row and a swap that
# works hides any loss: the WAL cannot be folded in AND the swap fails. The database
# file gets its own small volume, too small to fold into, mounted as a file so it
# cannot be replaced; the WAL and the copy have plenty of room beside it. A site that
# deleted the WAL here would be left with only what the main file held.
echo "The WAL cannot be folded in and the swap fails"
restore_rows_in_wal
SMALL=$(volume b 1m)
docker run -d --name "$RUN-hold2" -v "$SMALL:/small" alpine:3.22 sleep 3600 >/dev/null
docker exec -i "$RUN-hold2" sh -c "cat > /small/harpo.db; chown $UID_GID /small/harpo.db" < <(on 'cat /data/harpo.db')
on 'rm /data/harpo.db; touch /data/harpo.db; chown '$UID_GID' /data/harpo.db'
n=$((n + 1)); c=$RUN-$n
docker run -d --name "$c" "${ENVS[@]}" "${KEY1[@]}" -v "$V:/data" \
  --mount "type=volume,source=$SMALL,target=/data/harpo.db,volume-subpath=harpo.db" "$IMAGE" >/dev/null
for _ in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Status}}' "$c")" = exited ] && break; sleep 1; done
LOG=$(docker logs "$c" 2>&1); STATE=$(docker inspect -f '{{.State.Status}}' "$c")
docker rm -f "$c" >/dev/null 2>&1
check "refuses to start" down
check "says the disk is full" says "not enough free disk space to encrypt"
docker exec "$RUN-hold2" cat /small/harpo.db | on 'cat > /data/harpo.db; chown '$UID_GID' /data/harpo.db'
check "the WAL is kept" on 'test -s /data/harpo.db-wal'
check "every row is there" markers_all_there
docker rm -f "$RUN-hold2" >/dev/null 2>&1

echo "A stopped change with room afterwards"
restore_rows_in_wal
fill $((WAL_KB / 4))
start "$V" "${KEY1[@]}"
check "refuses to start" down
unfill
start "$V" "${KEY1[@]}"
check "starts once there is room" up
check "says the file is encrypted" says "The database file is encrypted"
SIZE_KB=$(on 'du -k /data/harpo.db | cut -f1')

echo "Decrypting with too little room"
fill $((SIZE_KB / 2))
BEFORE=$(hash_of)
start "$V" "${REMOVE[@]}"
check "refuses to start" down
check "says the disk is full" says "not enough free disk space to decrypt"
check "leaves no partial copy" no_copy
check "does not change the file" same "$BEFORE" "$(hash_of)"
unfill
start "$V" "${KEY1[@]}"
check "the key still opens it afterwards" up

echo "Rotating with too little room"
fill $((SIZE_KB / 2))
start "$V" "${KEY2[@]}"
check "refuses to start" down
check "does not say rotation is complete" silent "rotation complete"
check "does not call it a wrong key" silent "does not open it"
check "says what happened" says "did not take effect\|not enough free disk space\|could not write to the volume"
unfill
start "$V" "${KEY1[@]}"
check "the old key still opens it afterwards" up
start "$V" "${KEY2[@]}"
check "rotates once there is room" says "rotation complete"
start "$V" "${ONLY2[@]}"
check "the new key alone opens it" up

echo "A volume with nothing free at all"
fill 0
start "$V" "${ONLY2[@]}"
check "does not call the right key wrong" silent "does not open it"
check "says what is wrong, or starts" bash -c '[ "$1" = running ] || grep -q "could not\|not enough free\|disk is full" <<<"$2"' _ "$STATE" "$LOG"
unfill

echo "A wrong key is still told apart"
start "$V" -e Harpo__DatabaseKey=not-the-key
check "says the key does not open it" says "does not open it"
check "refuses to start" down

# Without its lock file, as a version too old to take one would run, so that only
# SQLite's lock stands in the way. db-file-lock.sh covers Harpos that do take it.
echo "A second Harpo on a file another has open"
SITE=$RUN-site
docker run -d --name "$SITE" "${ENVS[@]}" "${ONLY2[@]}" -e DOTNET_SYSTEM_IO_DISABLEFILELOCKING=1 -v "$V:/data" "$IMAGE" >/dev/null
for _ in $(seq 1 60); do docker logs "$SITE" 2>&1 | grep -q "Now listening\|Application started" && break; sleep 1; done
start "$V" -e Harpo__DatabaseKey=full-disk-key-2 -e Harpo__RemoveDatabaseEncryption=true
check "decrypting refuses to start" down
check "says the file is in use" says "in use by something else"
check "leaves it encrypted" bash -c '! docker exec -i "$1" head -c 15 /data/harpo.db | grep -q "SQLite format"' _ "$RUN-hold"
start "$V" -e Harpo__DatabaseKey=full-disk-key-3 -e Harpo__PreviousDatabaseKey=full-disk-key-2
check "rotating refuses to start" down
check "says the file is in use" says "in use by something else"
check "the first site is still running" [ "$(docker inspect -f '{{.State.Status}}' "$SITE")" = running ]
docker stop -t 3 "$SITE" >/dev/null
docker rm -f "$SITE" >/dev/null
start "$V" "${ONLY2[@]}"
check "the key still opens it afterwards" up

echo "$passed passed, $failed failed"
[ "$failed" = 0 ]
