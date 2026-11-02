#!/usr/bin/env bash
# Database encryption changes on a really full disk, which the unit tests cannot
# set up: real tmpfs volumes, so SQLite reports what it reports in production.
# Each change must stop with a message that says what is wrong, and leave the data
# readable. Usage: db-encryption-full-disk.sh <image>. Needs only Docker.
set -u
IMAGE=${1:?usage: db-encryption-full-disk.sh <image>}
RUN=harpo-fulldisk-$$
ENVS=(-e Harpo__SiteId=main -e Harpo__MasterKey=full-disk-test-master-key -e Auth__Mode=Development
  -e Auth__DevUsers__0__Username=alice -e Auth__DevUsers__0__Password=alice -e Auth__DevUsers__0__IsSiteAdmin=true)
UID_GID=1654
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

# A tmpfs volume loses its contents when nothing has it mounted, so a container
# keeps it mounted throughout; commands run there, as Harpo's user.
hold() { docker run -d --name "$RUN-hold" --user $UID_GID:$UID_GID --entrypoint sleep -v "$1:/data" "$IMAGE" 3600 >/dev/null; }
on() { shift; docker exec "$RUN-hold" sh -c "$*"; }

# Fills the volume until `leave` KB are free (0: until nothing is).
fill() { on "$1" "dd if=/dev/zero of=/data/fill bs=1k count=\$(( \$(df -k /data | tail -1 | awk '{print \$4}') - $2 )) 2>/dev/null; true"; }

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
no_copy() { [ -z "$(on "$1" 'ls /data | grep recrypt-tmp')" ]; }
hash_of() { on "$1" 'sha256sum /data/harpo.db'; }

KEY1=(-e Harpo__DatabaseKey=full-disk-key-1)
KEY2=(-e Harpo__DatabaseKey=full-disk-key-2 -e Harpo__PreviousDatabaseKey=full-disk-key-1)
REMOVE=(-e Harpo__DatabaseKey=full-disk-key-1 -e Harpo__RemoveDatabaseEncryption=true)

echo "Encrypting with too little room"
V=$(volume a 16m)
hold "$V"
start "$V"
check "a plain site starts" up
SIZE_KB=$(on "$V" "du -k /data/harpo.db | cut -f1")
fill "$V" $((SIZE_KB / 2))
BEFORE=$(hash_of "$V")
start "$V" "${KEY1[@]}"
check "refuses to start" down
check "says the disk is full and what it needs" says "not enough free disk space to encrypt"
check "leaves no partial copy" no_copy "$V"
check "does not change the file" [ "$BEFORE" = "$(hash_of "$V")" ]

echo "Encrypting once there is room"
on "$V" 'rm /data/fill'
start "$V" "${KEY1[@]}"
check "starts" up
check "says the file is encrypted" says "The database file is encrypted"

echo "Decrypting with too little room"
fill "$V" $((SIZE_KB / 2))
start "$V" "${REMOVE[@]}"
check "refuses to start" down
check "says the disk is full" says "not enough free disk space to decrypt"
check "leaves no partial copy" no_copy "$V"
on "$V" 'rm /data/fill'
start "$V" "${KEY1[@]}"
check "the key still opens it afterwards" up

echo "Rotating with too little room"
fill "$V" $((SIZE_KB / 2))
start "$V" "${KEY2[@]}"
check "refuses to start" down
check "does not say rotation is complete" silent "rotation complete"
check "does not call it a wrong key" silent "does not open it"
on "$V" 'rm /data/fill'
start "$V" "${KEY1[@]}"
check "the old key still opens it afterwards" up
start "$V" "${KEY2[@]}"
check "rotates once there is room" says "rotation complete"
start "$V" -e Harpo__DatabaseKey=full-disk-key-2
check "the new key alone opens it" up

echo "A volume with nothing free at all"
fill "$V" 0
start "$V" -e Harpo__DatabaseKey=full-disk-key-2
check "does not call the right key wrong" silent "does not open it"
on "$V" 'rm /data/fill'

echo "A wrong key is still told apart"
start "$V" -e Harpo__DatabaseKey=not-the-key
check "says the key does not open it" says "does not open it"
check "refuses to start" down

echo "$passed passed, $failed failed"
[ "$failed" = 0 ]
