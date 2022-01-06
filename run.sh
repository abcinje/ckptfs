#!/usr/bin/env bash

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 <command>"
  exit 1
fi

export CKPT="ckpt"
export BB="bb"
export PFS="pfs"

mkdir -p "$CKPT"
mkdir -p "$BB"
mkdir -p "$PFS"

repos_root=$(dirname $0)

if [ ! -e "/dev/shm/ckptfs" ]; then
  "$repos_root/build/bin/drainer" &
fi

LD_PRELOAD="$repos_root/build/lib/libckpt.so" "$@"
