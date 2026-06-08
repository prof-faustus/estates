#!/bin/bash
# ESTATES node watchdog — keeps the BSV nodes UP (within 1 block of tip). Runs forever in a Docker
# container (restart=unless-stopped). For each node:
#   * if the CONTAINER is not running -> start it
#   * if RPC is up, the height is BEHIND the header tip, and it has NOT advanced for 4 checks -> it is
#     STUCK -> restart it
#   * RPC temporarily down (node busy starting / rolling forward) is NOT treated as stuck (don't interrupt)
# Logs every check to stdout (docker logs estates-watchdog).
declare -A last; declare -A stuck
rpc(){ curl -s --max-time 8 --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"w\",\"method\":\"$2\",\"params\":[]}" -H 'content-type: text/plain' "http://e:e@127.0.0.1:$1/" 2>/dev/null; }
height(){ rpc "$1" getblockcount | grep -o '"result":[0-9]*' | grep -o '[0-9]*$'; }
headers(){ rpc "$1" getblockchaininfo | grep -o '"headers":[0-9]*' | grep -o '[0-9]*$'; }
ts(){ date -u +%FT%TZ; }
echo "$(ts) watchdog started"
while true; do
  for entry in "estates-bsv-mainnet:8332" "estates-bsv-testnet:18332" "estates-bsv:18443"; do
    c=${entry%%:*}; p=${entry##*:}
    running=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)
    if [ "$running" != "true" ]; then
      echo "$(ts) $c CONTAINER_DOWN -> start"; docker start "$c" >/dev/null 2>&1; stuck[$c]=0; last[$c]=""; continue
    fi
    h=$(height "$p"); hd=$(headers "$p")
    if [ -z "$h" ]; then
      echo "$(ts) $c rpc-busy (starting/rolling-forward) — not counted as stuck"; stuck[$c]=0; last[$c]=""; continue
    fi
    if [ -n "$hd" ] && [ "$h" -lt $(( hd - 1 )) ] && [ "$h" = "${last[$c]:-_none_}" ]; then
      stuck[$c]=$(( ${stuck[$c]:-0} + 1 )); echo "$(ts) $c STUCK $h/$hd (count ${stuck[$c]})"
    else
      [ -n "$hd" ] && [ "$h" -ge $(( hd - 1 )) ] && echo "$(ts) $c UP $h/$hd" || echo "$(ts) $c syncing $h/$hd"
      stuck[$c]=0
    fi
    last[$c]=$h
    if [ "${stuck[$c]:-0}" -ge 4 ]; then
      echo "$(ts) $c RESTART (stuck while behind)"; docker restart "$c" >/dev/null 2>&1; stuck[$c]=0; last[$c]=""
    fi
  done
  sleep 180
done
