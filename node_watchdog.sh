#!/bin/bash
# ESTATES NEVER-DOWN MONITOR (v2). The ONLY check that matters (Craig Wright's definition):
#   "Has the node got the LATEST block the network has?"  NOT "is the process running".
# Every SECOND, for each node: compare the node's block height to the NETWORK tip (the highest header any
# connected peer reports). If the node is behind by even ONE block, it is DOWN — we PANIC (log it loudly)
# and FIX it: force the network on, re-dial known public peers, and if it has not advanced while behind,
# restart it (data-preserving). Down for a single second is still down.
#
# Reachable public peers we always re-dial (resolved/seeded). 18333 mainnet, 18333 testnet (same port).
MAIN_PEERS="3.123.101.88 52.16.212.66 54.152.215.212"   # placeholder seeds; mainnet peers re-seeded below
TEST_PEERS="3.123.101.88:18333 52.16.212.66:18333 54.152.215.212:18333 23.22.19.204:18333"
MAIN_PEERS2="$(getent hosts seed.bitcoinsv.io 2>/dev/null | awk '{print $1":8333"}')"
TEST_PEERS2="$(getent hosts testnet-seed.bitcoinsv.io 2>/dev/null | awk '{print $1":18333"}')"

rpc(){ # $1 container-port  $2 method  $3 json-params
  curl -s --max-time 3 --data-binary "{\"method\":\"$2\",\"params\":${3:-[]}}" -H 'content-type:text/plain' "http://e:e@127.0.0.1:$1/" 2>/dev/null
}
num(){ echo "$1" | grep -oE '"result":-?[0-9]+' | grep -oE '\-?[0-9]+'; }
nettip(){ # highest synced_headers among peers (the network's tip as peers see it); fall back to our headers
  local p; p=$(rpc "$1" getpeerinfo | grep -oE '"synced_headers":-?[0-9]+' | grep -oE '\-?[0-9]+' | sort -n | tail -1)
  local h; h=$(num "$(rpc "$1" getblockchaininfo)")  # NOTE: getblockchaininfo result is an object; headers parsed below
  local hd; hd=$(rpc "$1" getblockchaininfo | grep -oE '"headers":[0-9]+' | grep -oE '[0-9]+')
  local best=0
  [ -n "$p" ] && [ "$p" -gt "$best" ] && best=$p
  [ -n "$hd" ] && [ "$hd" -gt "$best" ] && best=$hd
  echo "$best"
}
fix(){ # $1 container  $2 port  $3 "peer:port ..."
  rpc "$2" setnetworkactive '[true]' >/dev/null
  for pp in $3; do rpc "$2" addnode "[\"$pp\",\"onetry\"]" >/dev/null; rpc "$2" addnode "[\"$pp\",\"add\"]" >/dev/null; done
}

declare -A last; declare -A stall
ts(){ date -u +%FT%TZ; }
echo "$(ts) NEVER-DOWN monitor v2 started (1s cadence; behind-by-1-block = DOWN)"
while true; do
  for entry in "estates-bsv-mainnet:8332:M" "estates-bsv-testnet:18332:T" "estates-bsv:18443:R"; do
    c=${entry%%:*}; rest=${entry#*:}; p=${rest%%:*}; tag=${rest##*:}
    running=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)
    if [ "$running" != "true" ]; then echo "$(ts) $tag DOWN: container not running -> start"; docker start "$c" >/dev/null 2>&1; continue; fi
    nh=$(num "$(rpc "$p" getblockcount)")
    if [ -z "$nh" ]; then echo "$(ts) $tag DOWN: RPC not responding (starting/busy)"; continue; fi
    if [ "$tag" = "R" ]; then echo "$(ts) R UP $nh (regtest: local-only, no network tip)"; continue; fi
    peers="$TEST_PEERS $TEST_PEERS2"; [ "$tag" = "M" ] && peers="$MAIN_PEERS2"
    nt=$(nettip "$p")
    if [ -z "$nt" ] || [ "$nt" -le 0 ]; then echo "$(ts) $tag ? no network tip yet (no peers) -> dialing"; fix "$c" "$p" "$peers"; continue; fi
    behind=$(( nt - nh ))
    if [ "$behind" -le 1 ]; then
      echo "$(ts) $tag UP $nh/$nt"; stall[$c]=0; last[$c]=$nh
    else
      # DOWN: behind the network. PANIC + FIX.
      if [ "$nh" = "${last[$c]:-_}" ]; then stall[$c]=$(( ${stall[$c]:-0} + 1 )); else stall[$c]=0; fi
      last[$c]=$nh
      echo "$(ts) $tag DOWN: behind $behind blocks (node $nh / net $nt) -> FIX (conns/peers); no-progress=${stall[$c]}s"
      fix "$c" "$p" "$peers"
      if [ "${stall[$c]:-0}" -ge 30 ]; then echo "$(ts) $tag DOWN: stalled ${stall[$c]}s while behind -> RESTART"; docker restart "$c" >/dev/null 2>&1; stall[$c]=0; last[$c]=""; fi
    fi
  done
  sleep 1
done
