# @estates/link — invariants (every claim is an executable test)

Tests live in `packages/link/test/link.test.ts`. Read a claim, find the test, try to
break it.

## Authenticated transport

| # | Claim | Test |
|---|---|---|
| T1 | Two peers connect over real TCP, authenticate, and exchange encrypted frames both ways; mutual identity is learned | "two peers connect over REAL TCP, authenticate, and exchange encrypted frames" |
| T2 | Many frames stream in order across the link, none lost | "many frames stream in order across the TCP link" |

## Hostile-peer resistance (the socket is untrusted)

| # | Claim | Test |
|---|---|---|
| H1 | A dialer that cannot authenticate is dropped | "a dialer that cannot authenticate is dropped" |
| H2 | An oversized frame announcement is dropped before the buffer grows (#12) | "oversized frame announcement (#12) is dropped before the buffer grows" |
| H3 | Malformed handshake JSON destroys only that socket — no throw/crash (#13) | "malformed handshake JSON (#13) destroys only that socket, no throw/crash" |
| H4 | A JSON `null`/scalar/array handshake body is dropped, never crashes the listener (#13b) | "a JSON `null`/scalar handshake body (#13b) is dropped, never crashes the listener" |

> Off-curve / forged handshake totality is proven one layer down in
> `@estates/channel` (V1–V3), which `respond`/`complete` delegate to.

## How to attack this package (auditor guide)

1. Connect and send a 4-byte length of `0xffffffff`, then nothing → the server must drop
   you without allocating 4 GiB (H2).
2. Send a length prefix followed by `{ not json` → only your socket is destroyed; no
   uncaught exception (H3). Then try the JSON literals `null`, `42`, `"x"`, `[1,2,3]` as
   the body → still just dropped, no crash (H4).
3. Send a Hello with garbage/forged fields → dropped (H1; deeper cases in channel V1–V3).
4. Split a valid frame across several `write()`s of 1 byte each → still reassembled and
   delivered in order (T1/T2). A lost or reordered frame is a finding.
