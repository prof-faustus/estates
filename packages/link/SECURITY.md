# @estates/link — security boundary

Reference cryptographic infrastructure: the **native IP-to-IP TCP transport** that runs
the `@estates/channel` handshake over a real socket and then carries sealed frames. No
relay, no server — two peers connect directly. Written so an auditor can attack it.

## What this package is

`listen`/`connect` perform the channel handshake over a length-prefixed TCP stream and
hand back a `PeerLink`. The wire is `4-byte big-endian length ‖ JSON`. The first message
is the handshake (Hello→Ack); every later message is a `{t:'frame', f: sealedFrame}`.
`PeerLink.send` seals plaintext; inbound frames are opened and delivered to handlers.

## Threat model

Either endpoint is **fully hostile** and controls every byte on the socket:

- a length prefix announcing a gigantic frame (memory-pressure DoS);
- a handshake body that is non-JSON, or valid JSON that is `null`/a scalar/an array
  (so `.t` would throw on a non-object);
- a structurally-hostile but signed Hello/Ack (delegated to `@estates/channel`, which is
  total — see its SECURITY.md, incl. the off-curve ECDH crash);
- a malformed sealed frame after the handshake;
- bytes split arbitrarily across TCP segments (framing confusion).

**Any single hostile message must, at worst, drop that one socket — never throw out of
the socket's `data` handler (which would be an uncaught exception = whole-process crash =
remote DoS).**

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `framedReader` / inbound length prefix | **Fully untrusted** | A length `> MAX_FRAME` (1 MiB) destroys the socket BEFORE the buffer grows to the claimed size. Partial frames buffer until complete. |
| Handshake parse (`listen`/`connect`) | **Fully untrusted** | `JSON.parse` in `try/catch` (non-JSON → destroy socket). The `.t` access is guarded by `msg && typeof msg === 'object'` (a JSON `null`/scalar cannot crash the handler). `respond`/`complete` are total. |
| `respond`/`complete` (`@estates/channel`) | **Fully untrusted** | Total: never throw on any Hello/Ack, incl. an off-curve ephemeral key. |
| `openFrame` per inbound frame | **Fully untrusted** | Returns plaintext or `null`; the `onMsg` callback runs inside the reader's `try/catch`, so a throw cannot escape. |
| `send`, `bind` | **Trusted** (our session) | Seal with the agreed key; frame and write. |

## Invariants (each is a test — see INVARIANTS.md)

- **Real-socket round-trip:** two peers authenticate over TCP and exchange encrypted
  frames both ways; mutual identity is learned; many frames arrive in order, none lost.
- **Unauthenticated dialer dropped:** garbage instead of a Hello closes the socket.
- **Oversized frame dropped:** a 4 GiB length announcement drops the peer before buffering.
- **Malformed handshake isolated:** non-JSON, or a JSON `null`/scalar/array body, destroys
  only that socket — no uncaught exception escapes (no process crash).

## What must never be assumed

- That a length prefix is honest — it is capped before allocation.
- That a handshake body is an object — `.t` is guarded.
- That `respond`/`complete` cannot throw — they are total, but the transport still treats
  a `null` result as "drop the socket".
- That TCP delivers message-aligned chunks — the reader reassembles by length prefix.

## Known non-goals

- This is Node-side (real sockets); the browser talks to it over loopback.
- Connection-rate / SYN-flood DoS (OS/firewall concern, not this layer).
- Metadata privacy (peer IP + connection timing are inherently visible).
