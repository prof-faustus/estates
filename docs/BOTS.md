# ESTATES Bots — reference

A bot is **not** a person and **not** an AI making gameplay decisions — it is a separate node the human runs
and fully controls, used to test/fill a seat. This document specifies the bot's identity, persistence,
funding, and the mandatory refund-on-close ordering.

---

## 1. What a bot is

The same binary run as `estates.exe --bot --id N`. It opens its own narrow console window (docked to a
screen corner, never over the player window). It links to peers as a normal node, can chat and play its
seat inside a real, funded, on-chain game it has joined, and never simulates a solo game.

## 2. Fixed id → separate, persistent wallet

Each bot has a **fixed id** (`--id N`). Its seed is stored per id at `%APPDATA%/Estates/bots/bot_N.seed`,
created once and reused — so bot #N always reloads the **same** wallet and identity across restarts.
Spawning 10 bots = 10 fixed ids = 10 separate persistent wallets. The id is selectable on spawn.

## 3. Network selectable

The bot has its own network selector (mainnet / testnet / regtest); switching rebuilds its wallet + SPV
view for that network and re-derives its receive address. Its addresses, like the player's, are HMAC
hash-chain sub-keys (index ≥ 1); index 0 is the bot's identity key and is never an address.

## 4. Funding — pay is pay (no import)

There is **no** "import coin" and **no** special bot-funding method. You fund a bot by **paying its
address** — a real on-chain payment (from the player's Send tab or chat `\pay bot#N <sat>`). The bot shows
its receive address (copyable) and SPV-displays the balance paid to it.

## 5. Refund-to-funder on close (absolute)

When a bot closes (End bot, the human's GameClose signal, or window close), it **SPV-spends its entire
balance back to the funder** (the controlling player peer's advertised address), broadcasts it, and acks
the player — then exits holding nothing. No sat is ever left in a bot.

## 6. Close ordering (absolute)

When the **human** closes the game, **every funded bot closes and refunds the human FIRST**, before the
human's game finishes closing. Sequence: human-close is held → `GameClose` is sent to each bot → each bot
refunds + acks → the player waits for the acks (bounded) → then the player's game exits. A bot left running
or holding funds after the human closes is a 100% failure.

## 7. Human control

A person chooses every action; the bot never makes gameplay decisions for the human. Bots are a
test/seat-fill tool the human controls — consistent with the project-wide human-control rule.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
