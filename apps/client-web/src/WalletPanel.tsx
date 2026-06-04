import { useMemo, useState } from 'react';
import { Wallet, type Network } from '@estates/wallet';
import { DEFAULT_RELAY } from './game';

/**
 * Your full wallet — shown at ALL times. It's a wallet as much as a game: a
 * spendable key you control. Tabs: Receive · Send · Balance · Key. You fund and
 * DEFUND (send) yourself, any time; nobody asks you for money. (Send / balance
 * use WhatsOnChain on testnet/mainnet.)
 */
type Tab = 'receive' | 'send' | 'balance' | 'key';

export function WalletPanel({ wif, network }: { wif: string; network: Network }) {
  const wallet = useMemo(() => { try { return Wallet.fromWif(wif, network); } catch { return null; } }, [wif, network]);
  const [tab, setTab] = useState<Tab>('receive');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [confirmReal, setConfirmReal] = useState(false);
  const [status, setStatus] = useState('');
  const [balance, setBalance] = useState<number | null>(null);
  // regtest spends use YOUR node's JSON-RPC (there is no WhatsOnChain for regtest).
  // Pre-filled with the STANDARD local-node defaults so Send works out of the box;
  // edit only if your node differs. (You hold the key; nobody asks you for money.)
  const [rpcUrl, setRpcUrl] = useState('http://127.0.0.1:18443');
  const [rpcUser, setRpcUser] = useState('bitcoin');
  const [rpcPass, setRpcPass] = useState('bitcoin');
  const isReg = network === 'regtest';
  const canSend = !isReg || rpcUrl.trim() !== '';

  // regtest RPC goes through the local relay's loopback PROXY, never straight to
  // bitcoind: a webview can't fetch the node directly (no CORS on bitcoind → the
  // call dies as "Failed to fetch"). The relay (same loopback origin we already
  // reach) forwards to YOUR node and returns the result.
  async function rpc(method: string, params: unknown[]): Promise<any> {
    let r: Response;
    try {
      r = await fetch(`${DEFAULT_RELAY}/rpc`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: rpcUrl.trim(), user: rpcUser, pass: rpcPass, method, params }),
      });
    } catch {
      throw new Error('relay not reachable — is the ESTATES relay running on ' + DEFAULT_RELAY + '?');
    }
    const j = (await r.json()) as { result?: any; error?: { message: string } };
    if (j.error) throw new Error(`${method}: ${j.error.message}`);
    return j.result;
  }

  async function refreshBalance() {
    if (!wallet) return;
    setStatus('checking balance…');
    try {
      if (isReg) {
        const scan = await rpc('scantxoutset', ['start', [`addr(${wallet.address})`]]);
        setBalance(Math.round((scan.total_amount as number) * 1e8));
      } else {
        setBalance(await wallet.getBalance());
      }
      setStatus('');
    } catch (e) { setStatus(err(e)); }
  }

  async function doSend() {
    if (!wallet) return;
    const sats = Number(amount);
    if (!to.trim() || !Number.isFinite(sats) || sats <= 0) { setStatus('enter a destination address and a positive amount'); return; }
    if (isReg && !rpcUrl.trim()) { setStatus('regtest: paste your node’s RPC URL below to spend (regtest coins come from your node)'); return; }
    if (network === 'mainnet' && !confirmReal) { setStatus('tick “spend real value” to send on mainnet'); return; }
    setStatus('signing + broadcasting…');
    try {
      if (isReg) {
        const scan = await rpc('scantxoutset', ['start', [`addr(${wallet.address})`]]);
        const unspents = (scan.unspents as { txid: string; vout: number; amount: number }[]) ?? [];
        if (unspents.length === 0) throw new Error('no regtest funds at your address — fund it from your node first');
        const utxos = [] as { sourceTxHex: string; vout: number; satoshis: number }[];
        for (const u of unspents) {
          const raw = (await rpc('getrawtransaction', [u.txid])) as string; // needs txindex=1
          utxos.push({ sourceTxHex: raw, vout: u.vout, satoshis: Math.round(u.amount * 1e8) });
        }
        const { hex } = await wallet.buildAndSign(utxos, [{ address: to.trim(), satoshis: sats }]);
        const txid = (await rpc('sendrawtransaction', [hex])) as string;
        setStatus(`sent ✓ txid ${txid}`);
      } else {
        const r = await wallet.send(to.trim(), sats, network === 'mainnet' ? confirmReal : true);
        setStatus(`sent ✓ txid ${r.txid}`);
      }
      setAmount('');
    } catch (e) { setStatus(err(e)); }
  }

  return (
    <section className="wallet">
      <h3>Your wallet · {network}</h3>
      <div className="tabs">
        {(['receive', 'send', 'balance', 'key'] as Tab[]).map((tb) => (
          <button key={tb} className={tab === tb ? 'tab on' : 'tab'} onClick={() => setTab(tb)}>{tb}</button>
        ))}
      </div>

      {!wallet && <p className="hint">invalid key</p>}

      {wallet && tab === 'receive' && (
        <div className="wtab">
          <div className="wrow">your address (give this out to receive):</div>
          <code>{wallet.address}</code>
        </div>
      )}

      {wallet && tab === 'send' && (
        <div className="wtab">
          <input placeholder="destination address" value={to} onChange={(e) => setTo(e.target.value)} />
          <input placeholder="amount (sat)" value={amount} onChange={(e) => setAmount(e.target.value)} />
          {isReg && (
            <div className="rpcbox">
              <p className="hint">regtest spends use YOUR node’s RPC (regtest coins come from your node):</p>
              <input placeholder="RPC URL e.g. http://127.0.0.1:18443" value={rpcUrl} onChange={(e) => setRpcUrl(e.target.value)} />
              <input placeholder="RPC user" value={rpcUser} onChange={(e) => setRpcUser(e.target.value)} />
              <input placeholder="RPC pass" type="password" value={rpcPass} onChange={(e) => setRpcPass(e.target.value)} />
            </div>
          )}
          {network === 'mainnet' && <label><input type="checkbox" checked={confirmReal} onChange={(e) => setConfirmReal(e.target.checked)} /> spend real value</label>}
          <button className="primary" disabled={!canSend} onClick={doSend}>Send</button>
          {status && <p className="hint">{status}</p>}
        </div>
      )}

      {wallet && tab === 'balance' && (
        <div className="wtab">
          {isReg && (
            <div className="rpcbox">
              <p className="hint">regtest balance uses YOUR node’s RPC:</p>
              <input placeholder="RPC URL e.g. http://127.0.0.1:18443" value={rpcUrl} onChange={(e) => setRpcUrl(e.target.value)} />
              <input placeholder="RPC user" value={rpcUser} onChange={(e) => setRpcUser(e.target.value)} />
              <input placeholder="RPC pass" type="password" value={rpcPass} onChange={(e) => setRpcPass(e.target.value)} />
            </div>
          )}
          <button disabled={isReg && !rpcUrl.trim()} onClick={refreshBalance}>Refresh balance</button>
          {balance !== null && <p>balance: <b>{balance}</b> sat</p>}
          {status && <p className="hint">{status}</p>}
        </div>
      )}

      {wallet && tab === 'key' && (
        <div className="wtab">
          <div className="wrow">root key (WIF) — keep it safe; it controls all funds:</div>
          <code className="wif">{wif}</code>
          <p className="hint">You hold the key. Fund or defund (Send) yourself, any time. Nobody asks you for money.</p>
        </div>
      )}
    </section>
  );
}

function err(e: unknown): string { return 'error: ' + (e instanceof Error ? e.message : String(e)); }
