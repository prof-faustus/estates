import { useMemo, useState } from 'react';
import { Wallet, type Network } from '@estates/wallet';

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
  const onChain = network !== 'regtest';

  async function refreshBalance() {
    if (!wallet) return;
    setStatus('checking balance…');
    try { setBalance(await wallet.getBalance()); setStatus(''); } catch (e) { setStatus(err(e)); }
  }
  async function doSend() {
    if (!wallet) return;
    const sats = Number(amount);
    if (!to.trim() || !Number.isFinite(sats) || sats <= 0) { setStatus('enter a destination address and a positive amount'); return; }
    if (network === 'mainnet' && !confirmReal) { setStatus('tick “spend real value” to send on mainnet'); return; }
    setStatus('signing + broadcasting…');
    try {
      const r = await wallet.send(to.trim(), sats, network === 'mainnet' ? confirmReal : true);
      setStatus(`sent ✓ txid ${r.txid}`);
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
          {!onChain && <p className="hint">send/spend is over WhatsOnChain — switch to testnet or mainnet.</p>}
          <input placeholder="destination address" value={to} onChange={(e) => setTo(e.target.value)} />
          <input placeholder="amount (sat)" value={amount} onChange={(e) => setAmount(e.target.value)} />
          {network === 'mainnet' && <label><input type="checkbox" checked={confirmReal} onChange={(e) => setConfirmReal(e.target.checked)} /> spend real value</label>}
          <button className="primary" disabled={!onChain} onClick={doSend}>Send</button>
          {status && <p className="hint">{status}</p>}
        </div>
      )}

      {wallet && tab === 'balance' && (
        <div className="wtab">
          <button disabled={!onChain} onClick={refreshBalance}>Refresh balance</button>
          {!onChain && <p className="hint">balance is via WhatsOnChain — testnet/mainnet only.</p>}
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
