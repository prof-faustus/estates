import { Wallet, type Network } from '@estates/wallet';

/**
 * Your wallet — shown at ALL times (lobby and in-game). It's a wallet as much as
 * a game: you hold the key, so you fund or DEFUND it yourself, any time. Nobody
 * ever asks you for money.
 */
export function WalletPanel({ wif, network }: { wif: string; network: Network }) {
  let address = '(invalid key)';
  try { address = Wallet.fromWif(wif, network).address; } catch { /* bad WIF */ }
  return (
    <section className="wallet">
      <h3>Your wallet · {network}</h3>
      <div className="wrow">address <code>{address}</code></div>
      <div className="wrow">key (WIF) <code className="wif">{wif}</code></div>
      <p className="hint">You hold the key — fund or <b>defund this wallet yourself, any time</b>. Nobody asks you for money.</p>
    </section>
  );
}
