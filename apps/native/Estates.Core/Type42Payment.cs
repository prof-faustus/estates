// Estates.Core/Type42Payment.cs — the number-42 payment scheme. A payee NEVER publishes a payment
// address — only its MASTER public key. For each payment the payer and payee share an ECDH secret plus
// an agreed invoice number, and BOTH derive the SAME fresh sub-key: the payer derives the PUBLIC key to
// pay to; the payee derives the matching PRIVATE key to spend it. Every payment is a new address and
// every signing key is one-time. A used address is never offered to receive again.
namespace Estates.Core;

public static class Type42Payment
{
    /// <summary>Payer side: the fresh PUBLIC key (the address to pay) for the payee, from the payee's
    /// master pubkey + the payer's own private key + the agreed invoice.</summary>
    public static byte[] PayToPub(byte[] payeeMasterPub, byte[] payerPriv, string invoice)
        => Type42.DerivePublic(payeeMasterPub, payerPriv, invoice);

    /// <summary>Payee side: the matching PRIVATE key to SPEND that payment, from the payee's master
    /// private key + the payer's pubkey + the same invoice. PublicKey(this) == PayToPub(...).</summary>
    public static byte[] SpendPriv(byte[] payeeMasterPriv, byte[] payerPub, string invoice)
        => Type42.DerivePrivate(payeeMasterPriv, payerPub, invoice);

    /// <summary>The fresh receive ADDRESS (base58 P2PKH) the payer pays to — derived per invoice,
    /// never published, never reused.</summary>
    public static string PayToAddress(byte[] payeeMasterPub, byte[] payerPriv, string invoice, BsvNet net)
        => Address.P2pkh(Recovery.Hash160(PayToPub(payeeMasterPub, payerPriv, invoice)), net);
}
