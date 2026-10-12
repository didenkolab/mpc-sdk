// Package dkls23 provides Go bindings to the DKLs23 threshold ECDSA protocol
// over secp256k1, implemented in Rust and linked through cgo.
//
// Party IDs are 0-based. A t-of-n key is generated in five steps, each party
// running the same sequence on its own DKGState:
//
//  1. GenerateMsg1, broadcast the result.
//  2. HandleMsg1 with the other parties' msg1; send each element of the
//     returned array to the party named by its "to_id".
//  3. HandleMsg2 with the msg2 addressed to this party; route the returned
//     msg3 array the same way.
//  4. CalculateCommitment2 and share it, then HandleMsg3 with the msg3
//     addressed to this party and all commitments ordered by party ID;
//     broadcast the returned msg4.
//  5. HandleMsg4 with the other parties' msg4 to obtain the keyshare.
//
// Signing uses a DSGState created from a keyshare and a BIP32 path, three
// message rounds that produce a presignature, then CreatePartialSignature and
// CombineSignatures. The resulting signature is a standard 64-byte r || s
// ECDSA signature that verifies against the (derived) group public key.
package dkls23
