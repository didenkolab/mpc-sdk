// Command basic-dkls23 walks through a complete DKLs23 session round by round:
// a 2-of-2 distributed key generation followed by a threshold ECDSA signature
// that is verified locally against the group public key.
//
// Both parties run in this process so every message hand-off is visible. The
// chain examples use the same flow through the examples/internal/mpcdemo
// helpers.
//
//	go run ./examples/basic-dkls23            # standard mode (Lagrange)
//	go run ./examples/basic-dkls23 -ranked    # hierarchical mode, ranks [0 1] (Birkhoff)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
)

var ranked = flag.Bool("ranked", false, "use hierarchical mode with participant ranks [0 1]")

func main() {
	flag.Parse()
	mpcdemo.Run("DKLs23 threshold ECDSA: 2-of-2 key generation and signing", run)
}

func run() error {
	mpcdemo.Step(1, "Distributed key generation (2-of-2)")
	keyshares, err := keygen()
	if err != nil {
		return fmt.Errorf("DKG: %w", err)
	}
	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	pub1, err := mpcdemo.DKLS23PublicKey(keyshares[1])
	if err != nil {
		return err
	}
	if hex.EncodeToString(pub) != hex.EncodeToString(pub1) {
		return errors.New("parties disagree on the group public key")
	}
	mpcdemo.Field("group public key", hex.EncodeToString(pub))
	mpcdemo.Field("keyshare sizes", fmt.Sprintf("%d / %d bytes", len(keyshares[0]), len(keyshares[1])))

	mpcdemo.Step(2, "Distributed signing")
	message := "DKLs23 threshold signature example"
	hash := sha256.Sum256([]byte(message))
	mpcdemo.Field("message", fmt.Sprintf("%q", message))
	mpcdemo.Field("sha256", hex.EncodeToString(hash[:]))
	sig, err := sign(keyshares, hash)
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}
	mpcdemo.Field("signature (r||s)", hex.EncodeToString(sig))

	mpcdemo.Step(3, "Local verification")
	if err := mpcdemo.VerifyECDSA(pub, hash, sig); err != nil {
		return err
	}
	mpcdemo.Field("secp256k1 ECDSA", "valid")

	mpcdemo.Done("signature created without either party holding the full private key")
	return nil
}

// keygen runs the four DKG rounds between two in-process parties.
func keygen() ([2]string, error) {
	var out [2]string
	var p [2]*dkls23.DKGState
	defer func() {
		for _, s := range p {
			if s != nil {
				s.Free()
			}
		}
	}()

	for i := range p {
		var err error
		if *ranked {
			p[i], err = dkls23.NewDKGStateWithRanks(uint8(i), []uint8{0, 1}, 2)
		} else {
			p[i], err = dkls23.NewDKGState(uint8(i), 2, 2)
		}
		if err != nil {
			return out, err
		}
	}
	if *ranked {
		mpcdemo.Field("mode", "hierarchical, ranks [0 1] (Birkhoff coefficients)")
	} else {
		mpcdemo.Field("mode", "standard, all ranks 0 (Lagrange coefficients)")
	}

	// Round 1: each party broadcasts a commitment.
	a1, err := p[0].GenerateMsg1()
	if err != nil {
		return out, err
	}
	b1, err := p[1].GenerateMsg1()
	if err != nil {
		return out, err
	}
	mpcdemo.Field("round 1 (broadcast)", sizes(a1, b1))

	// Round 2: each party processes the peer's commitment and emits a
	// point-to-point message addressed to that peer.
	a2, err := p[0].HandleMsg1(one(b1))
	if err != nil {
		return out, err
	}
	b2, err := p[1].HandleMsg1(one(a1))
	if err != nil {
		return out, err
	}
	mpcdemo.Field("round 2 (p2p)", sizes(a2, b2))

	// Round 3: process the point-to-point messages.
	a3, err := p[0].HandleMsg2(list(b2))
	if err != nil {
		return out, err
	}
	b3, err := p[1].HandleMsg2(list(a2))
	if err != nil {
		return out, err
	}
	mpcdemo.Field("round 3 (p2p)", sizes(a3, b3))

	// Round 4: reveal the commitments from round 1 and verify the peer's
	// proofs against them, producing the last broadcast message.
	ca, err := p[0].CalculateCommitment2()
	if err != nil {
		return out, err
	}
	cb, err := p[1].CalculateCommitment2()
	if err != nil {
		return out, err
	}
	commitments := []string{ca, cb}
	a4, err := p[0].HandleMsg3(list(b3), commitments)
	if err != nil {
		return out, err
	}
	b4, err := p[1].HandleMsg3(list(a3), commitments)
	if err != nil {
		return out, err
	}
	mpcdemo.Field("round 4 (broadcast)", sizes(a4, b4))

	// Finalize: each party derives its own keyshare.
	if out[0], err = p[0].HandleMsg4(one(b4)); err != nil {
		return out, err
	}
	if out[1], err = p[1].HandleMsg4(one(a4)); err != nil {
		return out, err
	}
	return out, nil
}

// sign runs the three DSG rounds, then creates and combines the partial
// signatures.
func sign(keyshares [2]string, hash [32]byte) ([]byte, error) {
	var s [2]*dkls23.DSGState
	defer func() {
		for _, st := range s {
			if st != nil {
				st.Free()
			}
		}
	}()
	for i := range s {
		var err error
		if s[i], err = dkls23.NewDSGState(keyshares[i], "m"); err != nil {
			return nil, err
		}
	}

	a1, err := s[0].GenerateMsg1()
	if err != nil {
		return nil, err
	}
	b1, err := s[1].GenerateMsg1()
	if err != nil {
		return nil, err
	}
	a2, err := s[0].HandleMsg1(one(b1))
	if err != nil {
		return nil, err
	}
	b2, err := s[1].HandleMsg1(one(a1))
	if err != nil {
		return nil, err
	}
	a3, err := s[0].HandleMsg2(list(b2))
	if err != nil {
		return nil, err
	}
	b3, err := s[1].HandleMsg2(list(a2))
	if err != nil {
		return nil, err
	}
	mpcdemo.Field("rounds 1-3", "commitments, MtA, consistency proofs exchanged")

	// Each party now holds a presignature, which is independent of the
	// message and must be used for exactly one signature.
	presigA, err := s[0].HandleMsg3(list(b3))
	if err != nil {
		return nil, err
	}
	presigB, err := s[1].HandleMsg3(list(a3))
	if err != nil {
		return nil, err
	}

	partA, err := partial(presigA, hash)
	if err != nil {
		return nil, err
	}
	partB, err := partial(presigB, hash)
	if err != nil {
		return nil, err
	}

	// Party 0 combines its own partial signature with party 1's msg4.
	sigHex, err := dkls23.CombineSignatures(string(partA.Partial), []interface{}{partB.Msg4})
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(sigHex)
}

type partialSig struct {
	Partial json.RawMessage `json:"partial"`
	Msg4    json.RawMessage `json:"msg4"`
}

func partial(presig string, hash [32]byte) (partialSig, error) {
	var p partialSig
	out, err := dkls23.CreatePartialSignature(presig, hash)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(out), &p)
	return p, err
}

// one wraps a single JSON message as the list the bindings expect.
func one(msg string) []interface{} {
	return []interface{}{json.RawMessage(msg)}
}

// list passes a JSON array of messages through unchanged. In a 2-party
// session every point-to-point message is addressed to the single peer.
func list(msgs string) []interface{} {
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(msgs), &items); err != nil {
		return nil
	}
	out := make([]interface{}, len(items))
	for i, m := range items {
		out[i] = m
	}
	return out
}

func sizes(a, b string) string {
	return fmt.Sprintf("%d / %d bytes", len(a), len(b))
}
