// Command ranked-participants-example compares standard and hierarchical
// (ranked) DKLs23 keys with three parties and threshold 2.
//
// Standard mode: all ranks are 0 and any two parties can sign (Lagrange
// interpolation).
//
// Hierarchical mode: ranks [0 1 1]. Party 0 holds an evaluation of the secret
// polynomial, parties 1 and 2 hold first-derivative evaluations. A signing set
// must be able to reconstruct the secret (Birkhoff interpolation), so every
// valid set includes party 0; parties 1 and 2 cannot sign without it. This
// models, for example, a user device (rank 0) plus two co-signing servers.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
)

func main() {
	mpcdemo.Run("DKLs23 ranked participants: standard vs hierarchical 2-of-3", run)
}

func run() error {
	mpcdemo.Step(1, "Standard mode, ranks [0 0 0]")
	if err := demo(nil, [][]int{{0, 1}, {1, 2}, {0, 2}}); err != nil {
		return fmt.Errorf("standard mode: %w", err)
	}

	mpcdemo.Step(2, "Hierarchical mode, ranks [0 1 1]")
	if err := demo([]uint8{0, 1, 1}, [][]int{{0, 1}, {0, 2}}); err != nil {
		return fmt.Errorf("hierarchical mode: %w", err)
	}
	mpcdemo.Field("parties {1,2}", "not a valid signing set (no rank-0 share)")

	mpcdemo.Done("every valid signing set produced a verified signature")
	return nil
}

// demo creates a 2-of-3 key with the given ranks and signs with each set.
func demo(ranks []uint8, signingSets [][]int) error {
	keyshares, err := mpcdemo.DKLS23Keygen(3, 2, ranks)
	if err != nil {
		return err
	}
	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	mpcdemo.Field("public key", hex.EncodeToString(pub))

	var ks struct {
		RankList []uint8 `json:"rank_list"`
	}
	if err := json.Unmarshal([]byte(keyshares[0]), &ks); err != nil {
		return err
	}
	mpcdemo.Field("keyshare rank_list", ks.RankList)

	hash := sha256.Sum256([]byte("ranked participants example"))
	for _, set := range signingSets {
		subset := make([]string, len(set))
		for i, p := range set {
			subset[i] = keyshares[p]
		}
		sig, err := mpcdemo.DKLS23Sign(subset, hash)
		if err != nil {
			return fmt.Errorf("parties %v: %w", set, err)
		}
		if err := mpcdemo.VerifyECDSA(pub, hash, sig); err != nil {
			return fmt.Errorf("parties %v: %w", set, err)
		}
		mpcdemo.Field(fmt.Sprintf("parties {%d,%d}", set[0], set[1]), "signature valid")
	}
	return nil
}
