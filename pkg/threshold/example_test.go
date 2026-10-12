package threshold_test

import (
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/didenkolab/mpc-sdk/pkg/threshold"
)

// A 2-of-3 ECDSA wallet simulated in one process: generate keys, sign with
// two of the three parties and verify.
func Example() {
	wm := threshold.NewWalletManagerWithMode(threshold.ECDSASecp256k1, threshold.ExecutionModeInMemoryDemo)

	wallet, err := wm.CreateCompleteWallet(3, 2, 0)
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("hello, threshold signatures")
	sig, err := wallet.SignWithWallet(message, []int{0, 2}, wm)
	if err != nil {
		log.Fatal(err)
	}

	valid, err := wm.VerifySignature(message, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("address is SegWit:", strings.HasPrefix(wallet.MainAddress.Address, "bc1q"))
	fmt.Println("signature valid:", valid)
	// Output:
	// address is SegWit: true
	// signature valid: true
}

// Signing a transaction digest: the 32-byte hash is signed as-is.
func ExampleWalletManager_SignTransaction() {
	wm := threshold.NewWalletManagerWithMode(threshold.Ed25519FROST, threshold.ExecutionModeInMemoryDemo)
	wallet, err := wm.CreateCompleteWallet(2, 2, 0)
	if err != nil {
		log.Fatal(err)
	}

	txHash := sha256.Sum256([]byte("serialized transaction"))
	sig, err := wm.SignTransaction(txHash[:], wallet.KeyShares, []int{0, 1}, wallet.MainAddress)
	if err != nil {
		log.Fatal(err)
	}
	valid, err := wm.VerifyTransactionSignature(txHash[:], sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(sig.Data), valid)
	// Output: 64 true
}

// Each party runs its own DKGSession; here the parties share an in-memory
// transport, in production each would use a network transport.
func ExampleDKGSession() {
	ids := []uint8{0, 1, 2}
	transport := threshold.NewInMemoryTransport()

	shares := make([]*threshold.KeyShare, len(ids))
	var wg sync.WaitGroup
	for _, id := range ids {
		session, err := threshold.NewDKGSession(id, ids, 2, threshold.ECDSASecp256k1)
		if err != nil {
			log.Fatal(err)
		}
		defer session.Free()
		session.SetSessionID("example-session")
		session.SetTransport(transport)

		wg.Add(1)
		go func() {
			defer wg.Done()
			ks, err := session.ExecuteDKG()
			if err != nil {
				log.Fatal(err)
			}
			shares[id] = ks
		}()
	}
	wg.Wait()

	fmt.Println(shares[0].PublicKey == shares[1].PublicKey && shares[1].PublicKey == shares[2].PublicKey)
	// Output: true
}
