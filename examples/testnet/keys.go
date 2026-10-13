package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
)

const (
	schemeDKLS23 = "dkls23"
	schemeFROST  = "frost"

	parties   = 3
	threshold = 2
)

const keyfileWarning = "TEST ONLY. Unencrypted threshold keyshares of ALL parties in one file " +
	"(which defeats MPC). Use only on test networks. Never commit, share or fund with real money."

type keyFile struct {
	Warning   string   `json:"warning"`
	Scheme    string   `json:"scheme"`
	Parties   int      `json:"parties"`
	Threshold int      `json:"threshold"`
	Created   string   `json:"created"`
	Keyshares []string `json:"keyshares"`
}

// loadOrCreateKeyshares returns the keyshares stored at path, or runs an
// in-process 2-of-3 DKG and stores the result there (mode 0600) if the file
// does not exist yet.
func loadOrCreateKeyshares(path, scheme string) ([]string, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseKeyFile(path, data, scheme)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("read keyshares: %w", err)
	}

	mpcdemo.Step(1, fmt.Sprintf("Distributed key generation (%s %d-of-%d, new key)", scheme, threshold, parties))
	var keyshares []string
	if scheme == schemeFROST {
		keyshares, err = mpcdemo.FROSTKeygen(parties, threshold)
	} else {
		keyshares, err = mpcdemo.DKLS23Keygen(parties, threshold, nil)
	}
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(keyFile{
		Warning: keyfileWarning, Scheme: scheme, Parties: parties, Threshold: threshold,
		Created: time.Now().UTC().Format(time.RFC3339), Keyshares: keyshares,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create keyshare directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create keyshare file: %w", err)
	}
	if _, err := f.Write(append(out, '\n')); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write keyshare file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("write keyshare file: %w", err)
	}
	mpcdemo.Field("saved to", path+" (mode 0600, TEST ONLY, do not commit)")
	return keyshares, nil
}

func parseKeyFile(path string, data []byte, scheme string) ([]string, error) {
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if kf.Scheme != scheme {
		return nil, fmt.Errorf("%s holds %q keyshares, this chain needs %q (use another -keyshares path)", path, kf.Scheme, scheme)
	}
	if kf.Threshold != threshold || len(kf.Keyshares) != parties {
		return nil, fmt.Errorf("%s: want %d-of-%d keyshares, got %d-of-%d", path, threshold, parties, kf.Threshold, len(kf.Keyshares))
	}
	mpcdemo.Step(1, fmt.Sprintf("Keyshares (%s %d-of-%d, loaded)", scheme, threshold, parties))
	mpcdemo.Field("file", path)
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		fmt.Printf("   WARNING: %s is readable by other users (mode %v); run: chmod 600 %s\n", path, st.Mode().Perm(), path)
	}
	return kf.Keyshares, nil
}

// signers returns the keyshares of parties 1 and 3: any two of the three
// parties can sign, and skipping party 2 shows that.
func signers(keyshares []string) []string {
	return []string{keyshares[0], keyshares[2]}
}
