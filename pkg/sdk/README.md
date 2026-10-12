# sdk

A thin, round-oriented facade over the DKLs23 (ECDSA secp256k1) and FROST
(Ed25519) bindings. Every protocol message is a `json.RawMessage` (`sdk.RawMsg`),
so messages can be moved over any transport without being decoded.

## Requirements

- Go 1.24+ with cgo enabled.
- The Rust FFI libraries: `make build-ffi`.

## DKLs23 (2-of-2)

Party IDs are 0-based. Point-to-point outputs are JSON arrays: split them with
`DecodeList` and deliver each element to the party named by its `to_id`
(`FilterByToID`).

```go
dkg0, _ := sdk.NewDKLS23DKG(0, 2, 2)
dkg1, _ := sdk.NewDKLS23DKG(1, 2, 2)
defer dkg0.Close()
defer dkg1.Close()

m10, _ := dkg0.Round1()
m11, _ := dkg1.Round1()
m20, _ := dkg0.Round2([]sdk.RawMsg{m11})
m21, _ := dkg1.Round2([]sdk.RawMsg{m10})
l20, _ := sdk.DecodeList(m20)
l21, _ := sdk.DecodeList(m21)
m30, _ := dkg0.Round3(sdk.FilterByToID(0, l21))
m31, _ := dkg1.Round3(sdk.FilterByToID(1, l20))
c0, _ := dkg0.Commitment2()
c1, _ := dkg1.Commitment2()
l30, _ := sdk.DecodeList(m30)
l31, _ := sdk.DecodeList(m31)
m40, _ := dkg0.Round4(sdk.FilterByToID(0, l31), []string{c0, c1})
m41, _ := dkg1.Round4(sdk.FilterByToID(1, l30), []string{c0, c1})
k0, _ := dkg0.Finalize([]sdk.RawMsg{m41})
k1, _ := dkg1.Finalize([]sdk.RawMsg{m40})

s0, _ := sdk.NewDKLS23Signer(k0, "m")
s1, _ := sdk.NewDKLS23Signer(k1, "m")
defer s0.Close()
defer s1.Close()
a0, _ := s0.Round1()
a1, _ := s1.Round1()
b0, _ := s0.Round2([]sdk.RawMsg{a1})
b1, _ := s1.Round2([]sdk.RawMsg{a0})
lb0, _ := sdk.DecodeList(b0)
lb1, _ := sdk.DecodeList(b1)
d0, _ := s0.Round3(sdk.FilterByToID(0, lb1))
d1, _ := s1.Round3(sdk.FilterByToID(1, lb0))
ld0, _ := sdk.DecodeList(d0)
ld1, _ := sdk.DecodeList(d1)
pre0, _ := s0.Presign(sdk.FilterByToID(0, ld1))
pre1, _ := s1.Presign(sdk.FilterByToID(1, ld0))

h := sha256.Sum256([]byte("hello"))
p0, _ := sdk.CreateDKLS23Partial(pre0, h)
p1, _ := sdk.CreateDKLS23Partial(pre1, h)
sigHex, _ := sdk.CombineDKLS23(p0.Partial, []sdk.RawMsg{p1.Msg4}) // r || s
```

DKLs23 signs with exactly `threshold` parties. Presignatures are single-use.

## FROST (2-of-2)

Party IDs are 1-based; round-2 packet `to_id` values are 0-based.

```go
f1, _ := sdk.NewFrostDKG(1, 2, 2)
f2, _ := sdk.NewFrostDKG(2, 2, 2)
defer f1.Close()
defer f2.Close()

r1, _ := f1.Round1()
r2, _ := f2.Round1()
o1, _ := f1.Round2([]sdk.RawMsg{r2})
o2, _ := f2.Round2([]sdk.RawMsg{r1})
lo1, _ := sdk.DecodeList(o1)
lo2, _ := sdk.DecodeList(o2)
ks1, _ := f1.Round3(sdk.FilterByToID(0, lo2))
ks2, _ := f2.Round3(sdk.FilterByToID(1, lo1))

h := sha256.Sum256([]byte("hello"))
g1, _ := sdk.NewFrostSigner(ks1, h)
g2, _ := sdk.NewFrostSigner(ks2, h)
defer g1.Close()
defer g2.Close()
c1, _ := g1.Round1()
c2, _ := g2.Round1()
share1, _ := g1.Round2([]sdk.RawMsg{c2})
share2, _ := g2.Round2([]sdk.RawMsg{c1})
sigHex, _ := sdk.CombineFrost(share1, []sdk.RawMsg{share2}) // Ed25519 signature
```

## Tests

```bash
go test ./pkg/sdk
```

The tests run complete key generation and signing for several t-of-n
configurations and verify every signature with independent implementations.
