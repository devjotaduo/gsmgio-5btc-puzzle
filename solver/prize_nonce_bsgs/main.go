// Bounded discrete logs of public ECDSA nonce points and pairwise sums/differences.
// This reads public puzzle signatures only; it cannot create or broadcast a transaction.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var order, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

type point = secp.JacobianPoint
type signature struct {
	ID        string `json:"id"`
	R         string `json:"r"`
	S         string `json:"s"`
	Z         string `json:"z"`
	PublicKey string `json:"publicKey"`
}
type target struct {
	Name       string
	P          point
	I, J, Sign int
}

func hx(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex integer")
	}
	return v
}
func mod(v *big.Int) *big.Int { return new(big.Int).Mod(v, order) }
func scalar(v *big.Int) *secp.ModNScalar {
	var s secp.ModNScalar
	s.SetByteSlice(mod(v).FillBytes(make([]byte, 32)))
	return &s
}
func base(v *big.Int) point { var p point; secp.ScalarBaseMultNonConst(scalar(v), &p); return p }
func multiply(p point, v *big.Int) point {
	var q point
	secp.ScalarMultNonConst(scalar(v), &p, &q)
	return q
}
func add(p, q point) point { var r point; secp.AddNonConst(&p, &q, &r); return r }
func negate(p point) point { p.Y.Normalize().Negate(1).Normalize(); return p }
func pub(s string) point {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	p, e := secp.ParsePubKey(b)
	if e != nil {
		panic(e)
	}
	var q point
	p.AsJacobian(&q)
	return q
}
func key(p point) string {
	if p.Z.IsZero() {
		return "infinity"
	}
	p.ToAffine()
	return hex.EncodeToString(secp.NewPublicKey(&p.X, &p.Y).SerializeCompressed())
}
func xInt(p point) *big.Int {
	if p.Z.IsZero() {
		panic("unexpected infinity")
	}
	p.ToAffine()
	var x [32]byte
	p.X.PutBytes(&x)
	return new(big.Int).SetBytes(x[:])
}
func nonce(s signature) point {
	r, ss, z := hx(s.R), hx(s.S), hx(s.Z)
	if r.Sign() <= 0 || r.Cmp(order) >= 0 || ss.Sign() <= 0 || ss.Cmp(order) >= 0 {
		panic("invalid scalar")
	}
	p := multiply(add(base(z), multiply(pub(s.PublicKey), r)), new(big.Int).ModInverse(ss, order))
	if mod(xInt(p)).Cmp(r) != 0 {
		panic("invalid ECDSA equation")
	}
	return p
}

// Batch affine X coordinates, with a separate infinity marker. Full X is retained.
// Equal X allows either sign of the baby step; every match is checked as a full point.
func batchX(points []point) [][33]byte {
	n := len(points)
	out := make([][33]byte, n)
	if n == 0 {
		return out
	}
	zz := make([]secp.FieldVal, n)
	prefix := make([]secp.FieldVal, n)
	for i := range points {
		if points[i].Z.IsZero() {
			zz[i].SetInt(1)
		} else {
			zz[i].SquareVal(&points[i].Z)
		}
		if i == 0 {
			prefix[i].Set(&zz[i])
		} else {
			prefix[i].Mul2(&prefix[i-1], &zz[i])
		}
	}
	var inv secp.FieldVal
	inv.Set(&prefix[n-1]).Normalize().Inverse()
	for i := n - 1; i >= 0; i-- {
		var izz, x secp.FieldVal
		if i > 0 {
			izz.Mul2(&inv, &prefix[i-1])
			inv.Mul(&zz[i])
		} else {
			izz.Set(&inv)
		}
		if points[i].Z.IsZero() {
			continue
		}
		x.Mul2(&points[i].X, &izz).Normalize()
		var b [32]byte
		x.PutBytes(&b)
		out[i][0] = 1
		copy(out[i][1:], b[:])
	}
	return out
}

type table struct {
	M      int64
	Bound  int64
	Babies map[[33]byte]int64
	Giant  point
	Offset point
}

func makeTable(bits uint) table {
	m := int64(1) << (bits / 2)
	t := table{M: m, Bound: m * m, Babies: make(map[[33]byte]int64, m)}
	g := base(big.NewInt(1))
	acc := point{}
	batch := make([]point, 0, 2048)
	start := int64(0)
	flush := func() {
		for i, x := range batchX(batch) {
			if _, exists := t.Babies[x]; exists {
				panic("unexpected baby X collision")
			}
			t.Babies[x] = start + int64(i)
		}
		start += int64(len(batch))
		batch = batch[:0]
	}
	for j := int64(0); j < m; j++ {
		batch = append(batch, acc)
		acc = add(acc, g)
		if len(batch) == cap(batch) {
			flush()
		}
	}
	if len(batch) > 0 {
		flush()
	}
	t.Giant = negate(base(big.NewInt(m)))
	t.Offset = base(big.NewInt((m - 1) * m))
	return t
}
func (t table) solve(q point) (int64, bool) {
	acc := add(q, t.Offset)
	batch := make([]point, 0, 2048)
	start := -t.M + 1
	wanted := key(q)
	flush := func() (int64, bool) {
		for j, x := range batchX(batch) {
			if baby, ok := t.Babies[x]; ok {
				giant := (start + int64(j)) * t.M
				for _, v := range []int64{giant + baby, giant - baby} {
					if v > -t.Bound && v < t.Bound && key(base(big.NewInt(v))) == wanted {
						return v, true
					}
				}
			}
		}
		start += int64(len(batch))
		batch = batch[:0]
		return 0, false
	}
	for i := -t.M + 1; i < t.M; i++ {
		batch = append(batch, acc)
		acc = add(acc, t.Giant)
		if len(batch) == cap(batch) {
			if v, ok := flush(); ok {
				return v, true
			}
		}
	}
	if len(batch) > 0 {
		return flush()
	}
	return 0, false
}
func recoverSingle(s signature, k int64) *big.Int {
	v := new(big.Int).Sub(new(big.Int).Mul(hx(s.S), big.NewInt(k)), hx(s.Z))
	return mod(v.Mul(v, new(big.Int).ModInverse(hx(s.R), order)))
}
func recoverPair(a, b signature, sign int, delta int64) *big.Int {
	// k_a = sign*k_b + delta (mod n).
	sa, sb, ra, rb, za, zb := hx(a.S), hx(b.S), hx(a.R), hx(b.R), hx(a.Z), hx(b.Z)
	numerator := new(big.Int).Mul(sb, za)
	numerator.Sub(numerator, new(big.Int).Mul(big.NewInt(int64(sign)), new(big.Int).Mul(sa, zb)))
	numerator.Sub(numerator, new(big.Int).Mul(big.NewInt(delta), new(big.Int).Mul(sa, sb)))
	denominator := new(big.Int).Sub(new(big.Int).Mul(big.NewInt(int64(sign)), new(big.Int).Mul(sa, rb)), new(big.Int).Mul(sb, ra))
	inverse := new(big.Int).ModInverse(mod(denominator), order)
	if inverse == nil {
		return nil
	}
	return mod(numerator.Mul(numerator, inverse))
}
func planted(d, k, z *big.Int) signature {
	r := mod(xInt(base(k)))
	s := mod(new(big.Int).Mul(new(big.Int).Add(z, new(big.Int).Mul(r, d)), new(big.Int).ModInverse(k, order)))
	p := base(d)
	p.ToAffine()
	return signature{R: fmt.Sprintf("%064x", r), S: fmt.Sprintf("%064x", s), Z: fmt.Sprintf("%064x", z), PublicKey: hex.EncodeToString(secp.NewPublicKey(&p.X, &p.Y).SerializeUncompressed())}
}
func controls() map[string]any {
	t := makeTable(16)
	values := []int64{0, 1, -1, 255, -255, 256, -256, 257, -257, 65535, -65535}
	for _, v := range values {
		got, ok := t.solve(base(big.NewInt(v)))
		if !ok || got != v {
			panic(fmt.Sprintf("control failed: %d -> %d/%v", v, got, ok))
		}
	}
	for _, v := range []int64{65536, -65536, 65537, -65537} {
		if _, ok := t.solve(base(big.NewInt(v))); ok {
			panic("out-of-range control accepted")
		}
	}
	d := big.NewInt(123456789)
	a := planted(d, big.NewInt(12345), big.NewInt(9876))
	if recoverSingle(a, 12345).Cmp(d) != 0 || key(nonce(a)) != key(base(big.NewInt(12345))) {
		panic("single-key recovery control")
	}
	large := new(big.Int).Div(new(big.Int).Set(order), big.NewInt(3))
	paired := 0
	for _, s1 := range []int64{1, -1} {
		for _, s2 := range []int64{1, -1} {
			ka := mod(new(big.Int).Mul(big.NewInt(s1), new(big.Int).Add(large, big.NewInt(31415))))
			kb := mod(new(big.Int).Mul(big.NewInt(s2), large))
			a, b := planted(d, ka, big.NewInt(901)), planted(d, kb, big.NewInt(902))
			sign := int(s1 * s2)
			q := add(nonce(a), multiply(nonce(b), big.NewInt(int64(-sign))))
			delta, ok := t.solve(q)
			if !ok || delta != s1*31415 {
				panic("pairwise signed nonce control")
			}
			got := recoverPair(a, b, sign, delta)
			if got == nil || got.Cmp(d) != 0 {
				panic("pair-key recovery control")
			}
			paired++
		}
	}
	return map[string]any{"signedBoundaryControls": len(values), "outsideBoundRejected": 4, "smallNonceKeyRecovered": true, "largeNoncePairSignCases": paired, "allPassed": true}
}
func main() {
	input := flag.String("in", "", "validated signature JSON")
	output := flag.String("out", "", "fresh result JSON")
	bits := flag.Uint("bits", 32, "even bound exponent, 8 through 40")
	flag.Parse()
	if *input == "" || *output == "" || *bits < 8 || *bits > 40 || *bits%2 != 0 {
		panic("require -in, -out, and even -bits in [8,40]")
	}
	if _, err := os.Stat(*output); !os.IsNotExist(err) {
		panic("output must not exist")
	}
	started := time.Now()
	control := controls()
	raw, e := os.ReadFile(*input)
	if e != nil {
		panic(e)
	}
	var sigs []signature
	if e = json.Unmarshal(raw, &sigs); e != nil {
		panic(e)
	}
	if len(sigs) != 6 {
		panic("expected six puzzle signatures")
	}
	targetPub := key(pub(sigs[0].PublicKey))
	points := make([]point, len(sigs))
	targets := []target{}
	for i, s := range sigs {
		if key(pub(s.PublicKey)) != targetPub {
			panic("mixed public keys")
		}
		points[i] = nonce(s)
		targets = append(targets, target{fmt.Sprintf("nonce[%d]", i), points[i], i, -1, 0})
	}
	for i := range sigs {
		for j := 0; j < i; j++ {
			for _, sign := range []int{-1, 1} {
				p := add(points[i], multiply(points[j], big.NewInt(int64(-sign))))
				targets = append(targets, target{fmt.Sprintf("nonce[%d] - (%d)*nonce[%d]", i, sign, j), p, i, j, sign})
			}
		}
	}
	t := makeTable(*bits)
	results := []map[string]any{}
	hits := []map[string]any{}
	recovered := []map[string]any{}
	for i, q := range targets {
		k, ok := t.solve(q.P)
		r := map[string]any{"name": q.Name, "point": key(q.P), "found": ok}
		if ok {
			r["signedScalar"] = k
			hits = append(hits, r)
			var d *big.Int
			if q.J < 0 {
				d = recoverSingle(sigs[q.I], k)
			} else {
				d = recoverPair(sigs[q.I], sigs[q.J], q.Sign, k)
			}
			if d != nil && key(base(d)) == targetPub {
				recovered = append(recovered, map[string]any{"source": q.Name, "privateKeyHex": fmt.Sprintf("%064x", d), "publicKeyMatched": true})
			} else {
				r["degenerateOrNoKey"] = true
			}
		}
		results = append(results, r)
		fmt.Printf("%d/%d %s found=%v elapsed=%s\n", i+1, len(targets), q.Name, ok, time.Since(started).Round(time.Millisecond))
	}
	digest := sha256.Sum256(raw)
	report := map[string]any{"inputSHA256": hex.EncodeToString(digest[:]), "bits": *bits, "signedInterval": fmt.Sprintf("-%d < k < %d", t.Bound, t.Bound), "babySteps": t.M, "giantStepsPerTarget": 2*t.M - 1, "controls": control, "signatures": len(sigs), "targets": results, "hits": hits, "recoveredKeys": recovered, "elapsedMs": time.Since(started).Milliseconds(), "scope": "Signed nonce scalars, pairwise differences and sums; does not exclude arbitrary nonces, larger offsets or general affine relations."}
	body, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		panic(e)
	}
	f, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	if _, e = f.Write(append(body, '\n')); e != nil {
		panic(e)
	}
}
