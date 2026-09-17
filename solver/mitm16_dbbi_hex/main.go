// MITM sobre as 16! bijeções token→dígito hex do dbbi (64 tokens b/g) contra a pubkey do prêmio.
//
// Hipótese: os 64 tokens de `dbbi` (prefixos b/g) são os 64 dígitos hex de uma "Regular Bitcoin
// Private key" sob uma bijeção desconhecida π: 16 tokens → 16 dígitos. Como a chave é linear nos
// tokens, d = Σ_t π(t)·W_t (mod n), onde W_t = Σ 16^(63-j) sobre as posições j do token t.
// Logo pub = Σ_t π(t)·(W_t·G): meet-in-the-middle no grupo da curva com A = 7 tokens (tabela de
// 57.657.600 pontos) e B = 9 tokens (4.151.347.200 folhas, 1 adição jacobiana cada).
// Testa d e n−d (ambos os sinais) para cada ordem de leitura do config.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Config struct {
	Tokens  []string                     `json:"tokens"`
	Orders  map[string]map[string]string `json:"orders"`
	Pub     string                       `json:"pub"`
	Control struct {
		Pi  map[string]int `json:"pi"`
		Hex string         `json:"hex"`
		Pub string         `json:"pub"`
	} `json:"control"`
}

type entry struct {
	X uint64
	V uint32 // 7 nibbles empacotados (v0 nos bits mais altos)
}

const chunk = 8192

var curveN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func mustScalar(hx string) *secp256k1.ModNScalar {
	b, err := hex.DecodeString(hx)
	if err != nil || len(b) != 32 {
		panic("escalar inválido: " + hx)
	}
	var s secp256k1.ModNScalar
	if s.SetByteSlice(b) {
		panic("escalar >= n")
	}
	return &s
}

// tabelas k·P_t (k = 0..15) em coordenadas afins (Z = 1) e suas negações.
func buildTables(ws []*secp256k1.ModNScalar) (tab, neg [][]secp256k1.JacobianPoint) {
	tab = make([][]secp256k1.JacobianPoint, len(ws))
	neg = make([][]secp256k1.JacobianPoint, len(ws))
	for i, w := range ws {
		var p secp256k1.JacobianPoint
		secp256k1.ScalarBaseMultNonConst(w, &p)
		p.ToAffine()
		tab[i] = make([]secp256k1.JacobianPoint, 16)
		neg[i] = make([]secp256k1.JacobianPoint, 16)
		// k = 0 → ponto no infinito (X=Y=Z=0); AddNonConst trata Z=0 como infinito.
		var acc secp256k1.JacobianPoint
		for k := 1; k < 16; k++ {
			var r secp256k1.JacobianPoint
			secp256k1.AddNonConst(&acc, &p, &r)
			r.ToAffine()
			acc = r
			tab[i][k] = r
			neg[i][k] = r
			neg[i][k].Y.Negate(1).Normalize()
		}
	}
	return
}

// x afim (64 bits baixos) de um lote de pontos jacobianos, com inversão em lote (Montgomery).
func batchXLow64(pts []secp256k1.JacobianPoint, out []uint64) {
	m := len(pts)
	zz := make([]secp256k1.FieldVal, m)
	pre := make([]secp256k1.FieldVal, m)
	for i := 0; i < m; i++ {
		if pts[i].Z.IsZero() { // infinito: marca com Z=1 e X=0 (não vai casar com nada útil)
			zz[i].SetInt(1)
		} else {
			zz[i].SquareVal(&pts[i].Z)
		}
		if i == 0 {
			pre[i].Set(&zz[i])
		} else {
			pre[i].Mul2(&pre[i-1], &zz[i])
		}
	}
	var inv secp256k1.FieldVal
	inv.Set(&pre[m-1]).Normalize().Inverse()
	var b [32]byte
	for i := m - 1; i >= 0; i-- {
		var izz secp256k1.FieldVal
		if i > 0 {
			izz.Mul2(&inv, &pre[i-1])
			inv.Mul(&zz[i])
		} else {
			izz.Set(&inv)
		}
		var x secp256k1.FieldVal
		x.Mul2(&pts[i].X, &izz).Normalize()
		x.PutBytes(&b)
		out[i] = uint64(b[24])<<56 | uint64(b[25])<<48 | uint64(b[26])<<40 | uint64(b[27])<<32 |
			uint64(b[28])<<24 | uint64(b[29])<<16 | uint64(b[30])<<8 | uint64(b[31])
	}
}

// ---------- lado A: 7 tokens, todas as atribuições injetivas em {0..15} ----------
func buildA(tab [][]secp256k1.JacobianPoint, ta []int) []entry {
	nA := len(ta)
	total := 1
	for i := 0; i < nA; i++ {
		total *= 16 - i
	}
	entries := make([]entry, 0, total)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for v0 := 0; v0 < 16; v0++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(v0 int) {
			defer wg.Done()
			defer func() { <-sem }()
			local := make([]entry, 0, total/16+16)
			pts := make([]secp256k1.JacobianPoint, 0, chunk)
			packs := make([]uint32, 0, chunk)
			xs := make([]uint64, chunk)
			flush := func() {
				if len(pts) == 0 {
					return
				}
				batchXLow64(pts, xs[:len(pts)])
				for i := range pts {
					local = append(local, entry{xs[i], packs[i]})
				}
				pts = pts[:0]
				packs = packs[:0]
			}
			var used [16]bool
			used[v0] = true
			vals := [8]int{v0}
			S := make([]secp256k1.JacobianPoint, nA)
			S[0] = tab[ta[0]][v0]
			var rec func(level int)
			rec = func(level int) {
				for v := 0; v < 16; v++ {
					if used[v] {
						continue
					}
					secp256k1.AddNonConst(&S[level-1], &tab[ta[level]][v], &S[level])
					vals[level] = v
					if level == nA-1 {
						var pk uint32
						for i := 0; i < nA; i++ {
							pk = pk<<4 | uint32(vals[i])
						}
						pts = append(pts, S[level])
						packs = append(packs, pk)
						if len(pts) == chunk {
							flush()
						}
					} else {
						used[v] = true
						rec(level + 1)
						used[v] = false
					}
				}
			}
			rec(1)
			flush()
			mu.Lock()
			entries = append(entries, local...)
			mu.Unlock()
		}(v0)
	}
	wg.Wait()
	slices.SortFunc(entries, func(a, b entry) int {
		if a.X < b.X {
			return -1
		}
		if a.X > b.X {
			return 1
		}
		return 0
	})
	return entries
}

type hit struct {
	sign  int
	packA uint32
	packB uint64
}

// ---------- lado B: 9 tokens; para cada folha, R± = ±pub − S_B ----------
func runB(tab, neg [][]secp256k1.JacobianPoint, tb []int, pub *secp256k1.JacobianPoint, entries []entry, bitmap []uint64) []hit {
	nB := len(tb)
	var negPub secp256k1.JacobianPoint
	negPub = *pub
	negPub.Y.Negate(1).Normalize()
	targets := [2]*secp256k1.JacobianPoint{pub, &negPub}
	var hits []hit
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	var done int64
	var doneMu sync.Mutex
	t0 := time.Now()
	for v0 := 0; v0 < 16; v0++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(v0 int) {
			defer wg.Done()
			defer func() { <-sem }()
			pts := make([]secp256k1.JacobianPoint, 0, chunk)
			meta := make([]uint64, 0, chunk) // packB<<1 | sign
			xs := make([]uint64, chunk)
			var local []hit
			flush := func() {
				if len(pts) == 0 {
					return
				}
				batchXLow64(pts, xs[:len(pts)])
				for i := range pts {
					x := xs[i]
					if bitmap[(x&0xffffffff)>>6]&(1<<(x&63)) == 0 {
						continue
					}
					k, ok := slices.BinarySearchFunc(entries, x, func(e entry, t uint64) int {
						if e.X < t {
							return -1
						}
						if e.X > t {
							return 1
						}
						return 0
					})
					for ; ok && k < len(entries) && entries[k].X == x; k++ {
						local = append(local, hit{int(meta[i] & 1), entries[k].V, meta[i] >> 1})
					}
				}
				pts = pts[:0]
				meta = meta[:0]
			}
			var used [16]bool
			used[v0] = true
			vals := [10]int{v0}
			S := make([]secp256k1.JacobianPoint, nB)
			S[0] = tab[tb[0]][v0]
			var T [2]secp256k1.JacobianPoint
			var rec func(level int)
			rec = func(level int) {
				for v := 0; v < 16; v++ {
					if used[v] {
						continue
					}
					vals[level] = v
					if level == nB-1 {
						// R± = T± + (−k·P_{b8})
						var pk uint64
						for i := 0; i < nB; i++ {
							pk = pk<<4 | uint64(vals[i])
						}
						for s := 0; s < 2; s++ {
							var r secp256k1.JacobianPoint
							secp256k1.AddNonConst(&T[s], &neg[tb[level]][v], &r)
							pts = append(pts, r)
							meta = append(meta, pk<<1|uint64(s))
						}
						if len(pts) >= chunk-1 {
							flush()
						}
						continue
					}
					secp256k1.AddNonConst(&S[level-1], &tab[tb[level]][v], &S[level])
					if level == nB-2 {
						// T± = ±pub − S_{nB-2}: uma vez por loop interno
						var negS secp256k1.JacobianPoint
						negS = S[level]
						negS.Y.Negate(1).Normalize()
						secp256k1.AddNonConst(targets[0], &negS, &T[0])
						secp256k1.AddNonConst(targets[1], &negS, &T[1])
					}
					used[v] = true
					rec(level + 1)
					used[v] = false
				}
			}
			rec(1)
			flush()
			mu.Lock()
			hits = append(hits, local...)
			mu.Unlock()
			doneMu.Lock()
			done++
			fmt.Fprintf(os.Stderr, "  B: %d/16 ramos v0 concluídos (%.0fs)\n", done, time.Since(t0).Seconds())
			doneMu.Unlock()
		}(v0)
	}
	wg.Wait()
	return hits
}

func main() {
	cfgPath := flag.String("config", "config.json", "config.json gerado pelo Python")
	control := flag.Bool("control", false, "usa a pubkey do controle plantado (ordem fwd)")
	orderArg := flag.String("orders", "", "ordens a rodar, separadas por vírgula (default: todas)")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		panic(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		panic(err)
	}
	pubHex := cfg.Pub
	if *control {
		pubHex = cfg.Control.Pub
	}
	pubBytes, _ := hex.DecodeString(pubHex)
	pk, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		panic(err)
	}
	var pub secp256k1.JacobianPoint
	pk.AsJacobian(&pub)

	orders := []string{"fwd", "rev", "byterev", "byterev_swap"}
	if *control {
		orders = []string{"fwd"}
	} else if *orderArg != "" {
		orders = nil
		for _, o := range splitComma(*orderArg) {
			orders = append(orders, o)
		}
	}
	nT := len(cfg.Tokens)
	ta := []int{0, 1, 2, 3, 4, 5, 6}
	tb := []int{7, 8, 9, 10, 11, 12, 13, 14, 15}
	fmt.Printf("tokens=%d  A=%v  B=%v  pub=%s…  control=%v  CPUs=%d\n", nT, ta, tb, pubHex[:18], *control, runtime.NumCPU())

	for _, order := range orders {
		wmap := cfg.Orders[order]
		if wmap == nil {
			panic("ordem desconhecida: " + order)
		}
		ws := make([]*secp256k1.ModNScalar, nT)
		wbig := make([]*big.Int, nT)
		for i, t := range cfg.Tokens {
			ws[i] = mustScalar(wmap[t])
			wbig[i], _ = new(big.Int).SetString(wmap[t], 16)
		}
		t0 := time.Now()
		tab, neg := buildTables(ws)
		entries := buildA(tab, ta)
		bitmap := make([]uint64, 1<<26) // 2^32 bits
		for _, e := range entries {
			bitmap[(e.X&0xffffffff)>>6] |= 1 << (e.X & 63)
		}
		fmt.Printf("[%s] tabela A: %d entradas em %.0fs; iniciando B (4,15e9 folhas × 2 sinais)\n", order, len(entries), time.Since(t0).Seconds())
		hits := runB(tab, neg, tb, &pub, entries, bitmap)
		fmt.Printf("[%s] B concluído em %.0fs; candidatos de 64 bits: %d\n", order, time.Since(t0).Seconds(), len(hits))
		verified := 0
		for _, h := range hits {
			pi := make([]int, nT)
			for i := 0; i < len(ta); i++ {
				pi[ta[i]] = int(h.packA>>(4*(len(ta)-1-i))) & 15
			}
			for i := 0; i < len(tb); i++ {
				pi[tb[i]] = int(h.packB>>(4*(len(tb)-1-i))) & 15
			}
			d := new(big.Int)
			for i := 0; i < nT; i++ {
				d.Add(d, new(big.Int).Mul(big.NewInt(int64(pi[i])), wbig[i]))
			}
			d.Mod(d, curveN)
			if h.sign == 1 {
				d.Sub(curveN, d)
			}
			var ds secp256k1.ModNScalar
			db := d.FillBytes(make([]byte, 32))
			ds.SetByteSlice(db)
			var q secp256k1.JacobianPoint
			secp256k1.ScalarBaseMultNonConst(&ds, &q)
			q.ToAffine()
			pubA := pub
			pubA.ToAffine()
			if q.X.Equals(&pubA.X) && q.Y.Equals(&pubA.Y) {
				verified++
				fmt.Printf("*** SOLVE VERIFICADO [%s sign=%d] privkey=%x  pi=%v\n", order, h.sign, db, pi)
			}
		}
		fmt.Printf("[%s] verificados contra a pubkey: %d\n", order, verified)
		if verified == 0 {
			fmt.Printf("[%s] NEGATIVO: nenhuma das 16! bijeções (×2 sinais) gera a pubkey.\n", order)
		}
	}
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
