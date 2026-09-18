// critico_sete_janelas — varre TODA janela de 32 B (duas ordens de byte) de plaintexts COSMIC
// regenerados pelo critico da familia sete_entrelacados, contra as DUAS chaves do premio:
// pubkey nao comprimida == 1GSMG (04f4d1bb...) ou h160(unc|comp) == 17ucy (4bc46844...).
// Entrada: arquivos .bin com registros [u32 LE tamanho][bytes]. Saida: JSON em stdout.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	tgt   = mustHex("04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559")
	h17   = mustHex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")
	h1gsm = mustHex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
)

func h160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

// check devolve "" (nada), "invalida" (0 ou >= n), "1GSMG" ou "17ucy".
func check(sec, alvo, hAlvo []byte) string {
	var k secp.ModNScalar
	if k.SetByteSlice(sec) || k.IsZero() {
		return "invalida"
	}
	var P secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&k, &P)
	P.ToAffine()
	pub := secp.NewPublicKey(&P.X, &P.Y)
	u := pub.SerializeUncompressed()
	if bytes.Equal(u, alvo) {
		return "1GSMG"
	}
	if bytes.Equal(h160(u), hAlvo) || bytes.Equal(h160(pub.SerializeCompressed()), hAlvo) {
		return "17ucy"
	}
	return ""
}

type Hit struct {
	Arquivo  string `json:"arquivo"`
	Registro int    `json:"registro"`
	Offset   int    `json:"offset"`
	Ordem    string `json:"ordem"`
	Chave    string `json:"chave"`
	Sec      string `json:"sec"`
}

func varre(buf []byte, alvo, hAlvo []byte, arq string, reg int, inval *int64) []Hit {
	var hs []Hit
	rev := make([]byte, 32)
	for j := 0; j+32 <= len(buf); j++ {
		w := buf[j : j+32]
		for i := 0; i < 32; i++ {
			rev[i] = w[31-i]
		}
		for _, o := range []struct {
			nome string
			s    []byte
		}{{"JANELA", w}, {"JANELA_REV", rev}} {
			switch r := check(o.s, alvo, hAlvo); r {
			case "":
			case "invalida":
				atomic.AddInt64(inval, 1)
			default:
				hs = append(hs, Hit{arq, reg, j, o.nome, r, hex.EncodeToString(o.s)})
			}
		}
	}
	return hs
}

func autoteste() {
	g := mustHex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	one := make([]byte, 32)
	one[31] = 1
	if check(one, g, h17) != "1GSMG" || check(one, tgt, mustHex("751e76e8199196d454941c45d1b3a323f1433bd6")) != "17ucy" ||
		check(one, tgt, mustHex("91b24bf9f5288532960ac687abb035127b1d28a5")) != "17ucy" || check(one, tgt, h17) != "" {
		panic("autoteste: chave 1")
	}
	// valor cruzado com coincurve (Python): sha256("teste")
	k := sha256.Sum256([]byte("teste"))
	if check(k[:], mustHex("046a72d6f9eec2e40f2165e59ffcc374a9bef7b6a2c0001da593ca14efa91ea410188b2331a9fc82586a3cb97131f71264ddc1926b5dd438684b8736bec4925eab"), h17) != "1GSMG" ||
		check(k[:], tgt, mustHex("fc92cd0f10148b734d632397e194648bec91fd32")) != "17ucy" {
		panic("autoteste: cruzado com Python")
	}
	if !bytes.Equal(h160(tgt), h1gsm) {
		panic("autoteste: pubkey do premio nao bate com o h160 do 1GSMG")
	}
	if check(make([]byte, 32), tgt, h17) != "invalida" || check(bytes.Repeat([]byte{0xff}, 32), tgt, h17) != "invalida" {
		panic("autoteste: 0 e >= n")
	}
	// positivo sintetico de janela: chave embutida no offset 77 (direta) e 140 (invertida)
	buf := make([]byte, 300)
	for i := range buf {
		buf[i] = byte(i*37 + 11)
	}
	copy(buf[77:], k[:])
	for i := 0; i < 32; i++ {
		buf[140+i] = k[31-i]
	}
	var inv int64
	hs := varre(buf, mustHex("046a72d6f9eec2e40f2165e59ffcc374a9bef7b6a2c0001da593ca14efa91ea410188b2331a9fc82586a3cb97131f71264ddc1926b5dd438684b8736bec4925eab"), h17, "t", 0, &inv)
	if len(hs) != 2 || hs[0].Offset != 77 || hs[0].Ordem != "JANELA" || hs[1].Offset != 140 || hs[1].Ordem != "JANELA_REV" {
		panic(fmt.Sprintf("autoteste: janelas %+v", hs))
	}
	fmt.Fprintln(os.Stderr, "autoteste Go OK")
}

func main() {
	autoteste()
	type Res struct {
		Arquivo   string `json:"arquivo"`
		Registros int    `json:"registros"`
		Janelas   int64  `json:"janelas_checadas"`
		Invalidas int64  `json:"invalidas"`
		Hits      []Hit  `json:"hits"`
		Seg       float64 `json:"seg"`
	}
	var out []Res
	for _, arq := range os.Args[1:] {
		// ponytail: streaming record-a-record. Ler os 182 MB de uma vez estourava o commit do
		// Windows (VirtualAlloc errno=1455) com outras campanhas rodando na mesma maquina.
		t0 := time.Now()
		fh, err := os.Open(arq)
		if err != nil {
			panic(err)
		}
		rd := bufio.NewReaderSize(fh, 1<<20)
		nw := runtime.NumCPU()
		if v := os.Getenv("JANELAS_WORKERS"); v != "" {
			fmt.Sscan(v, &nw)
		}
		tarefas := make(chan struct {
			b []byte
			i int
		}, nw*2)
		var jan, inv, feitos int64
		var mu sync.Mutex
		var hits []Hit
		var wg sync.WaitGroup
		for w := 0; w < nw; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range tarefas {
					hs := varre(t.b, tgt, h17, arq, t.i, &inv)
					atomic.AddInt64(&jan, int64(2*(len(t.b)-31)))
					if len(hs) > 0 {
						mu.Lock()
						hits = append(hits, hs...)
						mu.Unlock()
					}
					if f := atomic.AddInt64(&feitos, 1); f%20000 == 0 {
						fmt.Fprintf(os.Stderr, "  %s %d regs %.0fs\n", arq, f, time.Since(t0).Seconds())
					}
				}
			}()
		}
		var cab [4]byte
		nregs := 0
		for {
			if _, err := io.ReadFull(rd, cab[:]); err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}
			b := make([]byte, binary.LittleEndian.Uint32(cab[:]))
			if _, err := io.ReadFull(rd, b); err != nil {
				panic(err)
			}
			tarefas <- struct {
				b []byte
				i int
			}{b, nregs}
			nregs++
		}
		close(tarefas)
		wg.Wait()
		fh.Close()
		out = append(out, Res{arq, nregs, jan, inv, hits, time.Since(t0).Seconds()})
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", " ")
	e.Encode(out)
}
