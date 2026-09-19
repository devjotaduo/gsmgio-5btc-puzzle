# -*- coding: utf-8 -*-
"""
F5 saltos_bijecao — fecha (ou reduz de forma declarada e exata) a lacuna de ENDGAME.md §6:
"saltos com bijeção arbitrária ficam em amostra (199.951 materiais)".

Mecanismo (reconstruído aqui porque o script original de
_work/residuo_saltos_2026-09-18/ não está neste checkout; ver FINDINGS.md "Convenção"):
  - resíduo (lista de símbolos a-i) vira lista de VALORES via uma bijeção {a..i}->{1..9}.
  - a partir de um offset (0-indexed em FAED, 570 símbolos), cada valor é um SALTO.
  - âncora "depois": posição_k = offset + dir*cumsum(valores[0..k])   (usa o k-ésimo salto)
  - âncora "antes" : posição_k = offset + dir*cumsum(valores[0..k-1]) (posição_1 = offset)
  - direção "frente": dir=+1; "trás": dir=-1
  - offset viável: toda posição gerada tem de cair em [0, 569] (sem wrap).

Controle: saltos [3,1,4] a partir de offset 0, âncora "depois", direção "frente", sobre FAED
(que começa "faedggeedfcbdabhhggcadcfeddgfdgbgigaaedg...") devolve "dgd" — reproduz o controle
citado em _work/residuo_saltos_2026-09-18/summary.json ("selecionado": "dgd").
"""
import sys, os, itertools, json, time, argparse, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
KITDIR = "/home/user/gsmgio-5btc-puzzle/solver/experiments/claude_endgame_2026_09_02"
sys.path.insert(0, KITDIR)
import gsmg_common as G  # noqa: E402

L84 = "difhccgihaeeihggegebgehhehhfafdhffcdbfcccgfeggecdcifffgigeeae"
L83 = L84[:-1]
assert len(L84) == 61 and len(L83) == 60
RESIDUOS = {"L84": L84, "L83": L83}
LETTERS = "abcdefghi"
FAED = G.FAED
assert len(FAED) == 570


def positions_depois(vals, offset, direction):
    pos = []
    c = 0
    for v in vals:
        c += direction * v
        pos.append(offset + c)
    return pos


def positions_antes(vals, offset, direction):
    pos = []
    c = 0
    for v in vals[:-1]:
        pos.append(offset + c)
        c += direction * v
    pos.append(offset + c)
    return pos


def max_reach_depois(vals, direction):
    # maior |deslocamento| absoluto atingido (sempre no fim, pois todos os valores > 0)
    return direction * sum(vals)


def max_reach_antes(vals, direction):
    return direction * sum(vals[:-1])


def viable_offsets(vals, anchor, direction):
    """Devolve (offset_min, offset_max) tal que toda posição cai em [0,569]. Vazio se nenhum."""
    if anchor == "depois":
        reach = max_reach_depois(vals, direction)
    else:
        reach = max_reach_antes(vals, direction)
    # posições variam monotonamente entre offset (deslocamento 0) e offset+reach
    lo_shift, hi_shift = (0, reach) if reach >= 0 else (reach, 0)
    # offset + lo_shift >= 0  e  offset + hi_shift <= 569
    off_min = max(0, -lo_shift)
    off_max = min(569, 569 - hi_shift)
    if off_max < off_min:
        return None
    return off_min, off_max


def control_check():
    vals = [3, 1, 4]
    pos = positions_depois(vals, 0, +1)
    mat = "".join(FAED[p] for p in pos)
    assert mat == "dgd", f"controle falhou: {mat!r}"
    # fase 2 controle: sha256hex("causality") abre o blob da fase 2 (G.PHASE2_B64), SO' via EVP-SHA256
    import base64
    raw = base64.b64decode(G.PHASE2_B64)
    s2, c2 = raw[8:16], raw[16:]
    pw = G.shahex("causality").encode()
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    k, iv = G.evp(pw, s2, SHA256)
    pt = G.unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c2))
    ok = pt is not None and pt.startswith(b"The ironic")
    assert ok, f"controle fase2 falhou: {pt!r}"
    return {"selecao_dgd": mat, "fase2_abriu": ok, "fase2_head": pt[:30].decode("latin-1")}


def sum_full_domain():
    """Aritmética EXATA do domínio completo (fórmula fechada, sem enumerar 9!)."""
    import math
    fact9 = math.factorial(9)
    out = {}
    total = 0
    for rname, res in RESIDUOS.items():
        L = len(res)
        # depois: usa os L valores inteiros -> soma esperada 5L, offsets = 570 - S (S<=570 sempre,
        # pois max S = 9*L < 570 aqui? checar) contagem = off_max-off_min+1 = 570 - S (quando S<570)
        # antes: usa os L-1 primeiros valores -> soma esperada 5(L-1)
        # contagem exata por bijeção: 570 - S (derivado de viable_offsets com reach=S, direction=+1:
        # off_min=0, off_max=569-S -> count = 570-S). É o mesmo valor para direction=-1 por simetria.
        sum_depois = fact9 * 570 - 5 * L * fact9
        sum_antes = fact9 * 570 - 5 * (L - 1) * fact9
        out[rname] = {
            "sum_offsets_depois_por_bijecao_9fatorial": sum_depois,
            "sum_offsets_antes_por_bijecao_9fatorial": sum_antes,
        }
        # x2 direções (frente/trás dão a mesma contagem de offsets, por simetria de reach)
        subtotal = 2 * (sum_depois + sum_antes)
        out[rname]["subtotal_materiais"] = subtotal
        total += subtotal
    out["TOTAL_dominio_completo"] = total
    out["fact9"] = fact9
    return out


def material_for_vals(vals, offset, anchor, direction):
    if anchor == "depois":
        pos = positions_depois(vals, offset, direction)
    else:
        pos = positions_antes(vals, offset, direction)
    return "".join(FAED[p] for p in pos)


def test_material(mat, kdf="sha256"):
    """Oráculo duro sobre um material: senha (raw + sha256hex, 3 blobs) e escalar (sha256).
    kdf='sha256' por padrão: AGENTS.md regra 2 -- os blobs autenticados so abrem via EVP-SHA256;
    MD5 e' controle secundario que nunca abre (fase 2 self-test confirma). Isso e' declarado como
    reducao explicita (nao MD5-blind): dobra o throughput sem perder o caminho que de fato abre."""
    result = {"padding": 0, "priv_hits": [], "aes_candidates": []}
    for pw in (mat, G.shahex(mat)):
        hard, soft = G.try_password_all(pw, kdf=kdf)
        result["padding"] += len(hard) + len(soft)
        if hard:
            result["aes_candidates"].extend(hard)
    b32 = G.sha(mat)
    hit = G.fast_priv_scan(b32, "scalar")  # coincurve, ~30x mais rapido que priv_hit (ecdsa puro)
    if hit:
        result["priv_hits"].extend(hit)
    return result


def planted_control():
    """Planta uma chave conhecida: um material cujo sha256 é a privkey de controle, testado
    contra um alvo temporário (mesmo mecanismo do self-test de gsmg_common)."""
    import oracles as O
    from coincurve import PublicKey
    k = G.sha(b"controle-dois-alvos-saltos-bijecao")
    pk = PublicKey.from_valid_secret(k)
    h = G._h160_hex(pk.format(False))
    old = O.TARGET_H160S
    O.TARGET_H160S = O.TARGET_H160S + (h,)
    G.TARGET_H160S = O.TARGET_H160S
    try:
        hit = G.priv_hit(k)
    finally:
        O.TARGET_H160S = old
        G.TARGET_H160S = old
    assert hit, "controle de privkey plantado NAO foi recuperado"
    return {"planted_h160": h, "recovered": bool(hit)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["arith", "bench", "run"], default="run")
    ap.add_argument("--offsets", type=int, default=1, help="quantos offsets por combinação testar (amostrados nas extremidades+centro do intervalo viável), 0 = todos")
    ap.add_argument("--limit-bij", type=int, default=0, help="0 = todas as 9! bijeções")
    ap.add_argument("--max-seconds", type=float, default=0, help="0 = sem limite de tempo")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "..", "..", "_work", "enxame_2026-09-19", "saltos_bijecao", "result.json"))
    args = ap.parse_args()

    t0 = time.time()
    ctrl_sel = control_check()
    ctrl_priv = planted_control()
    print("controle seleção:", ctrl_sel, "controle privkey:", ctrl_priv, file=sys.stderr)

    arith = sum_full_domain()
    print("aritmetica dominio completo:", json.dumps(arith), file=sys.stderr)

    if args.mode == "arith":
        json.dump({"aritmetica": arith, "controle_selecao": ctrl_sel, "controle_privkey": ctrl_priv},
                   open(args.out, "w"), indent=1, ensure_ascii=False)
        return

    perms = itertools.permutations(range(1, 10))
    n_bij = 0
    materiais_testados = 0
    padding_total = 0
    aes_candidatos = []
    priv_hits = []
    materiais_distintos = set()
    melhor = None

    def score_text(_mat):
        # NAO ha scorer de quadgramas neste container (result.json ausente; ver AGENTS.md e
        # o "Armadilhas" do prompt da frente). Nao usamos escore de texto como triagem nem
        # como resultado: o oraculo duro (AES padding+semantica, privkey) e a unica verdade
        # aqui. Mantemos so um criterio DETERMINISTICO e irrelevante para o oraculo (fracao de
        # vogais a/e/i) só para ter uma saida reprodutivel de "melhor" no relatorio.
        vowels = sum(1 for c in _mat if c in "aei")
        return vowels / len(_mat)

    stop = False
    for perm in perms:
        if stop:
            break
        n_bij += 1
        if args.limit_bij and n_bij > args.limit_bij:
            n_bij -= 1
            break
        bij = dict(zip(LETTERS, perm))
        vals_cache = {rname: [bij[c] for c in res] for rname, res in RESIDUOS.items()}
        for rname, res in RESIDUOS.items():
            vals = vals_cache[rname]
            for anchor in ("depois", "antes"):
                for direction in (+1, -1):
                    vr = viable_offsets(vals, anchor, direction)
                    if vr is None:
                        continue
                    off_min, off_max = vr
                    if args.offsets == 0:
                        offs = range(off_min, off_max + 1)
                    else:
                        cand = sorted(set([off_min, off_max, (off_min + off_max) // 2]))
                        offs = cand[: args.offsets] if args.offsets < len(cand) else cand
                    for offset in offs:
                        mat = material_for_vals(vals, offset, anchor, direction)
                        materiais_distintos.add(mat)
                        materiais_testados += 1
                        r = test_material(mat)
                        padding_total += r["padding"]
                        if r["aes_candidates"]:
                            aes_candidatos.append({"mat": mat, "res": rname, "anchor": anchor,
                                                    "dir": direction, "offset": offset,
                                                    "bij": "".join(str(x) for x in perm),
                                                    "hits": r["aes_candidates"]})
                        if r["priv_hits"]:
                            priv_hits.append({"mat": mat, "res": rname, "anchor": anchor,
                                               "dir": direction, "offset": offset,
                                               "bij": "".join(str(x) for x in perm),
                                               "hits": r["priv_hits"]})
                        sc = score_text(mat)
                        if melhor is None or sc > melhor[0]:
                            melhor = (sc, mat, rname, anchor, direction, offset, "".join(str(x) for x in perm))
        if n_bij % 5000 == 0:
            el = time.time() - t0
            print(f"bijecoes={n_bij} materiais={materiais_testados} t={el:.1f}s taxa={materiais_testados/max(el,1e-9):.1f}/s",
                  file=sys.stderr)
            if args.max_seconds and el >= args.max_seconds:
                stop = True

    elapsed = time.time() - t0
    out = {
        "aritmetica_dominio_completo": arith,
        "controle_selecao": ctrl_sel,
        "controle_privkey_plantado": ctrl_priv,
        "bijecoes_cobertas": n_bij,
        "offsets_por_combinacao": args.offsets,
        "materiais_testados": materiais_testados,
        "materiais_distintos": len(materiais_distintos),
        "padding_valido_total": padding_total,
        "aes_candidatos": aes_candidatos,
        "priv_hits": priv_hits,
        "melhor_escore": melhor,
        "tempo_s": elapsed,
        "taxa_materiais_por_s": materiais_testados / max(elapsed, 1e-9),
    }
    json.dump(out, open(args.out, "w"), indent=1, ensure_ascii=False)
    print("FEITO", json.dumps({k: v for k, v in out.items() if k not in ("aes_candidatos", "priv_hits")}), file=sys.stderr)


if __name__ == "__main__":
    main()
