# -*- coding: utf-8 -*-
"""telegram_miner — testa com oráculo duro os candidatos CONCRETOS garimpados do
export do Telegram (result.json) que NÃO constam das famílias fechadas do ENDGAME.

Hipótese (falsificável, espaço finito): alguma string literal dita pelo criador
(Jrk Bgrt) ou proposta como "quase-senha" pela comunidade e ainda não testada
(comentário HTML 2, frase do Rhineheart, concatenações 103-chars, senhas de
"decrypts" reivindicados, coordenadas -41,-17, "Infrared", "<3", datas do
passaporte, sobra da fase 2 X2SH4Y0QB15) é a senha EVP de SMALL/COSMIC/TAIL32
ou, via sha256, a chave privada do prêmio.
"""
import sys, hashlib, time
sys.path.insert(0, r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02")
import gsmg_common as G

LOG = r"C:\Users\ruthe\Desktop\puzzle\gsmgio-5btc-puzzle\solver\experiments\claude_endgame_2026_09_02\telegram_miner.jsonl"
open(LOG, "w").close()
G.jsonl(LOG, {"family": "telegram_miner", "hypothesis": __doc__.strip()})

POEM = "Roses are White but often Red.\nYellow has a number and so does Blue.\nGo back to the first puzzle piece without further ado.\n\nIt might have shown you only one door, beware that the rabbits nest may contain a whole lot more.\n\nHush hush."
CANDS = {
 # --- comunidade: concatenações/senhas concretas (ids do result.json)
 "#43685": ["matrixsumlistlastwordsbeforeachichoicethispasswordourfirsthintisyourlastcommand",
            "matrixsumlistlastwordsbeforearchichoicethispasswordourfirsthintisyourlastcommand"],
 "#62290": ["matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"],
 "#65298": ["matrixsumlistlastwordsbeforearchichoicethispasswordshabefourfirsthintisyourlastcommandentershabefanstoo",
            "matrixsumlistlastwordsbeforearchichoiceshabefourfirsthintisyourlastcommandentershabefanstoo"],
 "#35242": ["timehascometomakeachoicemrandersoneitheryouchoosetobeatyourdeskontimefromthisdayforwardoryouchoosetofindyourselfanotherjobdoimakemyselfclear",
            "time has come to make a choice mr anderson either you choose to be at your desk on time from this day forward or you choose to find yourself another job do i make myself clear",
            "rhineheart", "Rhineheart"],
 "#29451": ["You made it to the next step! Good luck little bunny hunter 😉", "You made it to the next step! Good luck little bunny hunter",
            "You made it to the next step!", "youmadeittothenextstep", "YouMadeItToTheNextStep", "next step", "nextstep"],
 "#52856": ["99c09ec07ab2ac6b8ba78e9c9395a0", "99 c0 9e c0 7a b2 ac 6b 8b a7 8e 9c 93 95 a0"],
 "#62300": ["20c53e334ca2e74815e5b93536db1849c8ac36929eea409bb02f9f52b177824d"],
 "#27849": ["1334001941", "u+2e2e", "shabef(u+2e2e)", "08f2d4bf9b355798419ad5786581891f6eeca4018347555030c7479b5bbde9e9"],
 "#225":   ["5ac407837447fba24ba2802e4d1e9aecb4580aa29fef1088cc387c180b746f75"],
 "#60232": ["ZION", "zion", "Zion"],
 # --- criador: strings literais ainda não testadas
 "#1837":  ["Only -41,-17 matters", "-41,-17", "-41-17", "4117", "1741", "-41", "-17", "41,17", "17,41"],
 "#6250":  ["Infrared", "infrared", "INFRARED"],
 "#3404":  ["And Oen", "Oen", "oen", "eon", "Neo", "One"],
 "#4105":  ["First or zero", "firstorzero", "FirstOrZero", "answer is there", "answeristhere"],
 "#6884":  ["another door might be found on {1 },{4} ,{21}", "{1 },{4} ,{21}", "1421", "1 4 21", "14 21"],
 "#6913":  ["R=18 A=1 B=2", "1812", "21", "RAB", "rab", "1812bit", "21bit", "R18A1B2"],
 "#7914":  ["There is Another DOOR", "There\nAnother\nD\nO\nO\nR", "ThereIsAnotherDOOR", "thereisanotherdoor", "anotherdoor", "DOOR"],
 "#1710":  [POEM, POEM.replace("\n", ""), POEM.replace("\n", " "), "Hush hush.", "Hush hush", "hushhush", "HushHush"],
 "#867":   ["giveit = givetit", "givetit", "givetit = giveit"],
 "#8385":  ["42", "-42", "fourtytwo", "fortytwo"],
 "#24071": ["1357 blocks to go", "1357", "1357blockstogo"],
 "#32671": ["the last number of pi", "thelastnumberofpi", "lastnumberofpi"],
 "#32613": ["ASCII 127", "\x7f", "127", "DEL"],
 "#32719": ["2145"],
 "#17891": ["Have you tried the purple pill already?", "purple pill", "purplepill", "PurplePill", "thepurplepill", "Candy flipping into 2024", "candyflipping"],
 "#49176": ["Carrots were originally purple, until the Dutch turned them orange in the 1600s to kiss up to their royal family.",
            "carrotswereoriginallypurpleuntilthedutchturnedthemorangeinthe1600stokissuptotheirroyalfamily",
            "carrot", "carrots", "purple", "orange", "dutch", "Dutch", "purplecarrot", "1600", "1600s", "royalfamily", "kissup"],
 "#9047":  ["Globally supporting my generation", "globallysupportingmygeneration", "GloballySupportingMyGeneration", "GLOBALLYSUPPORTINGMYGENERATION"],
 "#53342": ["Happy new year! Make the best of everything. Oh, and here's a \"tiny hint\" <3.", "<3", "<3.", "tiny hint", "tinyhint", "heart", "love",
            ".....", ". .. ... .... .....", "12345", "15", "5"],
 "#60312": ["Bingo", "bingo", "BINGO"],
 "#23159": ["I prefer superpositions", "superpositions", "superposition"],
 "#8796":  ["Actually, the hardest part is done.", "Are you really looking for just the btc...?", "Something was solved rather... remarkable.", "Partly.", "Partly", "partly"],
 "#8048":  ["11 SEP 2001", "11SEP2001", "11092001", "20010911", "2001-09-11", "09112001", "september112001", "11sep2001", "SEP 11 2001"],
 "#3390":  ["Humph. Hope, it is the quintessential human delusion, simultaneously the source of your greatest strength, and your greatest weakness.",
            "Humph", "humph"],
 "#60304": ["Looking Forward", "LookingForward", "lookingforward", "Looking forward"],
 "#60324": ["rewatch episode 3.5 with the better half", "episode 3.5", "episode3.5", "3.5"],
 # --- sobra da fase 2 (criador: "Can't say anything about this", #8569)
 "#8569":  ["# X 2 S H 4 Y 0 Q B 15 #", "X 2 S H 4 Y 0 Q B 15", "X2SH4Y0QB15", "x2sh4y0qb15", "Norton", "Nortons theorem", "nortonstheorem", "Norton's theorem",
            "X232-424Y0Q-1615", "X2324Y0Q-1615", "swordfish", "Swordfish", "fish", "cha' + (vagh * jav)", "BV80605001911AP"],
 "#5952":  ["HUNDRED FOURTY", "hundredfourty", "104", "FEFEFE", "fefefe", "101010"],
 "#1256":  ["1616"],
}

def forms(s):
    out = {s, s.upper(), s.lower(), s.replace(" ", ""), G.shahex(s), G.shahex(s.upper()), G.shahex(s.replace(" ", ""))}
    return out

n_tests = 0; hard = []; soft = []
t0 = time.time()
for src, lst in CANDS.items():
    for c in lst:
        for f in forms(c):
            h, s = G.try_password_all(f)
            n_tests += 6  # 3 blobs x 2 kdf
            for x in h: x.update(src=src, cand=c, pw=f); hard.append(x); G.jsonl(LOG, {"HARD": x})
            for x in s: x.update(src=src, cand=c, pw=f); soft.append(x); G.jsonl(LOG, {"soft": x})
        r = G.phrase_priv(c); n_tests += 36  # 6 formas x 2 (\n) x 3 hashes
        if r: hard.append({"src": src, "cand": c, "priv": str(r)}); G.jsonl(LOG, {"HARD_PRIV": src, "cand": c, "r": str(r)})
        # hex64 literal como privkey crua / senha-hex como bytes
        if len(c) == 64 and all(ch in "0123456789abcdef" for ch in c):
            r = G.priv_hit(bytes.fromhex(c)); n_tests += 1
            if r: hard.append({"src": src, "cand": c, "priv_raw": str(r)})
            for blob in ("SMALL", "COSMIC", "TAIL32"):
                p = G.aes_rawkey(bytes.fromhex(c), blob); n_tests += 1
                if p is not None and G.semantic(p): hard.append({"src": src, "cand": c, "rawkey_blob": blob, "hex": p.hex()})

# --- verificação estrutural (não-oráculo) da alegação de Denis Golovkin (#60325/#61489):
# b / be nas posições primas (1-based) do dbbi reproduz a sequência de cores espiral (B/Y)?
primes = [p for p in range(2, 92) if G.is_prime(p)]
d = G.DBBI
seq = ""
for p in primes:
    ch = d[p-1]; nx = d[p] if p < 91 else ""
    seq += "Y" if (ch == "b" and nx == "e") else ("B" if ch == "b" else "?")
match = sum(a == b for a, b in zip(seq, G.COLOR_SEQ))
denis = {"prime_seq": seq, "color_seq": G.COLOR_SEQ, "match": f"{match}/24", "n_b_on_prime": seq.count("B") + seq.count("Y")}
G.jsonl(LOG, {"denis_b_be_check": denis})

# controle positivo do decoder AES: cifra um plaintext conhecido com senha conhecida (EVP-MD5, formato openssl)
# e confere que try_password_all o classifica como hit duro.
from Crypto.Cipher import AES as _AES
from Crypto.Hash import MD5 as _MD5
_salt = b"\x01\x02\x03\x04\x05\x06\x07\x08"; _pw = "controlepositivo"
_k, _iv = G.evp(_pw.encode(), _salt, _MD5)
_pt = b"CONTROLE POSITIVO: plaintext semantico de teste para o oraculo duro."
_pt += bytes([16 - len(_pt) % 16]) * (16 - len(_pt) % 16)
G.BLOBS["CTRL"] = (_salt, _AES.new(_k, _AES.MODE_CBC, _iv).encrypt(_pt))
_h, _s = G.try_password_all(_pw, blobs=("CTRL",))
ctrl = bool(_h) and G.bif_full().startswith("BTCSEED")
G.jsonl(LOG, {"control_bifid_BTCSEED": ctrl, "n_tests": n_tests, "hard": len(hard), "soft": len(soft), "secs": round(time.time()-t0, 1)})
print("n_tests", n_tests, "hard", len(hard), "soft", len(soft), "ctrl", ctrl, "denis", denis)
for x in hard: print("HARD", x)
for x in soft[:10]: print("soft", x)
