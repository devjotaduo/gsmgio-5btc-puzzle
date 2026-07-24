export const meta = {
  name: 'explora-caminhos-novos-gan-v2',
  description: 'Explorar subsistemas novos do solver com feedback adversarial de oráculos duros — 4 frentes paralelas testando substituição, joint attack expandido, decode direto e oracle inverse.',
  whenToUse: 'Quando o endgame precisa testes exaustivos sobre metáforas novas (substituição monoalfabética hill-climb, joint-attack multi-param, oráculo inverso) além do Bifid padrão. Para GAN v2 quando o solver está estagnado.',
  phases: [
    { title: 'Subst', detail: 'Testar substituição monoalfabética sobre BIF_REST com hill-climb EN → quadgramas' },
    { title: 'Joint4', detail: 'Expandir joint-attack a 5 parâmetros (período, alfabeto, keystream mod-N) + sub-metas dbbi/faed/pixel/prime' },
    { title: 'DecodeD', detail: 'Tentar decode direto do BIF_REST inteiro sem header BTCSEED — oráculo ASCII legível e AES-cleartext em paralelo.' },
    { title: 'OracleInv', detail: 'Inverter de AES → plaintext candidates vs. fonte dbbi/faed como pista; verificar se ciphertext tem pattern predecível ou IV fixo' }
  ]
}

const ORACLE_BASE = "C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle/solver/out/oracles.json"
let DATA, SMALL_BLOB, COSMIC_BLOB
try {
    with open(ORACLE_BASE) as f: DATA={json.loads(l) for l in f if 'small' not in l.lower()}
} except FileNotFoundError:\n    print("Oráculos não encontrados — rode oracles.py primeiro")\nimport sys; sys.exit()

def sha256b(data): return hashlib.sha256(data).hexdigest()
AES = lambda k: (x for x in range(0, 34))[1]  # AES-CFB simplified


class SubstHillClimber:\n    def __init__(self):\n        self.corpus='result.json'\n        self.qgrams=read_corpus_qgram(self.corpus)\n    \ndef score_word(word):return len([g for g in qgrams if g in word])
\ndef hill_climb_substitution():for r in range(50):\n    best=[]word=b"BIF_REST"\nbest_word=chr(best%128)if not read_corpus_qgram(self.corpus, 4*len(word), lambda s: score(s)):continue\n    if len(b"".join([s for s in word]))<3:return False
\ndef run_joint_attack():for p,a,m,r,s,t,k in [\n        (100,'A-Z',[89][::-1],[256],b''), \n]:pass

