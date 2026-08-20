# -*- coding: utf-8 -*-
"""
GSMGJH / GSMGBH — payloads OP_RETURN de 71 B do endereco vanity
1GSMG9VDLTU6jyuG7bkNMdmnHBLtbbM51M (2026-05-15/16), apontados por
'GSMG WITNESS BLK 949653 TX 808f812f' enviado AO endereco do premio.

Estrutura: b'GSMGJH' + 65 B e b'GSMGBH' + 65 B.
Os 65 B tem cara de ASSINATURA COMPACTA de mensagem Bitcoin:
  [1B header 27..34][32B r][32B s]  (0x20=32 e 0x1f=31 estao na faixa)
Se for, a recuperacao ECDSA revela o ENDERECO do signatario sem conhecer
a pubkey — e se o endereco recuperado for o do premio (1GSMG1JC9...),
quem postou CONTROLA a chave do premio.

Varredura: mensagens candidatas x 2 assinaturas -> endereco recuperado.
Oraculo duro: endereco recuperado == premio OU um dos vanity GSMG.
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coincurve
import oracles as O

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')

def msg_hash(msg: bytes) -> bytes:
    payload = b'\x18Bitcoin Signed Message:\n' + varint(len(msg)) + msg
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()

def recover_addresses(sig65: bytes, msg: bytes):
    """Retorna lista de enderecos (unc/comp) recuperados p/ cada recid valido."""
    header = sig65[0]
    r, s = sig65[1:33], sig65[33:65]
    out = []
    base = header - 27
    for recid in range(4):
        for compressed in (False, True):
            h = 27 + recid + (4 if compressed else 0)
            if h != header:
                continue
            try:
                sig64 = r + s
                pk = coincurve.PublicKey.from_signature_and_message(
                    sig64, msg_hash(msg), hasher=None, recid=recid)
            except Exception:
                continue
            raw = pk.format(compressed=compressed)
            h160 = hashlib.new('ripemd160', hashlib.sha256(raw).digest()).digest()
            payload = b'\x00' + h160
            chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            import base58
            addr = base58.b58encode(payload + chk).decode()
            out.append((recid, compressed, addr))
    return out

SIGS = {
    'GSMGJH': bytes.fromhex('0495c689eb5aef53f7fa1ef650c56eac1a0e1b590f2a82fe6ddb7484ece385b37545eba470edae4316701263ce3abb194eca111d6107add0a30aab8bd77785f5'),
    'GSMGBH': bytes.fromhex('1f3afc610c1befe34300a07ec01e74c6b7f1e870dd3ff7e46e726363d0c9f18451650af99010f0495f43c1a332d45190631275191e429aa2dc1aae3b25ec79b35f'),
}
# headers: JH -> 0x04? NAO: JH payload comeca 04 (4) e BH comeca 1f (31).
# Testar AMBAS as interpretacoes de header: primeiro byte como header E ultimo byte.
INTERESTING = {
    O.PRIZE_ADDR,
    '1GSMG9VDLTU6jyuG7bkNMdmnHBLtbbM51M',
    '1GSMG1ABC95GES4k9UZCLtz6CYCUL8LUV2',
    '3GSMG24TujqfMJG1kQoBX18DzJHQLeJYMK',
    '1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe',
}

MSGS = [
    'GSMGJH', 'GSMGBH', 'JH', 'BH', 'half', 'betterhalf', 'better half',
    'half and better half', 'HALF AND BETTER HALF',
    'GSMG WITNESS BLK 949653 TX 808f812f',
    'gsmg.io', 'GSMG.IO', 'gsmg', 'GSMG',
    '1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe',
    '808f812f13a3137e48a0c95a818ae661a80fafaf409237efbb4b62b8198a4c13',
    '22381b6013973fedbe7821eb82e60d50ef61ee6e430896bd47f209b12157614b',
    'witness', 'WITNESS', 'yinyang', 'ying yang', 'salvation',
    'cosmic duality', 'Cosmic Duality', 'salphaseion', 'SalPhaseIon',
    'matrixsumlist', 'enter', 'lastwordsbeforearchichoice', 'thispassword',
    'ourfirsthintisyourlastcommand', 'HASHTHETEXT',
    'makethebestofeverything',
    'Happy new year! Make the best of everything. Oh, and here\'s a "tiny hint" <3.',
    '89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32',
    'The private keys belong to half and better half',
    'IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE',
    'secondanswer', 'yourlastcommand', 'hereismysecret', 'leavethematrix',
    'isolveditwithanabacus', 'bc1qks8zrshwmu3m8vgqdzwl2u8jjfgnvgjlezwqcd',
]

found = []
log = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '_work', 'gsmg_sig_recover.jsonl'), 'w', encoding='utf-8')
for name, sig in SIGS.items():
    # interpretacao 1: header = sig[0]
    for header_mode, s in [('first', sig), ('shifted', sig)]:
        header = s[0]
        if not (27 <= header <= 34):
            # tentar tratando o payload inteiro como r||s sem header, todos recids
            pass
        for msg in MSGS:
            for h_override in range(27, 35):
                s2 = bytes([h_override]) + s[1:]
                for recid, comp, addr in recover_addresses(s2, msg.encode()):
                    interesting = addr in INTERESTING
                    if interesting or h_override == s[0]:
                        rec = {'sig': name, 'header': h_override, 'msg': msg[:60],
                               'recid': recid, 'comp': comp, 'addr': addr, 'INTERESTING': interesting}
                        log.write(json.dumps(rec) + '\n')
                        if interesting:
                            found.append(rec)
                            print('!!! INTERESSE:', rec)
log.close()
print(f'\ntotal INTERESSANTES: {len(found)}')
for f in found:
    print(f)
