'use strict';
// Pré-carga (node -r) que roda solver/ebcdic_codepoints.cjs e solver/verify_ebcdic_codepoints.cjs SEM
// editá-los, na direção autêntica da fase 3.2: byte guardado b entra se latin1(b).encode(cp273) é ASCII
// 32–126/TAB/LF/CR. Os dois scripts tiram repertório e codificação de table.decoded; aqui eles recebem a
// tabela inversa (inv[b] = chr(índice de chr(b) na tabela 1141)), e o que gravariam na pasta de 16/09 vai
// para _work/lacunas_2026-09-18/ebcdic_codepoints_inverso/.
//   node -r ./solver/lacunas_2026_09_18/ebcdic_inverso_patch.cjs solver/ebcdic_codepoints.cjs
//   node -r ./solver/lacunas_2026_09_18/ebcdic_inverso_patch.cjs solver/verify_ebcdic_codepoints.cjs
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const root = path.resolve(__dirname, '..', '..');
const OLD = path.join(root, '_work', 'ebcdic_decimal_2026-09-16', 'codepoints');
const ENC = path.join(root, '_work', 'ebcdic_decimal_2026-09-16', 'encoding.json');
const NEW = path.join(root, '_work', 'lacunas_2026-09-18', 'ebcdic_codepoints_inverso');
// encoding.json é dado local: só existe no checkout principal
const REAL = 'C:/Users/ruthe/Desktop/puzzle/gsmgio-5btc-puzzle/_work/ebcdic_decimal_2026-09-16/encoding.json';
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const orig = {read: fs.readFileSync, write: fs.writeFileSync, mkdir: fs.mkdirSync};

const realRaw = orig.read(REAL), real = JSON.parse(realRaw.toString('utf8').replace(/^\uFEFF/, ''));
if (real.decoded.length !== 256) throw new Error('tabela 1141 inesperada');
const inv = real.decoded.map((_, b) => {
  const e = real.decoded.indexOf(String.fromCharCode(b));
  return e >= 0 ? String.fromCharCode(e) : '\u0000';  // sem imagem em cp273/1141: fora do repertório
});
const fakeRaw = Buffer.from(JSON.stringify({...real, decoded: inv, direcao: 'inversa (autêntica da fase 3.2)'}));
const ok = c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126 || [9, 10, 13].includes(c.charCodeAt(0));
const allowed = inv.flatMap((c, b) => ok(c) ? [b] : []);

const mapa = p => {
  const r = path.resolve(String(p));
  return r === path.resolve(OLD) || r.startsWith(path.resolve(OLD) + path.sep) ? path.join(NEW, path.relative(OLD, r)) : p;
};
fs.readFileSync = (p, ...a) => path.resolve(String(p)) === path.resolve(ENC) ? fakeRaw : orig.read(mapa(p), ...a);
fs.writeFileSync = (p, ...a) => orig.write(mapa(p), ...a);
fs.mkdirSync = (p, ...a) => orig.mkdir(mapa(p), ...a);

orig.mkdir(NEW, {recursive: true});
orig.write(path.join(NEW, 'repertorio.json'), JSON.stringify({
  direcao: 'inversa: b entra se latin1(b).encode(cp273) ∈ ASCII 32–126/TAB/LF/CR', n: allowed.length, allowed,
  tabela1141SHA256: sha(realRaw), tabelaInversaSHA256: sha(fakeRaw), patchSHA256: sha(orig.read(__filename)),
}, null, 1) + '\n');
