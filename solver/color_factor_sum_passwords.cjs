'use strict';
// Explicit colour arithmetic -> prime factors -> spatial sum lists -> passwords.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/color_factor_sums_2026-09-16'), hash = b => crypto.createHash('sha256').update(b).digest(), sha = b => hash(b).toString('hex');
function factors(value) { const list = []; let n = value; for (let d = 2; d * d <= n; d++) while (n % d === 0) { list.push(d); n /= d; } if (n > 1) list.push(n); assert.equal(list.reduce((a, b) => a * b, 1), value); return list; }
function derive() {
  const hex = { B: '3F48CC', Y: 'FFF200' }, projections = [];
  for (const method of ['hexDigitSum', 'channelSum', 'packedRGB']) {
    const values = Object.fromEntries(Object.entries(hex).map(([color, text]) => [color, method === 'hexDigitSum' ? [...text].reduce((n, c) => n + parseInt(c, 16), 0) : method === 'channelSum' ? text.match(/../g).reduce((n, c) => n + parseInt(c, 16), 0) : parseInt(text, 16)]));
    projections.push({ method, values, factors: Object.fromEntries(Object.entries(values).map(([c, n]) => [c, factors(n)])) });
  }
  const pairs = projections.flatMap(p => [...new Set(p.factors.B)].flatMap(blue => [...new Set(p.factors.Y)].map(yellow => ({ method: p.method, blue, yellow }))));
  assert.equal(pairs.length, 14); return { hex, projections, pairs };
}
function materials(input) {
  const derivation = derive(), colors = new Map(input.colored.map(([, color, r, c]) => [r + ',' + c, color])), lists = [], candidates = new Map();
  const speech = input.phase32_text.replace(/[^a-z]/gi, '').toLowerCase(), start = speech.indexOf('reinsertingtheprimebasics'), end = speech.indexOf('select', start);
  assert(start >= 0 && end > start); const lastwords = [speech.slice(start, end), 'sheisgoingtodieandthereisnothingyoucandotostopit'];
  assert.equal(lastwords[0], 'reinsertingtheprimebasicsafterwhichyouwillberequiredto');
  function add(text, provenance) { const hex = Buffer.from(text).toString('hex'); if (!candidates.has(hex)) candidates.set(hex, { id: candidates.size, hex, provenance }); }
  for (const [pair, values] of derivation.pairs.entries()) for (const background of ['bits', 'zero']) {
    const matrix = input.matrix.map((row, r) => row.map((v, c) => colors.get(r + ',' + c) === 'B' ? values.blue : colors.get(r + ',' + c) === 'Y' ? values.yellow : background === 'bits' ? v : 0));
    const row = matrix.map(r => r.reduce((a, b) => a + b, 0)), col = Array.from({ length: 14 }, (_, c) => matrix.reduce((n, r) => n + r[c], 0)); assert.equal(row.reduce((a, b) => a + b, 0), col.reduce((a, b) => a + b, 0));
    for (const [order, original] of [['rows', row], ['columns', col], ['rows-columns', [...row, ...col]], ['columns-rows', [...col, ...row]], ['interleaved', row.flatMap((x, i) => [x, col[i]])]]) for (const reverse of [false, true]) {
      const list = reverse ? [...original].reverse() : original, id = lists.length; lists.push({ id, pair, background, order, reverse, values: list });
      for (const [format, text] of [['concatenated', list.join('')], ['comma', list.join(',')], ['space', list.join(' ')], ['newline', list.join('\n')], ['json', JSON.stringify(list)], ['bracket-spaces', '[' + list.join(', ') + ']']]) {
        add(text, { list: id, format, composition: 'list' });
        for (const [words, suffix] of lastwords.entries()) {
          add(text + suffix, { list: id, format, composition: 'list-lastwords', words });
          add(String(values.yellow) + values.blue + text + suffix, { list: id, format, composition: 'yellow-blue-list-lastwords', words });
        }
      }
    }
  }
  return { derivation, lastwords, lists, candidates: [...candidates.values()] };
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'oracles.json')), 'Inspect existing campaign before rerunning');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), pre = materials(input);
  const spec = { hypothesis: 'The colour numbers are a hex-digit sum, RGB-channel sum or packed24-bit RGB integer. Distinct prime factors of each number become the corresponding colour weight in the original14x14 geometry. Other cells retain their original bits or become zero. Spatial row/column sum lists use five declared orders, optional reversal and six exact textual formats. Test list alone, list+one of two previously fixed last-word clauses, or yellow prime+blue prime+list+clause. This is a new hypothesis, not a creator-provided formula. No arbitrary colour swap, prime interval, value modulo reduction, cropped list or fitted text.', ...pre.derivation, lastwords: pre.lastwords, inputSHA256: sha(inputRaw), sourceSHA256: sha(fs.readFileSync(__filename)), helperSHA256: sha(fs.readFileSync(path.join(__dirname, 'decimal_keystream_constraints.cjs'))) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n'); fs.writeFileSync(path.join(out, 'lists.json'), JSON.stringify(pre.lists, null, 2) + '\n'); fs.writeFileSync(path.join(out, 'materials.json'), JSON.stringify(pre.candidates, null, 2) + '\n');
  const passwords = new Map(); for (const c of pre.candidates) { const b = Buffer.from(c.hex, 'hex'); for (const [form, p] of [['direct', b], ['sha256-hex', Buffer.from(sha(b))]]) { const hex = p.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, material: c.id, form, hex }); } }
  const ctrl = Buffer.from(input.phase32_control_b64, 'base64'); assert.equal(sha(open(Buffer.from(input.phase32_control_password), { salt: ctrl.subarray(8, 16).toString('hex'), ciphertext: ctrl.subarray(16).toString('hex') }, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const scalarSet = new Set(), flags = [], padding = []; let maxPrintable = 0;
  function scalar(b) { assert.equal(b.length, 32); scalarSet.add(b.toString('hex')); scalarSet.add(Buffer.from(b).reverse().toString('hex')); }
  for (const p of passwords.values()) {
    const bytes = Buffer.from(p.hex, 'hex'); scalar(hash(bytes));
    for (const [name, blob] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
      const body = open(bytes, blob, digest); flags.push(Number(body !== null)); if (body === null) continue;
      const printable = [...body].filter(b => b >= 32 && b <= 126 || [9, 10, 13].includes(b)).length / body.length; maxPrintable = Math.max(maxPrintable, printable); padding.push({ password: p.id, blob: name, digest, plaintextHex: body.toString('hex'), printable }); scalar(hash(body));
      for (let at = 0; at + 32 <= body.length; at++) scalar(body.subarray(at, at + 32));
    }
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, scalars = [...scalarSet].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort(), ec = crypto.createECDH('secp256k1'), matches = [];
  ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex')); assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(crypto.createHash('ripemd160').update(hash(Buffer.from(input.target_pubkey, 'hex'))).digest('hex'), input.target_h160);
  for (const [i, h] of scalars.entries()) { ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ hex: h, exact: pub === input.target_pubkey }); if (i && i % 50000 === 0) console.log(JSON.stringify({ scalarProgress: i, total: scalars.length })); }
  const report = { complete: true, pairs: pre.derivation.pairs.length, lists: pre.lists.length, materials: pre.candidates.length, passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable, scalars: scalars.length, scalarStreamSHA256: sha(Buffer.concat(scalars.map(h => Buffer.from(h, 'hex')))), matches, inputSHA256: sha(inputRaw), sourceSHA256: sha(fs.readFileSync(__filename)), materialsSHA256: sha(fs.readFileSync(path.join(out, 'materials.json'))), listsSHA256: sha(fs.readFileSync(path.join(out, 'lists.json'))), scope: 'All declared materials, direct and SHA256-hex passwords, three original blobs and EVP-SHA256/MD5. SHA256(password) and SHA256/all32-byte windows of padding bodies in both byte orders. No brute force beyond the declared14 prime-factor pairs, list formats and word clauses.' };
  fs.writeFileSync(path.join(out, 'oracles.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ pairs: report.pairs, lists: report.lists, materials: report.materials, passwords: passwords.size, attempts: flags.length, paddings: padding.length, maxPrintable, scalars: scalars.length, matches }));
}
if (require.main === module) main();
module.exports = { factors, derive, materials };
