'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/radix127_completion_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest();
const read = f => JSON.parse(fs.readFileSync(path.join(out, f)));
function main() {
  const summary = read('summary.json'), verification = read('verification.json'); assert(summary.complete && verification.complete);
  assert(!fs.existsSync(path.join(out, 'new_candidate_auth.json')), 'Inspect completed oracles before rerunning');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), hits = read('hits.json');
  const previousRaw = fs.readFileSync(path.join(root, '_work/shared_numeric_2026-09-11/prime_radix_results.json')), previous = JSON.parse(previousRaw).results.find(r => r.field === 'faed' && r.base === 127), old = new Set(previous.hits.map(h => h.decimal));
  const fresh = hits.filter(h => !old.has(h.decimal)); assert.equal(fresh.length, 11); assert(fresh.every(h => BigInt(h.decimal) >= BigInt(previous.resumeMinDecimal)));
  const materials = new Map(), passwords = new Map(), scalars = new Set();
  function scalar(b) { assert.equal(b.length, 32); scalars.add(b.toString('hex')); scalars.add(Buffer.from(b).reverse().toString('hex')); }
  function windows(b) { for (let i = 0; i + 32 <= b.length; i++) scalar(b.subarray(i, i + 32)); }
  for (const [candidate, h] of fresh.entries()) {
    for (const [form, text] of [['raw', h.ascii], ['withoutWhitespace', h.ascii.replace(/\s/g, '')], ['lowercase', h.ascii.toLowerCase()], ['uppercase', h.ascii.toUpperCase()]]) {
      const bytes = Buffer.from(text, 'ascii'), hex = bytes.toString('hex'); if (!materials.has(hex)) materials.set(hex, { id: materials.size, candidate, form, hex });
    }
  }
  for (const m of materials.values()) {
    const bytes = Buffer.from(m.hex, 'hex'); windows(bytes);
    for (const [form, p] of [['direct', bytes], ['sha256-hex', Buffer.from(hash(bytes).toString('hex'))]]) { const hex = p.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, material: m.id, form, hex }); }
  }
  const raw = Buffer.from(input.phase32_control_b64, 'base64'); assert.equal(hash(open(Buffer.from(input.phase32_control_password), { salt: raw.subarray(8, 16).toString('hex'), ciphertext: raw.subarray(16).toString('hex') }, 'sha256')).toString('hex'), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = []; let maxPrintable = 0;
  for (const p of passwords.values()) {
    const password = Buffer.from(p.hex, 'hex'); scalar(hash(password));
    for (const [name, blob] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
      const plain = open(password, blob, digest); flags.push(Number(plain !== null)); if (plain === null) continue;
      const fraction = [...plain].filter(v => v >= 32 && v <= 126 || v === 9 || v === 10 || v === 13).length / plain.length;
      padding.push({ password: p.id, blob: name, digest, plaintextHex: plain.toString('hex'), printable: fraction }); maxPrintable = Math.max(maxPrintable, fraction); scalar(hash(plain)); windows(plain);
    }
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, valid = [...scalars].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort(), ec = crypto.createECDH('secp256k1'), matches = [];
  for (const h of valid) { ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ hex: h, exact: pub === input.target_pubkey }); }
  const result = { complete: true, inputSHA256: hash(inputRaw).toString('hex'), previousResultsSHA256: hash(previousRaw).toString('hex'), sourceSHA256: hash(fs.readFileSync(__filename)).toString('hex'), candidates: fresh, materials: [...materials.values()], passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable, scalars: valid.length, scalarStreamSHA256: hash(Buffer.concat(valid.map(h => Buffer.from(h, 'hex')))).toString('hex'), matches, scope: 'Eleven newly completed base127 texts only; four previously declared text forms and direct/SHA256-hex passwords. All3 blobs, EVP-SHA256/MD5. SHA256 of each password, source-material32-byte windows, and SHA256/windows of padding bodies, in both byte orders. Old177 candidates were authenticated previously; passing ASCII or PKCS7 does not authenticate a solution.' };
  fs.writeFileSync(path.join(out, 'new_candidate_auth.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ candidates: fresh.length, materials: materials.size, passwords: passwords.size, attempts: flags.length, paddings: padding.length, maxPrintable, scalars: valid.length, matches }));
}
main();
