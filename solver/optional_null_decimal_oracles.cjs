'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), dir = path.join(root, '_work/optional_null_decimal_2026-09-16/with_zero');
const read = f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')), hash = b => crypto.createHash('sha256').update(b).digest();
const input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), candidates = read('candidates.json');
const raw = Buffer.from(input.phase32_control_b64, 'base64');
assert.equal(hash(open(Buffer.from(input.phase32_control_password), {salt: raw.subarray(8, 16).toString('hex'), ciphertext: raw.subarray(16).toString('hex')}, 'sha256')).toString('hex'), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const materials = new Map(), passwords = new Map(), scalars = new Set();
for (const [index, c] of candidates.entries()) for (const reverse of [false, true]) {
  const bytes = Buffer.from(c.hex, 'hex'); if (reverse) bytes.reverse(); assert([...bytes].every(b => b < 128));
  if (!materials.has(bytes.toString('hex'))) materials.set(bytes.toString('hex'), {hex: bytes.toString('hex'), candidate: index, reverse});
  const digest = hash(bytes); scalars.add(digest.toString('hex'));
  for (let at = 0; at + 32 <= bytes.length; at++) scalars.add(bytes.subarray(at, at + 32).toString('hex'));
  for (const [form, password] of [['raw', bytes], ['sha256-hex', Buffer.from(digest.toString('hex'))]]) {
    const hex = password.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, {hex, candidate: index, reverse, form});
  }
}
const padding = []; let attempts = 0, maxPrintable = 0;
for (const [password, p] of [...passwords.values()].entries()) for (const [name, blob] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
  attempts++; const plaintext = open(Buffer.from(p.hex, 'hex'), blob, digest); if (!plaintext) continue;
  const printable = [...plaintext].filter(v => v >= 32 && v < 127 || [9, 10, 13].includes(v)).length / plaintext.length;
  padding.push({password, blob: name, digest, plaintextHex: plaintext.toString('hex'), printable}); maxPrintable = Math.max(maxPrintable, printable);
  scalars.add(hash(plaintext).toString('hex'));
  for (let at = 0; at + 32 <= plaintext.length; at++) {const b = Buffer.from(plaintext.subarray(at, at + 32)); scalars.add(b.toString('hex')); scalars.add(b.reverse().toString('hex'));}
}
const order = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'), ec = crypto.createECDH('secp256k1'), valid = [...scalars].filter(h => {const n = BigInt('0x' + h); return n > 0n && n < order;}).sort(), hits = [];
for (const hex of valid) {ec.setPrivateKey(Buffer.from(hex, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) hits.push({hex, exact: pub === input.target_pubkey});}
const result = {sourceSHA256: hash(fs.readFileSync(__filename)).toString('hex'), candidatesSHA256: hash(fs.readFileSync(path.join(dir, 'candidates.json'))).toString('hex'),
  candidates: candidates.length, materials: [...materials.values()], passwords: [...passwords.values()], attempts, padding, maxPrintable,
  distinctScalars: valid.length, scalarStreamSHA256: hash(Buffer.concat(valid.map(h => Buffer.from(h, 'hex')))).toString('hex'), hits,
  printableWholeCandidates: [...materials.values()].filter(c => [...Buffer.from(c.hex, 'hex')].every(v => v >= 32 && v < 127 || [9, 10, 13].includes(v))), finalPasswordFound: false};
fs.writeFileSync(path.join(dir, 'oracles.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({candidates: candidates.length, materials: materials.size, passwords: passwords.size, attempts, paddings: padding.length, maxPrintable, distinctScalars: valid.length, hits, printableCandidates: result.printableWholeCandidates.length}));
