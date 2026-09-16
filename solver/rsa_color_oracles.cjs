'use strict';
// Candidate authentication; PKCS#7 alone is not authentication.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_color_candidates_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest();
const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw);
const candidateRaw = fs.readFileSync(path.join(out, 'candidates.jsonl')), candidates = candidateRaw.toString().trim().split(/\r?\n/).map(JSON.parse);
assert(!fs.existsSync(path.join(out, 'oracle_summary.json')), 'Inspect completed oracles before restarting');
const control = Buffer.from(input.phase32_control_b64, 'base64');
assert.equal(hash(open(Buffer.from(input.phase32_control_password), { salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex') }, 'sha256')).toString('hex'), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const passwords = new Map(), scalarFd = fs.openSync(path.join(out, 'scalar_records.bin'), 'wx'), paddingFd = fs.openSync(path.join(out, 'padding.jsonl'), 'wx');
const scalarHash = crypto.createHash('sha256'), flags = [], start = Date.now();
let scalarRecords = 0, attempts = 0, paddings = 0, maxPrintable = 0;
function scalar(b) { assert.equal(b.length, 32); fs.writeSync(scalarFd, b); scalarHash.update(b); scalarRecords++; }
for (const c of candidates) {
  const bytes = Buffer.from(c.hex, 'hex'), h = hash(bytes); scalar(h); scalar(Buffer.from(h).reverse());
  for (const [form, p] of [['raw', bytes], ['sha256-hex', Buffer.from(h.toString('hex'))]]) {
    const hex = p.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, candidate: c.id, form, hex });
  }
}
fs.writeFileSync(path.join(out, 'passwords.jsonl'), [...passwords.values()].map(r => JSON.stringify(r)).join('\n') + '\n');
for (const p of passwords.values()) for (const [name, blob] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
  attempts++; const plaintext = open(Buffer.from(p.hex, 'hex'), blob, digest); flags.push(Number(Boolean(plaintext))); if (!plaintext) continue;
  const printable = [...plaintext].filter(v => v >= 32 && v <= 126 || v === 9 || v === 10 || v === 13).length / plaintext.length;
  fs.writeSync(paddingFd, JSON.stringify({ password: p.id, blob: name, digest, plaintextHex: plaintext.toString('hex'), printable }) + '\n');
  paddings++; maxPrintable = Math.max(maxPrintable, printable); const h = hash(plaintext); scalar(h); scalar(Buffer.from(h).reverse());
  for (let at = 0; at + 32 <= plaintext.length; at++) { const b = plaintext.subarray(at, at + 32); scalar(b); scalar(Buffer.from(b).reverse()); }
}
fs.closeSync(scalarFd); fs.closeSync(paddingFd); fs.writeFileSync(path.join(out, 'aes_flags.bin'), Buffer.from(flags));
const result = { complete: true, candidates: candidates.length, passwords: passwords.size, attempts, paddings, maxPrintable, scalarRecords, scalarStreamSHA256: scalarHash.digest('hex'), elapsedMs: Date.now() - start, candidateSHA256: hash(candidateRaw).toString('hex'), inputSHA256: hash(inputRaw).toString('hex'), files: Object.fromEntries(['padding.jsonl', 'passwords.jsonl', 'aes_flags.bin'].map(f => [f, hash(fs.readFileSync(path.join(out, f))).toString('hex')])), sources: Object.fromEntries(['rsa_color_oracles.cjs', 'decimal_keystream_constraints.cjs'].map(f => [f, hash(fs.readFileSync(path.join(__dirname, f))).toString('hex')])), scope: 'Selected raw plaintexts and their lowercase SHA256-hex passwords only, three archived blobs, EVP_BytesToKey SHA256 and MD5. Scalar records contain SHA256(candidate), SHA256(padding plaintext), and every 32-byte padding-plaintext window, each in both byte orders. Scalar/public-key comparison is a separate step; padding alone never establishes a password.' };
fs.writeFileSync(path.join(out, 'oracle_summary.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
