/* Test every strict-UTF8 candidate, retaining control bytes exactly.
 * node solver/utf8_decimal_oracles.cjs
 */
'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work', 'utf8_decimal_2026-09-16');
const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json')), input = JSON.parse(inputBytes);
const summaryBytes = fs.readFileSync(path.join(out, 'two_symbols', 'summary.json')), summary = JSON.parse(summaryBytes);
const sha = b => crypto.createHash('sha256').update(b).digest();
const hashFile = f => sha(fs.readFileSync(f)).toString('hex');
assert.equal(summary.resultsSHA256, hashFile(path.join(out, 'two_symbols', 'results.json')));
assert.equal(summary.complete, summary.cases);
const candidates = [...new Map(summary.candidates.map(c => [c.hex, c])).values()];
const raw = Buffer.from(input.phase32_control_b64, 'base64');
const control = open(Buffer.from(input.phase32_control_password), {salt: raw.subarray(8,16).toString('hex'), ciphertext: raw.subarray(16).toString('hex')}, 'sha256');
assert.equal(sha(control).toString('hex'), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const ec = crypto.createECDH('secp256k1');
const order = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex'));
assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
const passwords = new Set(), scalars = new Set(), padding = [], pubHits = [];
let attempts = 0, maxPrintable = 0, noControlTexts = 0;
for (const [candidate, c] of candidates.entries()) {
  const preimage = Buffer.from(c.hex, 'hex'), hash = sha(preimage), hex = hash.toString('hex'), n = BigInt('0x' + hex);
  const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(preimage);
  assert.equal(text, c.text);
  if (![...text].some(ch => {const cp = ch.codePointAt(0); return cp < 32 && ![9, 10, 13].includes(cp) || cp >= 127 && cp <= 159;})) noControlTexts++;
  if (n > 0n && n < order && !scalars.has(hex)) {
    scalars.add(hex); ec.setPrivateKey(hash);
    const pub = ec.getPublicKey('hex', 'uncompressed');
    if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) {
      const secretHex = pub === input.target_pubkey ? hex : (order - n).toString(16).padStart(64, '0');
      ec.setPrivateKey(Buffer.from(secretHex, 'hex')); assert.equal(ec.getPublicKey('hex', 'uncompressed'), input.target_pubkey);
      pubHits.push({candidate, secretHex});
    }
  }
  for (const [form, password] of [['direct', preimage], ['sha256-hex', Buffer.from(hex)]]) {
    const id = password.toString('hex'); if (passwords.has(id)) continue; passwords.add(id);
    for (const [blob, data] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
      attempts++; const b = open(password, data, digest); if (!b) continue;
      const printable = [...b].filter(v => v >= 32 && v < 127 || [9, 10, 13].includes(v)).length / b.length;
      maxPrintable = Math.max(maxPrintable, printable);
      padding.push({candidate, form, blob, digest, plaintextHex: b.toString('hex'), printable});
    }
  }
}
fs.writeFileSync(path.join(out, 'candidates.json'), JSON.stringify(candidates) + '\n');
fs.writeFileSync(path.join(out, 'padding.json'), JSON.stringify(padding) + '\n');
const result = {candidateBytes: candidates.length, noControlTexts, passwords: passwords.size, aesAttempts: attempts,
  paddings: padding.length, maxPrintable, scalarChecks: scalars.size, pubHits,
  controls: {phase32SHA256: sha(control).toString('hex'), ecGenerator: true},
  inputSHA256: sha(inputBytes).toString('hex'), summarySHA256: sha(summaryBytes).toString('hex'),
  candidatesSHA256: hashFile(path.join(out, 'candidates.json')), paddingSHA256: hashFile(path.join(out, 'padding.json')),
  sourceSHA256: hashFile(__filename), caveat: 'Every candidate tested exactly as bytes and via SHA256 hexadecimal. Valid UTF8 and padding are not authentication. No case changes, truncation, replacement decoding or control-byte removal.'};
fs.writeFileSync(path.join(out, 'oracles.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
