/* Recheck every saved password against the ORIGINAL three ciphertexts.
 * Includes unsuccessful attempts, not only retained padding results.
 * node solver/verify_blue_hex.cjs
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const base = path.join(root, '_work', 'blue_hex_2026-09-11');
const data = JSON.parse(fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json')));
const readLines = file => fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).filter(Boolean).map(x => JSON.parse(x));
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
function open(password, blob, digest) {
  const salt = Buffer.from(blob.salt, 'hex');
  let previous = Buffer.alloc(0), result = Buffer.alloc(0);
  while (result.length < 48) {
    previous = crypto.createHash(digest).update(Buffer.concat([previous, password, salt])).digest();
    result = Buffer.concat([result, previous]);
  }
  const d = crypto.createDecipheriv('aes-256-cbc', result.subarray(0, 32), result.subarray(32, 48));
  try { return Buffer.concat([d.update(Buffer.from(blob.ciphertext, 'hex')), d.final()]).toString('hex'); }
  catch (error) { if (error.code === 'ERR_OSSL_BAD_DECRYPT') return null; throw error; }
}
const control = Buffer.from(data.phase32_control_b64, 'base64');
const controlBlob = {salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex')};
assert(Buffer.from(open(Buffer.from(data.phase32_control_password), controlBlob, 'sha256'), 'hex').toString().startsWith("I've been waiting for you."));
const families = {}, allPasswords = new Set();
for (const family of ['', 'prime_bits', 'rail_values', 'composite']) {
  const dir = path.join(base, family);
  const passwords = readLines(path.join(dir, 'passwords.jsonl'));
  const records = readLines(path.join(dir, 'padding_results.jsonl'));
  const expected = new Map(records.map(x => [[x.passwordHex, x.blob, x.kdf].join('/'), x.plaintextHex]));
  assert.equal(expected.size, records.length);
  let attempts = 0, paddings = 0;
  for (const p of passwords) {
    const password = Buffer.from(p.passwordHex, 'hex'); allPasswords.add(p.passwordHex);
    if (family === 'composite') assert.equal(password.toString(), sha(p.preimage));
    for (const [name, blob] of Object.entries(data.blobs)) for (const digest of ['sha256', 'md5']) {
      const plaintext = open(password, blob, digest);
      const label = [p.passwordHex, name, digest].join('/');
      assert.equal(plaintext, expected.get(label) ?? null, `${family}/${p.label}/${name}/${digest}`);
      attempts++; if (plaintext !== null) paddings++;
    }
  }
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json')));
  assert.equal(attempts, summary.attempts); assert.equal(paddings, summary.padding);
  families[family || 'blue_digits'] = {passwords: passwords.length, attempts, matchingPaddingPlaintexts: paddings};
}
const result = {
  verifier_sha256: sha(fs.readFileSync(__filename)), families,
  distinctPasswordsAcrossFamilies: allPasswords.size,
  allOriginalAESAttemptsRechecked: Object.values(families).reduce((a, x) => a + x.attempts, 0),
  allFullPaddingPlaintextsRechecked: Object.values(families).reduce((a, x) => a + x.matchingPaddingPlaintexts, 0),
  controls: 'Known phase 3.2 plaintext; composite SHA256 preimages; compare all successes and failures.',
  limitation: 'Confirms saved cryptographic results; does not authenticate any proposed puzzle interpretation.',
};
fs.writeFileSync(path.join(base, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
