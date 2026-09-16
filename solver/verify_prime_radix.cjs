/* Verify the saved candidates and ALL their recorded AES successes/failures.
 * node solver/verify_prime_radix.cjs
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const base = path.join(root, '_work', 'shared_numeric_2026-09-11');
const out = path.join(base, 'candidate_checks');
const data = JSON.parse(fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json')));
const search = JSON.parse(fs.readFileSync(path.join(base, 'prime_radix_summary.json')));
const lines = file => fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).filter(Boolean).map(x => JSON.parse(x));
const passwords = lines(path.join(out, 'passwords.jsonl'));
const records = lines(path.join(out, 'padding_results.jsonl'));
const reference = JSON.parse(fs.readFileSync(path.join(out, 'summary.json')));
const expected = new Map(records.map(r => [[r.passwordHex, r.blob, r.kdf].join('/'), r.plaintextHex]));
assert.equal(expected.size, records.length);
const generated = new Set();
for (const candidate of search.hits) {
  const bytes = Buffer.from(candidate.ascii, 'ascii');
  let n = 0n;
  for (const b of bytes) { assert(b === 9 || b === 10 || b === 13 || b >= 32 && b <= 126); n = n * BigInt(candidate.base) + BigInt(b); }
  assert.equal(n.toString(), candidate.decimal);
  const original = data[candidate.field];
  assert.equal(original.length, candidate.decimal.length);
  [...original].forEach((c, i) => assert(c === 'g' ? '07'.includes(candidate.decimal[i]) : candidate.decimal[i] === String(c.charCodeAt(0) - 96)));
  for (const text of [candidate.ascii, candidate.ascii.replace(/\s/g, ''), candidate.ascii.toLowerCase(), candidate.ascii.toUpperCase()]) {
    generated.add(Buffer.from(text).toString('hex'));
    generated.add(Buffer.from(crypto.createHash('sha256').update(text).digest('hex')).toString('hex'));
  }
}
assert.deepEqual(new Set(passwords.map(x => x.passwordHex)), generated, 'Saved passwords must cover the current candidate list. Rebuild them after resuming the search.');
function decrypt(password, blob, hash) {
  let prior = Buffer.alloc(0), material = Buffer.alloc(0);
  const salt = Buffer.from(blob.salt, 'hex');
  while (material.length < 48) {
    prior = crypto.createHash(hash).update(Buffer.concat([prior, password, salt])).digest();
    material = Buffer.concat([material, prior]);
  }
  const d = crypto.createDecipheriv('aes-256-cbc', material.subarray(0, 32), material.subarray(32, 48));
  try { return Buffer.concat([d.update(Buffer.from(blob.ciphertext, 'hex')), d.final()]).toString('hex'); }
  catch (error) { if (error.code === 'ERR_OSSL_BAD_DECRYPT') return null; throw error; }
}
const control = Buffer.from(data.phase32_control_b64, 'base64');
const controlBlob = {salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex')};
assert(Buffer.from(decrypt(Buffer.from(data.phase32_control_password), controlBlob, 'sha256'), 'hex').toString().startsWith("I've been waiting for you."));
let attempts = 0, padding = 0;
for (const record of passwords) for (const [name, blob] of Object.entries(data.blobs)) for (const hash of ['sha256', 'md5']) {
  const actual = decrypt(Buffer.from(record.passwordHex, 'hex'), blob, hash);
  assert.equal(actual, expected.get([record.passwordHex, name, hash].join('/')) ?? null);
  attempts++; if (actual !== null) padding++;
}
assert.equal(attempts, reference.attempts); assert.equal(padding, reference.padding);
const result = {candidatesReconstructed: search.hits.length, passwordsRegenerated: generated.size,
  allAESAttemptsVerified: attempts, fullPaddingPlaintextsVerified: padding,
  pendingSearches: search.incomplete, verifierSHA256: crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex')};
fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
