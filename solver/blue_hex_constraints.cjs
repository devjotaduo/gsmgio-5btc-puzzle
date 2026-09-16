/* Bounded test of SEND THE BLUE TO SET HEX -> DBBI's 64/16 prefix tokens.
 * Run: node solver/blue_hex_constraints.cjs [--prime-bits]
 * Uses original blobs and Node built-ins; writes only local research artifacts.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const primeMode = process.argv.includes('--prime-bits');
const out = path.join(root, '_work', 'blue_hex_2026-09-11', ...(primeMode ? ['prime_bits'] : []));
const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
const data = JSON.parse(inputBytes);
const sha = x => crypto.createHash('sha256').update(x).digest();
const hex = '0123456789abcdef';
const unique = xs => [...new Set(xs)];
function tokens(text) {
  const result = [];
  for (let i = 0; i < text.length;) {
    const n = 'bg'.includes(text[i]) ? 2 : 1;
    assert(i + n <= text.length);
    result.push(text.slice(i, i + n)); i += n;
  }
  return result;
}
function evp(password, salt, hash) {
  let previous = Buffer.alloc(0), material = Buffer.alloc(0);
  while (material.length < 48) {
    previous = crypto.createHash(hash).update(previous).update(password).update(salt).digest();
    material = Buffer.concat([material, previous]);
  }
  return [material.subarray(0, 32), material.subarray(32, 48)];
}
function decrypt(password, blob, hash) {
  const [key, iv] = evp(password, Buffer.from(blob.salt, 'hex'), hash);
  const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  try { return Buffer.concat([cipher.update(Buffer.from(blob.ciphertext, 'hex')), cipher.final()]); }
  catch (error) {
    if (error.code === 'ERR_OSSL_BAD_DECRYPT') return null;
    throw error;
  }
}
function classifyKey(key) {
  if (key.length !== 32) return null;
  const ecdh = crypto.createECDH('secp256k1');
  try { ecdh.setPrivateKey(key); } catch { return null; }
  const pub = ecdh.getPublicKey(null, 'uncompressed').toString('hex');
  if (pub === data.target_pubkey) return 'exact target';
  if (pub.slice(2, 66) === data.target_pubkey.slice(2, 66)) return 'negated target';
  return null;
}
const parsed = tokens(data.dbbi);
assert.equal(parsed.length, 64); assert.equal(unique(parsed).length, 16);
assert.equal(parsed.join(''), data.dbbi);
const blue = data.colored.filter(x => x[1] === 'B');
const rowBlue = [...blue].sort((a, b) => a[2] - b[2] || a[3] - b[3]);
const blueHex = Buffer.from(rowBlue.map(x => x[2] * 14 + x[3] + 1)).toString('hex');
const seenHex = unique(blueHex).join('');
const missing = [...hex].filter(c => !seenHex.includes(c)).join('');
assert.equal(blueHex, '061119242f3a5863767e81a3aab9c1');
assert.equal(missing, 'd');
const isPrime = n => n >= 2 && Array.from({length: Math.max(0, Math.floor(Math.sqrt(n)) - 1)}, (_, i) => i + 2).every(i => n % i !== 0);
const bluePrimes = rowBlue.map(x => x[2] * 14 + x[3] + 1).filter(isPrime);
const primeWeights = bluePrimes.map(p => (p - 1) % 9 + 1);
assert.deepEqual(bluePrimes, [17, 47, 163, 193]);
assert.deepEqual(primeWeights, [8, 2, 1, 4]);
function subsetAlphabet(weights) {
  return Array.from({length: 16}, (_, n) => weights.reduce((sum, weight, bit) => sum + ((n >> bit) & 1) * weight, 0).toString(16)).join('');
}
const canonicalAlphabet = primeMode ? subsetAlphabet(primeWeights) : seenHex + missing;
const canonicalTokenOrder = unique(parsed);
const canonicalCandidate = parsed.map(t => canonicalAlphabet[canonicalTokenOrder.indexOf(t)]).join('');

// Declare the complete finite family before testing the unknown ciphertexts.
const spec = {
  source_sha256: sha(fs.readFileSync(__filename)).toString('hex'),
  inputs_sha256: sha(inputBytes).toString('hex'),
  hypothesis: primeMode ? 'Blue prime positions have digital roots 8,2,1,4, exactly four binary place weights. Their subset sums supply the hexadecimal substitution alphabet for DBBI prefix tokens.' : 'Order of first distinct hex digits in blue cell indices supplies a substitution alphabet for DBBI prefix tokens.',
  status: 'Hypothesis; neither the b/g parse nor this alphabet operation is creator-confirmed.',
  canonical: {blueHex, seenHex, missing, bluePrimes, primeWeights, alphabet: canonicalAlphabet, tokenOrder: canonicalTokenOrder, candidate: canonicalCandidate},
  variants: {
    alphabet_construction: primeMode ? 'All 24 permutations of weights 8,2,1,4; enumerate subsets by binary masks 0..15. Canonical first weight is least significant mask bit. Permutations cover either mask bit orientation.' : 'First distinct hex digits of blue indices; three traversals (row/column/known URL spiral), forward/backward, row-major numbering 0/1-based; append/prepend missing digits in 0..f order.',
    token_order: ['first occurrence', 'lexicographic', 'single symbols then pairs, lexicographic'],
    token_traversal: ['forward', 'backward'],
    password_forms: ['hex lowercase', 'hex uppercase', 'raw 32 bytes', 'sha256hex of each preceding form'],
    key_tests: ['raw mapped 32 bytes', 'reversed mapped bytes', 'sha256 of every password'],
    aes: 'All three original blobs, AES-256-CBC, EVP_BytesToKey SHA256 and MD5. No invented IV or derived ciphertext.',
  },
  acceptance: 'Exact prize public key (or its negation, invertible), or independently verifiable complete plaintext. Padding/printable ratio are triage only.',
};
fs.mkdirSync(out, {recursive: true});
fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');

// Real earlier-stage control plus binary known-answer controls for both KDFs.
const known = Buffer.from(data.phase32_control_b64, 'base64');
const control = {salt: known.subarray(8, 16).toString('hex'), ciphertext: known.subarray(16).toString('hex')};
assert(decrypt(Buffer.from(data.phase32_control_password), control, 'sha256').toString().startsWith("I've been waiting for you."));
assert.equal(decrypt(Buffer.from(data.phase32_control_password), control, 'md5'), null);
for (const hash of ['sha256', 'md5']) for (const length of [1, 16, 64, 79, 1312, 1327]) {
  const password = Buffer.from('binary known-answer control'), salt = Buffer.from('0011223344556677', 'hex');
  const plaintext = Buffer.from(Array.from({length}, (_, i) => (131 * i + 17) % 256));
  const [key, iv] = evp(password, salt, hash);
  const enc = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ciphertext = Buffer.concat([enc.update(plaintext), enc.final()]);
  assert.deepEqual(decrypt(password, {salt: salt.toString('hex'), ciphertext: ciphertext.toString('hex')}, hash), plaintext);
}
const testScalar = Buffer.alloc(32); testScalar[31] = 1;
const check = crypto.createECDH('secp256k1'); check.setPrivateKey(testScalar);
assert.equal(check.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');

const orders = {
  row: rowBlue,
  column: [...blue].sort((a, b) => a[3] - b[3] || a[2] - b[2]),
  spiral: [...blue].sort((a, b) => a[0] - b[0]),
};
const tokenOrders = {
  first: unique(parsed),
  lex: unique(parsed).sort(),
  checkerboard: unique(parsed).sort((a, b) => a.length - b.length || (a < b ? -1 : a > b ? 1 : 0)),
};
const candidates = new Map(), mappingRecords = [];
if (primeMode) {
  function permutations(xs) {
    return xs.length ? xs.flatMap((x, i) => permutations(xs.filter((_, j) => i !== j)).map(rest => [x, ...rest])) : [[]];
  }
  for (const weights of permutations(primeWeights)) {
    const alphabet = subsetAlphabet(weights);
    assert.equal(unique(alphabet).length, 16);
    for (const [tname, order] of Object.entries(tokenOrders)) for (const tokenReverse of [false, true]) {
      const candidate = (tokenReverse ? [...parsed].reverse() : parsed).map(t => alphabet[order.indexOf(t)]).join('');
      const label = `prime-bits:${weights.join(',')}/tokens:${tname}/reverse:${tokenReverse}`;
      mappingRecords.push({label, weights, alphabet, tokenOrder: order, candidate});
      if (!candidates.has(candidate)) candidates.set(candidate, label);
    }
  }
} else for (const [oname, cells] of Object.entries(orders)) for (const reverse of [false, true]) for (const base of [1, 0]) {
  const positions = (reverse ? [...cells].reverse() : cells).map(x => x[2] * 14 + x[3] + base);
  const digits = unique(Buffer.from(positions).toString('hex')).join('');
  const absent = [...hex].filter(c => !digits.includes(c)).join('');
  for (const completion of ['append', 'prepend']) {
    const alphabet = completion === 'append' ? digits + absent : absent + digits;
    assert.equal(unique(alphabet).length, 16);
    for (const [tname, order] of Object.entries(tokenOrders)) for (const tokenReverse of [false, true]) {
      const candidate = (tokenReverse ? [...parsed].reverse() : parsed).map(t => alphabet[order.indexOf(t)]).join('');
      const label = `${oname}/reverse:${reverse}/base:${base}/${completion}/tokens:${tname}/reverse:${tokenReverse}`;
      mappingRecords.push({label, positions, alphabet, tokenOrder: order, candidate});
      if (!candidates.has(candidate)) candidates.set(candidate, label);
    }
  }
}
assert(candidates.has(canonicalCandidate));
const passwords = new Map(), keys = new Map();
function addPassword(label, bytes) {
  const h = bytes.toString('hex'); if (!passwords.has(h)) passwords.set(h, {label, bytes});
}
function addKey(label, bytes) {
  const h = bytes.toString('hex'); if (!keys.has(h)) keys.set(h, {label, bytes});
}
for (const [candidate, label] of candidates) {
  const raw = Buffer.from(candidate, 'hex');
  addKey(label + '/raw', raw); addKey(label + '/bytes-reversed', Buffer.from(raw).reverse());
  for (const [form, bytes] of [['hex', Buffer.from(candidate)], ['HEX', Buffer.from(candidate.toUpperCase())], ['raw', raw]]) {
    addPassword(label + '/' + form, bytes);
    addPassword(label + '/sha256hex/' + form, Buffer.from(sha(bytes).toString('hex')));
  }
}
for (const {label, bytes} of passwords.values()) addKey(label + '/sha256', sha(bytes));
const keyHits = [];
for (const {label, bytes} of keys.values()) {
  const match = classifyKey(bytes); if (match) keyHits.push({label, match, key: bytes.toString('hex')});
}
const padding = []; let attempts = 0;
for (const [passwordHex, {label, bytes}] of passwords) for (const [blob, value] of Object.entries(data.blobs)) for (const kdf of ['sha256', 'md5']) {
  attempts++;
  const plaintext = decrypt(bytes, value, kdf); if (plaintext === null) continue;
  const ascii = [...plaintext].filter(x => x === 9 || x === 10 || x === 13 || x >= 32 && x <= 126).length / plaintext.length;
  padding.push({label, passwordHex, blob, kdf, length: plaintext.length, ascii, plaintextHex: plaintext.toString('hex')});
}
fs.writeFileSync(path.join(out, 'mappings.jsonl'), mappingRecords.map(x => JSON.stringify(x)).join('\n') + '\n');
fs.writeFileSync(path.join(out, 'passwords.jsonl'), [...passwords].map(([passwordHex, {label}]) => JSON.stringify({label, passwordHex})).join('\n') + '\n');
fs.writeFileSync(path.join(out, 'keys.jsonl'), [...keys].map(([keyHex, {label}]) => JSON.stringify({label, keyHex})).join('\n') + '\n');
fs.writeFileSync(path.join(out, 'padding_results.jsonl'), padding.map(x => JSON.stringify(x)).join('\n') + (padding.length ? '\n' : ''));
const summary = {
  canonical: spec.canonical, mappingVariants: mappingRecords.length, distinctMappedHashes: candidates.size,
  passwords: passwords.size, keyCandidates: keys.size, attempts, padding: padding.length,
  expectedRandomPadding: attempts / 255, maxAscii: Math.max(0, ...padding.map(x => x.ascii)),
  textTriage: padding.filter(x => x.ascii >= .85).length, keyHits,
  controls: 'Real phase 3.2 + 12 binary AES round trips + scalar 1 public key',
  limitation: 'Negative is limited to these declared mappings and encodings. Full plaintext window/hex/WIF key checks are recorded separately.',
};
fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify(summary, null, 2));
