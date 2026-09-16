'use strict';
// Language-selected DBBI sample under the all-nine optional-zero relaxation.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_codepoints_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest();
const read = f => JSON.parse(fs.readFileSync(path.join(out, f)));
const lines = f => fs.readFileSync(path.join(out, f), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
function main() {
  assert(read('verification.json').complete && read('keyformat_verification.json').complete);
  assert(!fs.existsSync(path.join(out, 'candidate_auth.json')), 'Inspect completed oracles before restarting');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw);
  const candidates = read('selected_candidates.json').candidates.map(r => r.hex);
  const materials = new Map(), passwords = new Map(), scalars = new Set();
  function scalar(bytes) { assert.equal(bytes.length, 32); scalars.add(bytes.toString('hex')); scalars.add(Buffer.from(bytes).reverse().toString('hex')); }
  function windows(bytes) { for (let i = 0; i + 32 <= bytes.length; i++) scalar(bytes.subarray(i, i + 32)); }
  for (const [candidate, hex] of candidates.entries()) {
    const text = Buffer.from(hex, 'hex').toString('ascii');
    for (const [form, value] of [['raw', text], ['lowercase', text.toLowerCase()], ['uppercase', text.toUpperCase()], ['withoutWhitespace', text.replace(/\s/g, '')], ['joinedLowercase', text.replace(/\s/g, '').toLowerCase()]]) {
      const bytes = Buffer.from(value, 'ascii'), key = bytes.toString('hex'); if (!materials.has(key)) materials.set(key, { id: materials.size, candidate, form, hex: key });
    }
  }
  for (const m of materials.values()) {
    const bytes = Buffer.from(m.hex, 'hex'); windows(bytes);
    for (const [form, p] of [['direct', bytes], ['sha256-hex', Buffer.from(hash(bytes).toString('hex'))]]) { const hex = p.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, material: m.id, form, hex }); }
  }
  const control = Buffer.from(input.phase32_control_b64, 'base64');
  assert.equal(hash(open(Buffer.from(input.phase32_control_password), { salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex') }, 'sha256')).toString('hex'), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = []; let maxPrintable = 0;
  for (const p of passwords.values()) {
    const password = Buffer.from(p.hex, 'hex'); scalar(hash(password));
    for (const [name, blob] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
      const plain = open(password, blob, digest); flags.push(Number(plain !== null)); if (plain === null) continue;
      const fraction = [...plain].filter(c => c >= 32 && c <= 126 || c === 9 || c === 10 || c === 13).length / plain.length;
      padding.push({ password: p.id, blob: name, digest, plaintextHex: plain.toString('hex'), printable: fraction }); maxPrintable = Math.max(maxPrintable, fraction); scalar(hash(plain)); windows(plain);
    }
  }
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const valid = [...scalars].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < n).sort(), ec = crypto.createECDH('secp256k1'), matches = [];
  ec.setPrivateKey(Buffer.from('0'.repeat(63) + '1', 'hex')); assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(crypto.createHash('ripemd160').update(hash(Buffer.from(input.target_pubkey, 'hex'))).digest('hex'), input.target_h160);
  for (const [i, h] of valid.entries()) { ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ hex: h, exact: pub === input.target_pubkey }); if (i && i % 50000 === 0) console.log(JSON.stringify({ checkedScalars: i, total: valid.length })); }
  const result = { complete: true, scope: 'Only saved language-optimal DBBI witnesses from broad and common-word filters, deduplicated. Five case/spacing forms, direct and SHA256-hex passwords, three blobs, EVP-SHA256 and MD5. SHA256(password), material 32-byte windows and SHA256/windows of PKCS7 bodies in both byte orders. This is a sample of parse paths; zero hits does not exclude untested paths.', inputSHA256: hash(inputRaw).toString('hex'), sourceSHA256: hash(fs.readFileSync(__filename)).toString('hex'), candidates, materials: [...materials.values()], passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable, scalars: valid.length, scalarStreamSHA256: hash(Buffer.concat(valid.map(h => Buffer.from(h, 'hex')))).toString('hex'), matches };
  fs.writeFileSync(path.join(out, 'candidate_auth.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ candidates: candidates.length, materials: materials.size, passwords: passwords.size, attempts: flags.length, paddings: padding.length, maxPrintable, scalars: valid.length, matches }));
}
if (require.main === module) main();
