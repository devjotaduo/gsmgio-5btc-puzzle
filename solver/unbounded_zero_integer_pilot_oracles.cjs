'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/unbounded_zero_integer_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function main() {
  assert(!fs.existsSync(path.join(folder, 'pilot_oracles.json')), 'Inspect existing pilot authentication before rerunning');
  const input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), inputs = [], candidates = new Map(), passwords = new Map();
  for (const name of ['printable_pilot.json', 'lowercase_digits_pilot.json.gz']) {
    const raw = fs.readFileSync(path.join(folder, name)), data = JSON.parse(name.endsWith('.gz') ? zlib.gunzipSync(raw) : raw);
    inputs.push({ name, SHA256: sha(raw), searchComplete: data.complete, hits: data.hits.length });
    for (const h of data.hits) if (!candidates.has(h.hex)) candidates.set(h.hex, { hex: h.hex, origin: name });
  }
  for (const c of candidates.values()) for (const [form, pw] of [['direct', Buffer.from(c.hex, 'hex')], ['sha256-hex', Buffer.from(sha(Buffer.from(c.hex, 'hex')))]]) {
    const hex = pw.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, candidateHex: c.hex, form, hex });
  }
  const ctrl = Buffer.from(input.phase32_control_b64, 'base64');
  assert.equal(sha(open(Buffer.from(input.phase32_control_password), { salt: ctrl.subarray(8, 16).toString('hex'), ciphertext: ctrl.subarray(16).toString('hex') }, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = [], scalars = new Set();
  for (const p of passwords.values()) {
    const pw = Buffer.from(p.hex, 'hex'); scalars.add(sha(pw));
    for (const [blob, data] of Object.entries(input.blobs)) for (const kdf of ['sha256', 'md5']) {
      const b = open(pw, data, kdf); flags.push(Number(b !== null)); if (b === null) continue;
      const printable = [...b].filter(c => c >= 32 && c <= 126 || [9, 10, 13].includes(c)).length / b.length;
      padding.push({ password: p.id, blob, kdf, hex: b.toString('hex'), printable });
      if (b.length === 32) scalars.add(b.toString('hex'));
      if (/^[0-9a-fA-F]{64}$/.test(b.toString())) scalars.add(b.toString().toLowerCase());
    }
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, values = [...scalars].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort(), matches = [], ec = crypto.createECDH('secp256k1');
  ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex')); assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  for (const h of values) { ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ hex: h, exact: pub === input.target_pubkey }); }
  const result = { complete: true, scope: 'Every candidate FOUND in the two partial all-zeroable-integer pilots, direct and SHA256-hex; three original blobs, EVP-SHA256/MD5; SHA256(password) and complete32-byte/64-hex bodies as scalars. Does not complete either pilot or cover remaining masks, reversal, appended words or other password forms.', inputs, sourceSHA256: sha(fs.readFileSync(__filename)), candidates: candidates.size, passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable: Math.max(0, ...padding.map(x => x.printable)), scalars: values.length, scalarStreamSHA256: sha(Buffer.concat(values.map(h => Buffer.from(h, 'hex')))), matches };
  fs.writeFileSync(path.join(folder, 'pilot_oracles.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ candidates: candidates.size, passwords: passwords.size, attempts: flags.length, padding: padding.length, scalars: values.length, maxPrintable: result.maxPrintable, matches }));
}
if (require.main === module) main();
