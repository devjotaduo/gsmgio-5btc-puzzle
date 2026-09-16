'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/unbounded_integer_words_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function main() {
  assert(!fs.existsSync(path.join(folder, 'oracles.json')), 'Inspect existing authentication before rerunning');
  const input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), inputs = [], candidates = new Map(), passwords = new Map();
  for (const name of ['candidates.json', 'wordcase_candidates.json', 'resume_candidates.json']) {
    const raw = fs.readFileSync(path.join(folder, name)), data = JSON.parse(raw); inputs.push({ name, SHA256: sha(raw), rows: data.length });
    for (const c of data) if (!candidates.has(c.hex)) candidates.set(c.hex, { hex: c.hex, origin: name });
  }
  for (const c of candidates.values()) for (const [form, pw] of [['direct', Buffer.from(c.hex, 'hex')], ['sha256-hex', Buffer.from(sha(Buffer.from(c.hex, 'hex')))]]) {
    const hex = pw.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, candidateHex: c.hex, form, hex });
  }
  const ctrl = Buffer.from(input.phase32_control_b64, 'base64');
  assert.equal(sha(open(Buffer.from(input.phase32_control_password), { salt: ctrl.subarray(8, 16).toString('hex'), ciphertext: ctrl.subarray(16).toString('hex') }, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = [], scalars = new Set(); let processed = 0;
  for (const p of passwords.values()) {
    const pw = Buffer.from(p.hex, 'hex'); scalars.add(sha(pw));
    for (const [blob, data] of Object.entries(input.blobs)) for (const kdf of ['sha256', 'md5']) {
      const b = open(pw, data, kdf); flags.push(Number(b !== null)); if (b === null) continue;
      const printable = [...b].filter(c => c >= 32 && c <= 126 || [9, 10, 13].includes(c)).length / b.length;
      padding.push({ password: p.id, blob, kdf, hex: b.toString('hex'), printable });
      if (b.length === 32) scalars.add(b.toString('hex'));
      if (/^[0-9a-fA-F]{64}$/.test(b.toString())) scalars.add(b.toString().toLowerCase());
    }
    processed++; if (processed % 50000 === 0) console.log(JSON.stringify({ stage: 'AES', passwords: processed }));
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, values = [...scalars].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort(), matches = [], ec = crypto.createECDH('secp256k1');
  ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex')); assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  processed = 0;
  for (const h of values) {
    ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ hex: h, exact: pub === input.target_pubkey });
    processed++; if (processed % 50000 === 0) console.log(JSON.stringify({ stage: 'secp256k1', scalars: processed }));
  }
  const result = { complete: true, scope: 'All candidates FOUND by the sixteen dictionary/integer models and two continuations. Direct and SHA256-hex password forms only, three original AES blobs with EVP-SHA256/MD5. Scalars: SHA256(password), complete32-byte or64-hex padding bodies. Pending search masks, reversal of decoded bytes, appended words and other forms are not exhausted.', inputs, sourceSHA256: sha(fs.readFileSync(__filename)), candidates: candidates.size, passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable: Math.max(0, ...padding.map(x => x.printable)), scalars: values.length, scalarStreamSHA256: sha(Buffer.concat(values.map(h => Buffer.from(h, 'hex')))), matches };
  fs.writeFileSync(path.join(folder, 'oracles.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ candidates: candidates.size, passwords: passwords.size, attempts: flags.length, padding: padding.length, scalars: values.length, maxPrintable: result.maxPrintable, matches }));
}
if (require.main === module) main();
