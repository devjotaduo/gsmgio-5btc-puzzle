'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_integer_2026-09-16');
const digest = b => crypto.createHash('sha256').update(b).digest(), sha = b => digest(b).toString('hex');
function main() {
  assert(!fs.existsSync(path.join(out, 'oracles.json')), 'Inspect existing results before rerunning');
  const input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')));
  const raw = fs.readFileSync(path.join(out, 'candidates.json')), candidates = JSON.parse(raw), materials = new Map(), passwords = new Map();
  const clauses = ['', 'reinsertingtheprimebasicsafterwhichyouwillberequiredto', 'sheisgoingtodieandthereisnothingyoucandotostopit'];
  for (const c of candidates) for (const reverseBytes of [false, true]) for (const [clause, suffix] of clauses.entries()) {
    const b = Buffer.from(c.hex, 'hex'); if (reverseBytes) b.reverse();
    const material = Buffer.concat([b, Buffer.from(suffix)]), hex = material.toString('hex');
    if (!materials.has(hex)) materials.set(hex, { id: materials.size, candidate: c.id, reverseBytes, clause, hex });
  }
  for (const m of materials.values()) {
    const b = Buffer.from(m.hex, 'hex');
    for (const [form, pw] of [['direct', b], ['sha256-hex', Buffer.from(sha(b))]]) {
      const hex = pw.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, material: m.id, form, hex });
    }
  }
  const ctrl = Buffer.from(input.phase32_control_b64, 'base64');
  assert.equal(sha(open(Buffer.from(input.phase32_control_password), { salt: ctrl.subarray(8, 16).toString('hex'), ciphertext: ctrl.subarray(16).toString('hex') }, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = [], scalars = new Set();
  for (const p of passwords.values()) {
    const pw = Buffer.from(p.hex, 'hex'); scalars.add(sha(pw));
    for (const [name, blob] of Object.entries(input.blobs)) for (const kdf of ['sha256', 'md5']) {
      const b = open(pw, blob, kdf); flags.push(Number(b !== null)); if (b === null) continue;
      const printable = [...b].filter(x => x >= 32 && x <= 126 || [9, 10, 13].includes(x)).length / b.length;
      padding.push({ password: p.id, blob: name, kdf, plaintextHex: b.toString('hex'), printable });
      if (b.length === 32) scalars.add(b.toString('hex'));
      if (/^[0-9a-fA-F]{64}$/.test(b.toString())) scalars.add(b.toString().toLowerCase());
    }
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, list = [...scalars].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort();
  const ec = crypto.createECDH('secp256k1'), matches = [];
  ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex')); assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(crypto.createHash('ripemd160').update(digest(Buffer.from(input.target_pubkey, 'hex'))).digest('hex'), input.target_h160);
  for (const h of list) { ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ scalar: h, exact: pub === input.target_pubkey }); }
  const result = { complete: true, scope: 'All42 candidates from the20 completed alphabet models, original or reversed byte order, alone or with one of two preselected last-word clauses. Direct and SHA256-hex passwords, three original blobs with EVP-SHA256/MD5. SHA256(password), plus whole32-byte/64-hex padding bodies as scalars. The22,858 candidates of the separate partial full-ASCII pilot are NOT covered.', clauses, candidatesSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), materials: [...materials.values()], passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable: Math.max(0, ...padding.map(x => x.printable)), scalars: list.length, scalarStreamSHA256: sha(Buffer.concat(list.map(h => Buffer.from(h, 'hex')))), matches };
  fs.writeFileSync(path.join(out, 'oracles.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ candidates: candidates.length, materials: materials.size, passwords: passwords.size, attempts: flags.length, padding: padding.length, maxPrintable: result.maxPrintable, scalars: list.length, matches }));
}
if (require.main === module) main();
