'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const { checkWitness } = require('./verify_rsa_substituted_digits.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/rsa_substituted_digits_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest(), read = f => JSON.parse(fs.readFileSync(path.join(out, f))), lines = f => fs.readFileSync(path.join(out, f), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
function main() {
  const summary = read('summary.json'), verifier = read('verification.json'); assert(summary.complete && verifier.complete);
  assert(!fs.existsSync(path.join(out, 'candidate_auth.json')), 'Inspect completed authentication first');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), cases = lines('cases.jsonl'), independent = lines('verification_cases.jsonl'), followups = [...lines('letters_followup.jsonl'), ...lines('ascii_followup.jsonl')];
  assert.equal(cases.length, summary.decisions); assert.equal(independent.length, cases.length);
  const perIndex = new Map(), certificate = new Set(read('pair_capacity_certificate.json').affectedModelIndexes), candidates = new Map();
  for (const r of followups) { if (!perIndex.has(r.index)) perIndex.set(r.index, []); perIndex.get(r.index).push(r); }
  const tally = {}, pending = [], unverifiedNegatives = [], consolidatedFd = fs.openSync(path.join(out, 'consolidated.jsonl'), 'wx');
  let checkedWitnesses = 0;
  for (const [index, r] of cases.entries()) {
    const v = independent[index]; assert.equal(v.index, index);
    const records = [r, v, ...(perIndex.get(index) || [])], hasYes = records.some(x => x.status === 'compatible'), hasNo = certificate.has(index) || records.some(x => x.status === 'excluded');
    assert(!(hasYes && hasNo), 'Conflicting evidence at ' + index);
    const verifiedNo = certificate.has(index) || v.status === 'excluded';
    const status = hasYes ? 'compatible' : verifiedNo ? 'excluded-verified' : hasNo ? 'excluded-producer-only' : 'unknown-cap';
    if (status === 'unknown-cap') pending.push(index); if (status === 'excluded-producer-only') unverifiedNegatives.push(index);
    const key = r.mode + '/' + status; tally[key] = (tally[key] || 0) + 1;
    fs.writeSync(consolidatedFd, JSON.stringify({ index, status, witnessSources: records.flatMap((x, j) => x.witness ? [j] : []) }) + '\n');
    for (const [j, x] of records.entries()) if (x.witness) {
      const source = r.reverse ? [...input[r.field]].reverse().join('') : input[r.field]; checkWitness(r, source, x.witness); checkedWitnesses++;
      const hex = x.witness.hex; if (!candidates.has(hex)) candidates.set(hex, { id: candidates.size, index, witnessSource: j, hex });
    }
  }
  fs.closeSync(consolidatedFd);
  const consolidation = { complete: true, decisions: cases.length, tally, pendingIndexes: pending, producerOnlyNegativeIndexes: unverifiedNegatives, checkedWitnesses, candidates: candidates.size, sources: Object.fromEntries(['cases.jsonl', 'verification_cases.jsonl', 'letters_followup.jsonl', 'ascii_followup.jsonl', 'pair_capacity_certificate.json'].map(f => [f, hash(fs.readFileSync(path.join(out, f))).toString('hex')])) };
  fs.writeFileSync(path.join(out, 'consolidation.json'), JSON.stringify(consolidation, null, 2) + '\n');
  const control = Buffer.from(input.phase32_control_b64, 'base64');
  assert.equal(hash(open(Buffer.from(input.phase32_control_password), { salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex') }, 'sha256')).toString('hex'), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const passwords = new Map(), scalars = new Set(), padding = [], flags = [];
  function scalar(bytes) { assert.equal(bytes.length, 32); scalars.add(bytes.toString('hex')); scalars.add(Buffer.from(bytes).reverse().toString('hex')); }
  for (const c of candidates.values()) {
    const bytes = Buffer.from(c.hex, 'hex'), h = hash(bytes); scalar(h);
    for (const [form, p] of [['raw', bytes], ['sha256-hex', Buffer.from(h.toString('hex'))]]) {
      const hex = p.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, candidate: c.id, form, hex });
    }
  }
  let maxPrintable = 0;
  for (const p of passwords.values()) for (const [name, blob] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
    const plain = open(Buffer.from(p.hex, 'hex'), blob, digest); flags.push(Number(plain !== null)); if (plain === null) continue;
    const fraction = [...plain].filter(v => v >= 32 && v <= 126 || v === 9 || v === 10 || v === 13).length / plain.length;
    padding.push({ password: p.id, blob: name, digest, plaintextHex: plain.toString('hex'), printable: fraction }); maxPrintable = Math.max(maxPrintable, fraction); scalar(hash(plain));
    for (let at = 0; at + 32 <= plain.length; at++) scalar(plain.subarray(at, at + 32));
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, valid = [...scalars].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort(), ec = crypto.createECDH('secp256k1'), hits = [];
  for (const h of valid) { ec.setPrivateKey(Buffer.from(h, 'hex')); const pub = ec.getPublicKey('hex', 'uncompressed'); if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) hits.push({ hex: h, exact: pub === input.target_pubkey }); }
  const result = { complete: true, inputSHA256: hash(inputRaw).toString('hex'), sourceSHA256: hash(fs.readFileSync(__filename)).toString('hex'), candidates: [...candidates.values()], passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, maxPrintable, distinctScalars: valid.length, scalarStreamSHA256: hash(Buffer.concat(valid.map(h => Buffer.from(h, 'hex')))).toString('hex'), hits, scope: 'Only saved compatible witnesses; raw and SHA256-hex passwords, three blobs, two EVP digests. SHA256 of candidates and padded outputs plus all32-byte padded-output windows, in both byte orders. Neither grammar compatibility nor PKCS7 authenticates a solution.' };
  fs.writeFileSync(path.join(out, 'candidate_auth.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ consolidation: { ...consolidation, pendingIndexes: pending.length, producerOnlyNegativeIndexes: unverifiedNegatives.length }, candidates: candidates.size, passwords: passwords.size, attempts: flags.length, paddings: padding.length, maxPrintable, scalars: valid.length, hits }));
}
main();
