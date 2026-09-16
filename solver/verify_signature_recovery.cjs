'use strict';
// Check the corrected recovery records with Node/OpenSSL and the raw transactions.
// This verifies the bounded message list; it does not identify the sender.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/signature_audit_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest(), hash = b => sha(b).toString('hex'), sha2 = b => sha(sha(b));
function compact(n) {
  if (n < 253) return Buffer.from([n]);
  if (n <= 65535) {const b = Buffer.alloc(3); b[0] = 253; b.writeUInt16LE(n, 1); return b;}
  throw new Error('Unexpected size in these archived transactions or candidate messages');
}
function txOutputs(raw, expected) {
  let pos = 4; const version = raw.subarray(0, 4), segwit = raw[pos] === 0 && raw[pos + 1] === 1;
  if (segwit) pos += 2;
  function size() {const n = raw[pos++]; if (n < 253) return n; assert.equal(n, 253); const v = raw.readUInt16LE(pos); pos += 2; return v;}
  const startInputs = pos, inputCount = size();
  for (let i = 0; i < inputCount; i++) {pos += 36; const length = size(); pos += length + 4;}
  const endInputs = pos, startOutputs = pos, outputCount = size(), scripts = [];
  for (let i = 0; i < outputCount; i++) {pos += 8; const length = size(); scripts.push(raw.subarray(pos, pos + length)); pos += length;}
  const endOutputs = pos;
  if (segwit) for (let i = 0; i < inputCount; i++) {const items = size(); for (let j = 0; j < items; j++) {const length = size(); pos += length;}}
  const lock = raw.subarray(pos, pos + 4); pos += 4; assert.equal(pos, raw.length);
  const stripped = Buffer.concat([version, raw.subarray(startInputs, endInputs), raw.subarray(startOutputs, endOutputs), lock]);
  assert.equal(Buffer.from(sha2(stripped)).reverse().toString('hex'), expected); return scripts;
}
function address(pub) {
  const body = Buffer.concat([Buffer.from([0]), crypto.createHash('ripemd160').update(sha(pub)).digest()]);
  const bytes = Buffer.concat([body, sha2(body).subarray(0, 4)]), alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt('0x' + bytes.toString('hex')), encoded = '';
  while (n) {encoded = alphabet[Number(n % 58n)] + encoded; n /= 58n;}
  let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  return '1'.repeat(zeros) + encoded;
}
function derSignature(rs) {
  const ints = [rs.subarray(0, 32), rs.subarray(32)].map(value => {
    let start = 0; while (start < value.length - 1 && value[start] === 0) start++;
    let v = value.subarray(start); if (v[0] & 128) v = Buffer.concat([Buffer.from([0]), v]);
    return Buffer.concat([Buffer.from([2, v.length]), v]);
  });
  const body = Buffer.concat(ints); return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
function main() {
  const read = file => JSON.parse(fs.readFileSync(path.join(out, file), 'utf8'));
  const manifest = read('verification.json'), cases = read('recovery_cases.json'), messages = read('messages.json'), sigs = {};
  assert.equal(hash(fs.readFileSync(path.join(out, 'messages.json'))), manifest.messagesSHA256);
  assert.equal(hash(fs.readFileSync(path.join(out, 'recovery_cases.json'))), manifest.casesSHA256);
  assert.equal(hash(fs.readFileSync(path.join(root, 'solver/gsmg_sig_recover.py'))), manifest.oldScriptSHA256);
  for (const t of manifest.transactions) {
    const raw = Buffer.from(fs.readFileSync(path.join(out, t.txid + '.hex'), 'utf8').trim(), 'hex'); assert.equal(hash(raw), t.rawSHA256);
    const scripts = txOutputs(raw, t.txid), json = read(t.txid + '.json'); assert.deepEqual(scripts.map(b => b.toString('hex')), json.vout.map(v => v.scriptpubkey));
    for (const script of scripts) if (script[0] === 106) {
      assert.equal(script[1], 71); assert.equal(script.length, 73);
      const name = script.subarray(2, 8).toString('ascii'), sig = script.subarray(8); assert.equal(sig.length, 65);
      assert.equal(sig.toString('hex'), manifest.payloads[name]); sigs[name] = sig;
    }
  }
  const seen = new Set(), interesting = new Set(['1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe', '1GSMG9VDLTU6jyuG7bkNMdmnHBLtbbM51M', '1GSMG1ABC95GES4k9UZCLtz6CYCUL8LUV2', '3GSMG24TujqfMJG1kQoBX18DzJHQLeJYMK']);
  let verified = 0, failures = 0, actualHeader = 0; const hits = [];
  for (const r of cases) {
    const sig = sigs[r.payload]; assert(sig); assert(Number.isInteger(r.message) && r.message >= 0 && r.message < messages.length);
    assert(Number.isInteger(r.header) && r.header >= 27 && r.header <= 34);
    const id = [r.payload, r.message, r.header].join('/'); assert(!seen.has(id)); seen.add(id);
    assert.equal(r.actualHeader, r.header === sig[0]); assert.equal(r.compressed, r.header >= 31); assert.equal(r.recid, (r.header - 27) & 3);
    if (!r.recovered) {
      // For recid 2/3, R.x is r+n, which exceeds the field prime here.
      const curveOrder = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
      const fieldPrime = (1n << 256n) - (1n << 32n) - 977n;
      assert(r.recid >= 2 && BigInt('0x' + sig.subarray(1, 33).toString('hex')) + curveOrder >= fieldPrime); failures++; continue;
    }
    const pub = Buffer.from(r.pubkey, 'hex'); assert.equal(pub.length, r.compressed ? 33 : 65); assert.equal(address(pub), r.address);
    const uncompressed = crypto.ECDH.convertKey(pub, 'secp256k1', undefined, undefined, 'uncompressed');
    const spki = Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex'), uncompressed]);
    const key = crypto.createPublicKey({key: spki, format: 'der', type: 'spki'}), message = Buffer.from(messages[r.message]);
    const payload = Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), compact(message.length), message]);
    assert(crypto.verify('sha256', sha(payload), key, derSignature(sig.subarray(1)))); verified++;
    if (r.actualHeader) actualHeader++;
    if (interesting.has(r.address)) hits.push(id);
  }
  assert.equal(seen.size, 2 * messages.length * 8); assert.equal(verified, manifest.recoveredAndIndependentlyVerified); assert.equal(failures, manifest.recoveryFailures);
  assert.equal(actualHeader, manifest.actualHeaderRecoveries); assert.deepEqual(hits, []); assert.deepEqual(manifest.interestingAddressHits, []);
  const result = {verifiedAt: new Date().toISOString(), sourceSHA256: hash(fs.readFileSync(__filename)), manifestSHA256: hash(fs.readFileSync(path.join(out, 'verification.json'))),
    transactionIdentitiesVerified: manifest.transactions.length, candidateMessages: messages.length, configurations: cases.length,
    signaturesVerifiedWithOpenSSL: verified, impossibleRecoveryBranchesProved: failures, actualHeaderRecoveries: actualHeader,
    allAddressesRecomputed: true, interestingAddressHits: hits, finalPasswordFound: false};
  fs.writeFileSync(path.join(out, 'openssl_verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
