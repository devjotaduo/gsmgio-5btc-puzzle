'use strict';
// Reconstruct legacy SIGHASH_ALL from raw prize-address transactions.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), sha = b => crypto.createHash('sha256').update(b).digest();
const hex = b => b.toString('hex'), sha2 = b => sha(sha(b));

function compact(n) {
  assert(Number.isSafeInteger(n) && n >= 0 && n <= 65535);
  if (n < 253) return Buffer.from([n]);
  const b = Buffer.alloc(3); b[0] = 253; b.writeUInt16LE(n, 1); return b;
}
function parse(raw) {
  let pos = 0;
  function take(n) { assert(pos + n <= raw.length); const b = raw.subarray(pos, pos + n); pos += n; return b; }
  function size() { const b = take(1)[0]; if (b < 253) return b; assert.equal(b, 253); const n = take(2).readUInt16LE(); assert(n >= 253); return n; }
  const version = take(4), inputs = [], count = size(); assert(count > 0, 'This parser expects legacy transactions.');
  for (let i = 0; i < count; i++) { const outpoint = take(36), script = take(size()), sequence = take(4); inputs.push({outpoint, script, sequence}); }
  const outputStart = pos, outputCount = size(), outputs = [];
  for (let i = 0; i < outputCount; i++) { const value = take(8), script = take(size()); outputs.push({value, script}); }
  const outputsRaw = raw.subarray(outputStart, pos), locktime = take(4); assert.equal(pos, raw.length);
  return {version, inputs, outputs, outputsRaw, locktime};
}
function signature(script) {
  let pos = 0;
  function push() { const n = script[pos++]; assert(n > 0 && n <= 75 && pos + n <= script.length); const b = script.subarray(pos, pos + n); pos += n; return b; }
  const sig = push(), pub = push(); assert.equal(pos, script.length); assert.equal(pub.length, 65); assert.equal(pub[0], 4);
  const der = sig.subarray(0, -1); assert.equal(sig.at(-1), 1, 'Only SIGHASH_ALL is accepted.');
  assert.equal(der[0], 0x30); assert.equal(der[1], der.length - 2); let dp = 2;
  function integer() {
    assert.equal(der[dp++], 2); const len = der[dp++]; assert(len > 0 && dp + len <= der.length);
    const value = der.subarray(dp, dp + len); dp += len;
    assert(!(value[0] & 128)); assert(value.length === 1 || value[0] !== 0 || (value[1] & 128));
    const n = BigInt('0x' + hex(value)); assert(n > 0n && n < BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'));
    return n.toString(16).padStart(64, '0');
  }
  const r = integer(), s = integer(); assert.equal(dp, der.length); return {der, pub, r, s};
}
function preimage(tx, index, scriptCode) {
  const inputs = tx.inputs.map((vin, i) => {
    const script = i === index ? scriptCode : Buffer.alloc(0);
    return Buffer.concat([vin.outpoint, compact(script.length), script, vin.sequence]);
  });
  return Buffer.concat([tx.version, compact(inputs.length), ...inputs, tx.outputsRaw, tx.locktime, Buffer.from('01000000', 'hex')]);
}
function main() {
  const src = path.resolve(process.argv[2] || path.join(root, '_work/prize_nonce_2026-09-17'));
  const out = path.resolve(process.argv[3] || path.join(src, 'inputs'));
  assert(!fs.existsSync(out), 'Use a fresh output directory.'); fs.mkdirSync(out, {recursive: true});
  const save = (f, data) => fs.writeFileSync(path.join(out, f), JSON.stringify(data, null, 2) + '\n', {flag: 'wx'});
  const canonical = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')));
  const records = JSON.parse(fs.readFileSync(path.join(src, 'spending_verified.json'))), signatures = [], transactions = [];
  for (const record of records) {
    const rawHex = fs.readFileSync(path.join(src, record.txid + '.hex'), 'utf8').trim(); assert(/^(?:[0-9a-f]{2})+$/.test(rawHex));
    const raw = Buffer.from(rawHex, 'hex'), tx = parse(raw); assert.equal(hex(Buffer.from(sha2(raw)).reverse()), record.txid);
    assert.equal(tx.inputs.length, record.vin.length); assert.equal(tx.outputs.length, record.vout.length);
    assert.equal(tx.version.readInt32LE(), record.version); assert.equal(tx.locktime.readUInt32LE(), record.locktime);
    tx.outputs.forEach((v, i) => {assert.equal(hex(v.script), record.vout[i].scriptpubkey); assert.equal(v.value.readBigUInt64LE(), BigInt(record.vout[i].value));});
    for (let index = 0; index < tx.inputs.length; index++) {
      const vin = tx.inputs[index], api = record.vin[index];
      assert.equal(hex(vin.script), api.scriptsig); assert.equal(hex(Buffer.from(vin.outpoint.subarray(0, 32)).reverse()), api.txid);
      assert.equal(vin.outpoint.readUInt32LE(32), api.vout); assert.equal(vin.sequence.readUInt32LE(), api.sequence);
      const sig = signature(vin.script); assert.equal(hex(sig.pub), canonical.target_pubkey);
      const h160 = crypto.createHash('ripemd160').update(sha(sig.pub)).digest('hex'); assert.equal(h160, canonical.target_h160);
      assert.equal(api.prevout.scriptpubkey, '76a914' + h160 + '88ac');
      const message = preimage(tx, index, Buffer.from(api.prevout.scriptpubkey, 'hex'));
      const spki = Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex'), sig.pub]);
      const pub = crypto.createPublicKey({key: spki, format: 'der', type: 'spki'});
      assert(crypto.verify('sha256', sha(message), pub, sig.der));
      signatures.push({id: record.txid + ':' + index, txid: record.txid, inputIndex: index, r: sig.r, s: sig.s, z: hex(sha2(message)),
        publicKey: hex(sig.pub), der: hex(sig.der), preimage: hex(message), hashType: 1, opensslVerified: true});
    }
    transactions.push({txid: record.txid, rawSHA256: hex(sha(raw)), inputCount: tx.inputs.length});
  }
  assert.equal(signatures.length, 6); assert.equal(new Set(signatures.map(s => s.r)).size, 6);
  save('signatures.json', signatures);
  const summary = {sourceSHA256: hex(sha(fs.readFileSync(__filename))), createdAt: new Date().toISOString(), transactions,
    signatures: signatures.length, allVerifiedWithOpenSSL: true, repeatedR: false, targetPublicKey: canonical.target_pubkey,
    scope: 'Six legacy P2PKH SIGHASH_ALL signatures spending the public puzzle prize address; no transaction created or broadcast.'};
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
module.exports = {parse, signature, preimage};
