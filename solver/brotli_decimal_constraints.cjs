'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const zlib = require('node:zlib'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/brotli_decimal_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function bytes(n) { let h = n.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); }
function common(lo, hi) {
  const a = bytes(lo), b = bytes(hi); if (a.length !== b.length) return Buffer.alloc(0);
  let i = 0; while (i < a.length && a[i] === b[i]) i++; return a.subarray(0, i);
}
function classify(b, maxOutputLength = 1048576) {
  try {
    const decoded = zlib.brotliDecompressSync(b, { info: true, maxOutputLength });
    return { status: 'finished', consumed: decoded.engine.bytesWritten, outputHex: decoded.buffer.toString('hex') };
  } catch (e) {
    if (e.code === 'Z_BUF_ERROR') return { status: 'incomplete', code: e.code };
    if (e.code.startsWith('ERR__ERROR_FORMAT_')) return { status: 'invalid', code: e.code, errno: e.errno };
    return { status: 'unknown', code: e.code, message: e.message };
  }
}
function domain(source) {
  assert(/^[a-i]+$/.test(source));
  const digits = [...source].map(c => c === 'g' ? '0' : String(c.charCodeAt(0) - 96));
  const low = BigInt(digits.join(''));
  const weights = [...source].flatMap((c, i) => c === 'g' ? [7n * 10n ** BigInt(source.length - i - 1)] : []);
  const tails = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  return { low, weights, tails };
}
function search(source, { maxNodes = 200000, maxMs = 15000, progress = false } = {}) {
  const { low, weights, tails } = domain(source), start = Date.now(), cache = new Map();
  const terminal = [], hits = []; let nodes = 0, excluded = 0n, pending = 0n;
  function visit(lo, mask) {
    if (nodes >= maxNodes || Date.now() - start >= maxMs) {
      terminal.push({ mask, status: 'pending-limit' }); pending += 1n << BigInt(weights.length - mask.length); return;
    }
    nodes++; const hi = lo + tails[mask.length], prefix = common(lo, hi), key = prefix.toString('hex');
    if (!cache.has(key)) cache.set(key, classify(prefix));
    const r = cache.get(key), leaf = mask.length === weights.length;
    const invalid = r.status === 'invalid' || r.status === 'finished' && r.consumed < bytes(lo).length || leaf && r.status === 'incomplete';
    if (invalid) {
      terminal.push({ mask, status: 'excluded', prefixHex: key, reason: r.status === 'finished' ? 'trailing-bytes' : leaf && r.status === 'incomplete' ? 'truncated-full-input' : r.code });
      excluded += 1n << BigInt(weights.length - mask.length); return;
    }
    if (r.status === 'unknown') {
      terminal.push({ mask, status: 'pending-decoder', prefixHex: key, reason: r.code }); pending += 1n << BigInt(weights.length - mask.length); return;
    }
    if (leaf) {
      assert.equal(r.status, 'finished'); assert.equal(r.consumed, prefix.length);
      hits.push({ mask, inputHex: key, outputHex: r.outputHex }); terminal.push({ mask, status: 'hit' }); return;
    }
    if (progress && nodes % 10000 === 0) console.log(JSON.stringify({ nodes, depth: mask.length, cache: cache.size, elapsedMs: Date.now() - start }));
    visit(lo, mask + '0'); visit(lo + weights[mask.length], mask + '1');
  }
  visit(low, '');
  const total = 1n << BigInt(weights.length); assert.equal(excluded + pending + BigInt(hits.length), total);
  return { complete: pending === 0n, nodes, decoderCalls: cache.size, ambiguous: weights.length, total: String(total), excluded: String(excluded), pending: String(pending), terminal, hits, elapsedMs: Date.now() - start };
}
function controls() {
  const texts = [Buffer.alloc(0), Buffer.from('matrixsumlist lastwordsbeforearchichoice'), Buffer.from('The seed is planted. '.repeat(100)), Buffer.from(Array.from({ length: 256 }, (_, i) => i))];
  let validPrefixes = 0, streams = 0, planted = 0;
  for (const text of texts) for (const quality of [0, 4, 11]) {
    const b = zlib.brotliCompressSync(text, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: quality } });
    for (let i = 0; i <= b.length; i++) {
      const r = classify(b.subarray(0, i)); assert(['incomplete', 'finished'].includes(r.status));
      if (r.status === 'finished') { assert.equal(i, b.length); assert.equal(r.outputHex, text.toString('hex')); }
      validPrefixes++;
    }
    const r = classify(Buffer.concat([b, Buffer.from([0x55]) ])); assert.equal(r.status, 'finished'); assert.equal(r.consumed, b.length); streams++;
    const decimal = BigInt('0x' + b.toString('hex')).toString();
    const source = [...decimal].map(c => 'gabcdefghi'[Number(c)]).join('');
    const result = search(source, { maxNodes: 100000, maxMs: 1000 });
    assert(result.hits.some(h => h.inputHex === b.toString('hex') && h.outputHex === text.toString('hex')) || !result.complete);
    if (result.hits.some(h => h.inputHex === b.toString('hex'))) planted++;
  }
  assert(planted > 0); return { streams, validPrefixes, plantedRecovered: planted, plantedTotal: 12 };
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'cases.json')), 'Inspect existing results before rerunning');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw), checked = controls();
  const spec = { hypothesis: 'Whole DBBI/FAED decimal integers, a..i=1..9 and each g independently 0/7, become one complete RFC7932 Brotli stream in minimal big-endian bytes. Both symbol orders. Arbitrary binary output; all input consumed. Standard built-in dictionary, no external shared dictionary or Large Window extension.', proof: 'At each assignment prefix the remaining values lie between exact integer bounds. The common big-endian byte prefix is fixed throughout that interval. Native format errors reject all completions; incomplete prefixes remain open. Resource/unrecognized errors are pending, never exclusions.', limits: { maxNodes: 200000, maxMs: 15000, maxOutputLength: 1048576 }, inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), node: process.version, brotli: process.versions.brotli, controls: checked, references: ['https://www.rfc-editor.org/rfc/rfc7932.html', 'https://raw.githubusercontent.com/google/brotli/master/c/include/brotli/decode.h', 'https://nodejs.org/api/zlib.html#zlibbrotlidecompresssyncbuffer-options'] };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const cases = [];
  for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) {
    const source = reverse ? [...input[field]].reverse().join('') : input[field];
    const r = search(source, { ...spec.limits, progress: true }); cases.push({ field, reverse, ...r });
    console.log(JSON.stringify({ field, reverse, ...r, terminal: r.terminal.length, hits: r.hits.length }));
  }
  fs.writeFileSync(path.join(out, 'cases.json'), JSON.stringify(cases, null, 2) + '\n');
}
if (require.main === module) main();
module.exports = { bytes, common, classify, domain, search, controls };
