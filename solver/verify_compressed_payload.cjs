/* Independent negative-certificate checker.
 * Rebuilds interval bounds and reads DEFLATE stored/fixed blocks directly
 * from RFC 1951. Does not import the search or rely on zlib error messages
 * for production exclusions. Dynamic blocks are explicitly unsupported by
 * this proof parser; none occur in the certificates being verified.
 * Run after the search: node solver/verify_compressed_payload.cjs
 */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'compressed_payload_2026-09-11');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

class NeedMore extends Error {}
class Bits {
  constructor(bytes) { this.bytes = bytes; this.offset = 0; }
  bit() {
    if (this.offset >= this.bytes.length * 8) throw new NeedMore();
    const value = (this.bytes[this.offset >> 3] >> (this.offset & 7)) & 1;
    this.offset++;
    return value;
  }
  integer(width) {
    let value = 0;
    for (let i = 0; i < width; i++) value += this.bit() * 2 ** i;
    return value;
  }
  huffman(width) {
    let value = 0;
    for (let i = 0; i < width; i++) value = value * 2 + this.bit();
    return value;
  }
}

function fixedSymbol(bits) {
  let code = 0;
  for (let length = 1; length <= 9; length++) {
    code = code * 2 + bits.bit();
    if (length === 7 && code <= 23) return 256 + code;
    if (length === 8 && code >= 48 && code <= 191) return code - 48;
    if (length === 8 && code >= 192 && code <= 199) return 280 + code - 192;
    if (length === 9 && code >= 400 && code <= 511) return 144 + code - 400;
  }
  throw new Error('Impossible fixed Huffman code');
}

const lengthBases = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const lengthExtras = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const distanceBases = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const distanceExtras = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];

function inspect(bytes, dictionaryLength = 0) {
  const bits = new Bits(bytes), trace = [];
  let produced = 0;
  try {
    while (true) {
      const final = bits.bit(), type = bits.integer(2);
      if (type === 3) return {status: 'invalid', reason: 'reserved_block_type', trace};
      if (type === 2) return {status: 'unsupported_dynamic_block', trace};
      if (type === 0) {
        bits.offset = Math.ceil(bits.offset / 8) * 8;
        const length = bits.integer(16), complement = bits.integer(16);
        trace.push({block: 'stored', length, complement});
        if ((length ^ complement) !== 65535) return {status: 'invalid', reason: 'stored_length_complement', trace};
        if (bits.offset + length * 8 > bytes.length * 8) throw new NeedMore();
        bits.offset += length * 8;
        produced += length;
      } else {
        while (true) {
          const symbol = fixedSymbol(bits);
          if (symbol === 256) break;
          if (symbol < 256) { produced++; continue; }
          if (symbol > 285) return {status: 'invalid', reason: 'reserved_length_symbol', trace};
          const length = lengthBases[symbol - 257] + bits.integer(lengthExtras[symbol - 257]);
          const distanceSymbol = bits.huffman(5);
          if (distanceSymbol > 29) return {status: 'invalid', reason: 'reserved_distance_symbol', trace};
          const distance = distanceBases[distanceSymbol] + bits.integer(distanceExtras[distanceSymbol]);
          const available = Math.min(32768, produced + dictionaryLength);
          if (trace.length < 12) trace.push({block: 'fixed', symbol, length, distance, produced, available});
          if (distance > available) return {status: 'invalid', reason: 'distance_before_history', trace};
          produced += length;
        }
      }
      if (final) return {status: 'complete', consumed: Math.ceil(bits.offset / 8), produced, trace};
    }
  } catch (error) {
    if (error instanceof NeedMore) return {status: 'incomplete', produced, trace};
    throw error;
  }
}

function bytesOf(n) {
  const bytes = [];
  do { bytes.unshift(Number(n % 256n)); n /= 256n; } while (n);
  return Buffer.from(bytes);
}

function rebuild(text, choices = '') {
  let minimum = 0n;
  const positions = [];
  for (let i = 0; i < text.length; i++) {
    minimum = minimum * 10n + (text[i] === 'g' ? 0n : BigInt(text.charCodeAt(i) - 96));
    if (text[i] === 'g') positions.push(text.length - 1 - i);
  }
  assert(choices.length <= positions.length && /^[07]*$/.test(choices));
  let lower = minimum, upper = minimum;
  for (let i = 0; i < positions.length; i++) {
    const weight = 7n * 10n ** BigInt(positions[i]);
    if (i < choices.length) { if (choices[i] === '7') { lower += weight; upper += weight; } }
    else upper += weight;
  }
  return {lower, upper, ambiguous: positions.length};
}

function fixedPrefix(lower, upper) {
  const a = bytesOf(lower), b = bytesOf(upper);
  if (a.length !== b.length) return Buffer.alloc(0);
  let i = 0;
  while (i < a.length && a[i] === b[i]) i++;
  return a.subarray(0, i);
}

function main() {
  const read = f => JSON.parse(fs.readFileSync(path.join(out, f)));
  const spec = read('spec.json'), result = read('results.json');
  const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
  const input = JSON.parse(inputBytes);
  assert.equal(sha(inputBytes), spec.inputsSHA256);
  assert.equal(sha(fs.readFileSync(path.join(__dirname, 'compressed_payload_constraints.cjs'))), spec.sourceSHA256);

  let positiveControls = 0, truncatedControls = 0;
  for (const sample of [Buffer.from('matrixsumlist '.repeat(40)), Buffer.from(Array.from({length: 256}, (_, i) => i))]) {
    for (const options of [{level: 0}, {strategy: zlib.constants.Z_FIXED}]) {
      const compressed = zlib.deflateRawSync(sample, options), parsed = inspect(compressed);
      assert(parsed.status === 'complete' && parsed.consumed === compressed.length && parsed.produced === sample.length);
      positiveControls++;
      for (let n = 0; n < compressed.length; n++) {
        assert.equal(inspect(compressed.subarray(0, n)).status, 'incomplete'); truncatedControls++;
      }
    }
  }
  const dict = Buffer.from('yellowblueprimesmatrixsumlistlastwords');
  const sample = Buffer.from('matrixsumlistlastwords yellowblueprimes matrixsumlistlastwords');
  const compressed = zlib.deflateRawSync(sample, {dictionary: dict, strategy: zlib.constants.Z_FIXED});
  assert.equal(inspect(compressed).status, 'invalid');
  const parsed = inspect(compressed, dict.length);
  assert(parsed.status === 'complete' && parsed.produced === sample.length); positiveControls++;

  const firstBytes = {zlib: [8,24,40,56,72,88,104,120], gzip: [31], zip: [80], bzip2: [66], xz: [253], '7z': [55]};
  let headerProofs = 0;
  for (const entry of result.headers) {
    const {lower, upper} = rebuild(input[entry.field]);
    assert.equal(lower.toString(), entry.lower); assert.equal(upper.toString(), entry.upper);
    const prefix = fixedPrefix(lower, upper);
    assert.equal(prefix.toString('hex'), entry.prefixHex);
    assert(prefix.length && !firstBytes[entry.format].includes(prefix[0]));
    assert.equal(entry.status, 'excluded_header'); headerProofs++;
  }

  const probeFile = path.join(out, 'larger_dictionary_probes.json');
  const probes = spec.optionalDictionaryProbes?.enabled ? JSON.parse(fs.readFileSync(probeFile)) : null;
  if (probes) assert.equal(probes.sourceSHA256, spec.sourceSHA256);
  const searches = [...result.raw, ...(probes?.probes ?? []).map(r => ({field: 'faed', ...r}))];
  const proofResults = [];
  for (const search of searches) {
    assert.equal(search.hits.length, 0, 'Positive candidates need output verification, not a negative certificate');
    assert.equal(search.complete, search.pending.length === 0);
    const paths = [...search.certificates, ...search.pending].map(c => c.choices).sort();
    for (let i = 1; i < paths.length; i++) assert(!paths[i].startsWith(paths[i - 1]), 'Overlapping proof branches');
    let covered = 0n;
    const traces = [];
    for (const certificate of search.certificates) {
      const {lower, upper, ambiguous} = rebuild(input[search.field], certificate.choices);
      assert.equal(certificate.depth, certificate.choices.length);
      assert.equal(lower.toString(), certificate.lower); assert.equal(upper.toString(), certificate.upper);
      assert.equal(ambiguous, search.ambiguousDigits);
      const count = 1n << BigInt(ambiguous - certificate.depth);
      assert.equal(count.toString(), certificate.masks); covered += count;
      const prefix = fixedPrefix(lower, upper);
      assert.equal(prefix.toString('hex'), certificate.prefixHex);
      const parsed = inspect(prefix, search.dictionaryLength);
      if (certificate.reason === 'invalid_prefix') assert.equal(parsed.status, 'invalid');
      else if (certificate.reason === 'stream_ends_before_input') {
        assert.equal(parsed.status, 'complete'); assert(parsed.consumed < bytesOf(lower).length);
      } else if (certificate.reason === 'truncated_stream') {
        assert.equal(certificate.depth, ambiguous); assert.equal(parsed.status, 'incomplete');
      } else throw new Error('Unknown certificate reason');
      traces.push({choices: certificate.choices, prefixHex: certificate.prefixHex, ...parsed});
    }
    let pendingCount = 0n;
    for (const pending of search.pending) {
      const {lower, upper, ambiguous} = rebuild(input[search.field], pending.choices);
      assert.equal(lower.toString(), pending.lower); assert.equal(upper.toString(), pending.upper);
      assert.equal(pending.depth, pending.choices.length);
      const count = 1n << BigInt(ambiguous - pending.depth);
      assert.equal(count.toString(), pending.masks); pendingCount += count;
    }
    assert.equal(covered + pendingCount, 1n << BigInt(search.ambiguousDigits));
    assert.equal(covered.toString(), search.rejectedAssignments);
    assert.equal(pendingCount.toString(), search.pendingAssignments);
    proofResults.push({field: search.field, dictionaryLength: search.dictionaryLength,
      complete: search.complete, covered: covered.toString(), pending: pendingCount.toString(), traces});
  }
  // Separate exhaustive enumeration of the small input: no prefix bounds used.
  const small = rebuild(input.dbbi);
  let exhaustiveDBBI = 0;
  for (let mask = 0; mask < 2 ** small.ambiguous; mask++) {
    const choices = Array.from({length: small.ambiguous}, (_, i) => mask & (1 << i) ? '7' : '0').join('');
    const {lower, upper} = rebuild(input.dbbi, choices);
    assert.equal(lower, upper); assert.equal(inspect(bytesOf(lower)).status, 'invalid'); exhaustiveDBBI++;
  }
  const verification = {method: 'Independent RFC 1951 bit parser, interval reconstruction, prefix-free coverage, and DBBI exhaustive enumeration.',
    sourceSHA256: sha(fs.readFileSync(__filename)), resultsSHA256: sha(fs.readFileSync(path.join(out, 'results.json'))),
    probesSHA256: probes ? sha(fs.readFileSync(probeFile)) : null,
    positiveControls, truncatedControls, headerProofs, exhaustiveDBBI, proofResults};
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(verification, null, 2) + '\n');
  console.log(JSON.stringify({positiveControls, truncatedControls, headerProofs, exhaustiveDBBI,
    completeSearches: proofResults.filter(r => r.complete).length,
    partialSearches: proofResults.filter(r => !r.complete).length,
    certificates: proofResults.reduce((s, r) => s + r.traces.length, 0)}, null, 2));
}

if (require.main === module) main();
module.exports = {inspect};
