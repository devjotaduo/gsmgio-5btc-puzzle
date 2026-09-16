/* Whole decimal integers with independently ambiguous 0/7 digits.
 * Exact common-prefix pruning for standalone raw DEFLATE. Header exclusions
 * for other declared formats. No ASCII filter, byte stripping, or network.
 * Run: node solver/compressed_payload_constraints.cjs [--probe-dictionaries]
 */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'compressed_payload_2026-09-11');
const inputFile = path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const toBytes = n => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
};
const toPattern = text => [...text].map(c => c === 'g' ? '?' : c.charCodeAt(0) - 96).join('');

function decimalModel(pattern) {
  assert.match(pattern, /^[0-9?]+$/);
  const minimum = BigInt(pattern.replaceAll('?', '0'));
  const weights = [...pattern].flatMap((c, i) => c === '?'
    ? [7n * 10n ** BigInt(pattern.length - 1 - i)] : []);
  const tail = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tail[i] = tail[i + 1] + weights[i];
  return {minimum, weights, tail};
}

function commonPrefix(lo, hi) {
  const a = toBytes(lo), b = toBytes(hi);
  if (a.length !== b.length) return {prefix: Buffer.alloc(0), byteLength: null};
  let length = 0;
  while (length < a.length && a[length] === b[length]) length++;
  return {prefix: a.subarray(0, length), byteLength: a.length};
}

// Z_FINISH is retained. A successful partial flush is never called a solve.
// bytesWritten is additionally checked against the full expected input size.
function inflateWhole(bytes, format = 'raw', {dictionary, maxOutputLength = 1048576} = {}) {
  const method = {raw: zlib.inflateRawSync, zlib: zlib.inflateSync, gzip: zlib.gunzipSync}[format];
  assert(method, 'Unsupported decompressor');
  try {
    const result = method(bytes, {dictionary, info: true, maxOutputLength});
    if (result.engine.bytesWritten !== bytes.length) {
      return {status: 'trailing', consumed: result.engine.bytesWritten, output: result.buffer};
    }
    return {status: 'valid', consumed: result.engine.bytesWritten, output: result.buffer};
  } catch (error) {
    if (error.code === 'Z_DATA_ERROR') return {status: 'invalid', reason: error.message};
    if (error.code === 'Z_BUF_ERROR') return {status: 'incomplete', reason: error.message};
    if (error.code === 'ERR_BUFFER_TOO_LARGE') return {status: 'limit', reason: error.message};
    if (error.code === 'Z_NEED_DICT') return {status: 'needs_dictionary', reason: error.message};
    throw error;
  }
}

function solveRaw(pattern, {
  dictionaryLength = 0, maxNodes = 100000, maxMs = 30000,
  maxOutputLength = 1048576, maxHits = 1000,
} = {}) {
  assert(Number.isInteger(dictionaryLength) && dictionaryLength >= 0 && dictionaryLength <= 32768);
  const {minimum, weights, tail} = decimalModel(pattern);
  // Dictionary contents affect copied bytes, not DEFLATE token validity.
  // For positive dictionary lengths, hits are structural candidates only.
  const dictionary = dictionaryLength ? Buffer.alloc(dictionaryLength) : undefined;
  const stack = [{i: 0, lo: minimum, choices: ''}];
  const certificates = [], hits = [], deferred = [];
  let nodes = 0, rejected = 0n, limitReason = null;
  const start = Date.now();
  while (stack.length) {
    if (nodes >= maxNodes || Date.now() - start >= maxMs || hits.length >= maxHits) {
      limitReason = nodes >= maxNodes ? 'node limit' : hits.length >= maxHits ? 'hit limit' : 'time limit';
      break;
    }
    const state = stack.pop(), {i, lo, choices} = state;
    const hi = lo + tail[i], count = 1n << BigInt(weights.length - i);
    nodes++;
    const {prefix, byteLength} = commonPrefix(lo, hi);
    const decoded = inflateWhole(prefix, 'raw', {dictionary, maxOutputLength});
    let reason = null;
    if (decoded.status === 'invalid') reason = 'invalid_prefix';
    else if (['valid', 'trailing'].includes(decoded.status) && byteLength !== null && decoded.consumed < byteLength) {
      reason = 'stream_ends_before_input';
    } else if (i === weights.length && decoded.status === 'incomplete') reason = 'truncated_stream';
    if (reason) {
      certificates.push({choices, depth: i, lower: lo.toString(), upper: hi.toString(),
        masks: count.toString(), prefixHex: prefix.toString('hex'), byteLength, reason,
        decoderReason: decoded.reason ?? null, consumed: decoded.consumed ?? null});
      rejected += count;
      continue;
    }
    if (['limit', 'needs_dictionary'].includes(decoded.status)) {
      deferred.push({...state, reason: decoded.status});
      continue;
    }
    if (i === weights.length) {
      assert.equal(decoded.status, 'valid');
      assert.equal(decoded.consumed, byteLength);
      hits.push({choices, decimal: lo.toString(), compressedHex: prefix.toString('hex'),
        outputLength: decoded.output.length,
        outputHex: dictionaryLength ? null : decoded.output.toString('hex'),
        dictionaryNote: dictionaryLength ? 'Structural candidate; output requires the real dictionary.' : null});
      continue;
    }
    stack.push({i: i + 1, lo: lo + weights[i], choices: choices + '7'});
    stack.push({i: i + 1, lo, choices: choices + '0'});
  }
  const pending = [...stack, ...deferred].map(s => ({choices: s.choices, depth: s.i,
    lower: s.lo.toString(), upper: (s.lo + tail[s.i]).toString(),
    masks: (1n << BigInt(weights.length - s.i)).toString(), reason: s.reason ?? limitReason}));
  const pendingCount = pending.reduce((s, p) => s + BigInt(p.masks), 0n);
  assert.equal(rejected + BigInt(hits.length) + pendingCount, 1n << BigInt(weights.length));
  return {dictionaryLength, ambiguousDigits: weights.length, assignments: (1n << BigInt(weights.length)).toString(),
    nodes, complete: pending.length === 0, elapsedMs: Date.now() - start,
    rejectedAssignments: rejected.toString(), pendingAssignments: pendingCount.toString(),
    certificates, hits, pending};
}

const zlibHeaders = [];
for (let info = 0; info <= 7; info++) for (let flags = 0; flags <= 255; flags++) {
  const cmf = (info << 4) | 8;
  if (((cmf << 8) | flags) % 31 === 0) zlibHeaders.push(Buffer.from([cmf, flags]).toString('hex'));
}
const headerFormats = {
  zlib: zlibHeaders,
  gzip: ['1f8b08'],
  zip: ['504b'], // Conservative: accept any PK record, not just a local entry.
  bzip2: Array.from({length: 9}, (_, i) => Buffer.from(`BZh${i + 1}`).toString('hex')),
  xz: ['fd377a585a00'],
  '7z': ['377abcaf271c'],
};

function headerChecks(pattern) {
  const {minimum, tail} = decimalModel(pattern), maximum = minimum + tail[0];
  const {prefix, byteLength} = commonPrefix(minimum, maximum);
  return Object.entries(headerFormats).map(([format, candidates]) => {
    const compatible = candidates.some(hex => {
      const header = Buffer.from(hex, 'hex'), n = Math.min(header.length, prefix.length);
      return header.subarray(0, n).equals(prefix.subarray(0, n));
    });
    return {format, status: compatible ? 'unresolved_header_compatible' : 'excluded_header',
      lower: minimum.toString(), upper: maximum.toString(), prefixHex: prefix.toString('hex'), byteLength,
      permittedPrefixes: candidates};
  });
}

function controls() {
  const samples = [Buffer.from('matrixsumlist matrixsumlist matrixsumlist'),
    Buffer.from('yellow blue primes; last words before a choice. '.repeat(12)),
    Buffer.from(Array.from({length: 256}, (_, i) => i))];
  const rawCases = [];
  for (const sample of samples) for (const options of [
    {level: 0}, {strategy: zlib.constants.Z_FIXED}, {strategy: zlib.constants.Z_HUFFMAN_ONLY},
  ]) rawCases.push({sample, encoded: zlib.deflateRawSync(sample, options)});
  let roundTrips = 0, planted = 0, bruteForce = 0, rejectedIncomplete = 0, rejectedTrailing = 0;
  const blockTypes = new Set();
  for (const {sample, encoded} of rawCases) {
    blockTypes.add((encoded[0] >> 1) & 3);
    const decoded = inflateWhole(encoded);
    assert.equal(decoded.status, 'valid'); assert(decoded.output.equals(sample)); roundTrips++;
    assert.equal(inflateWhole(encoded.subarray(0, encoded.length - 1)).status, 'incomplete'); rejectedIncomplete++;
    assert.equal(inflateWhole(Buffer.concat([encoded, Buffer.from([0x91, 0x22])])).status, 'trailing'); rejectedTrailing++;
    const decimal = BigInt('0x' + encoded.toString('hex')).toString();
    assert(toBytes(BigInt(decimal)).equals(encoded), 'Control must preserve minimal-byte representation');
    let masked = 0;
    const pattern = decimal.replace(/[07]/g, c => masked++ < 6 ? '?' : c);
    const result = solveRaw(pattern);
    assert(result.complete && result.hits.some(h => h.decimal === decimal)); planted++;
    const {minimum, weights} = decimalModel(pattern);
    let values = [minimum];
    for (const weight of weights) values = values.flatMap(n => [n, n + weight]);
    const expected = values.filter(n => inflateWhole(toBytes(n)).status === 'valid').map(String).sort();
    assert.deepEqual(result.hits.map(h => h.decimal).sort(), expected); bruteForce++;
  }
  assert.deepEqual([...blockTypes].sort(), [0, 1, 2]);
  let wrapperRoundTrips = 0, checksumRejections = 0;
  for (const sample of samples) for (const format of ['zlib', 'gzip']) {
    const encoded = (format === 'zlib' ? zlib.deflateSync : zlib.gzipSync)(sample);
    const decoded = inflateWhole(encoded, format);
    assert.equal(decoded.status, 'valid'); assert(decoded.output.equals(sample)); wrapperRoundTrips++;
    const damaged = Buffer.from(encoded); damaged[damaged.length - 1] ^= 1;
    assert.equal(inflateWhole(damaged, format).status, 'invalid'); checksumRejections++;
  }
  const dictionary = Buffer.from('yellowblueprimesmatrixsumlistlastwords');
  const sample = Buffer.from('matrixsumlistlastwords yellowblueprimes matrixsumlistlastwords');
  const encoded = zlib.deflateRawSync(sample, {dictionary});
  assert.notEqual(inflateWhole(encoded).status, 'valid');
  const original = inflateWhole(encoded, 'raw', {dictionary});
  assert(original.status === 'valid' && original.output.equals(sample));
  const structural = inflateWhole(encoded, 'raw', {dictionary: Buffer.alloc(dictionary.length)});
  assert(structural.status === 'valid' && structural.output.length === sample.length);
  assert(!structural.output.equals(sample), 'Dictionary content must affect the reconstructed data');
  const dictionaryDecimal = BigInt('0x' + encoded.toString('hex')).toString();
  const dictionarySearch = solveRaw(dictionaryDecimal, {dictionaryLength: dictionary.length});
  assert(dictionarySearch.complete && dictionarySearch.hits.length === 1);
  assert.equal(dictionarySearch.hits[0].decimal, dictionaryDecimal);
  assert.equal(dictionarySearch.hits[0].outputHex, null, 'A placeholder dictionary must not yield a claimed plaintext');
  const bomb = zlib.deflateRawSync(Buffer.alloc(2048, 65));
  assert.equal(inflateWhole(bomb, 'raw', {maxOutputLength: 32}).status, 'limit');
  const bombPattern = BigInt('0x' + bomb.toString('hex')).toString();
  assert(!solveRaw(bombPattern, {maxOutputLength: 32}).complete);
  const limited = solveRaw('???', {maxNodes: 0});
  assert(!limited.complete && limited.pendingAssignments === '8');
  return {roundTrips, blockTypes: [...blockTypes].sort(), planted, bruteForce,
    rejectedIncomplete, rejectedTrailing, wrapperRoundTrips, checksumRejections,
    dictionaryControl: true, dictionarySearchControl: true,
    outputLimitIsNotAnExclusion: true, nodeLimitIsNotAnExclusion: true};
}

function main() {
  fs.mkdirSync(out, {recursive: true});
  const save = (file, value) => fs.writeFileSync(path.join(out, file), JSON.stringify(value, null, 2) + '\n');
  const bytes = fs.readFileSync(inputFile), input = JSON.parse(bytes);
  const withDictionaryProbes = process.argv.includes('--probe-dictionaries');
  save('spec.json', {
    sourceSHA256: sha(fs.readFileSync(__filename)), inputsSHA256: sha(bytes),
    node: process.version, zlib: process.versions.zlib,
    hypothesis: 'Original complete DBBI/FAED, a..i=1..9, every g independently 0/7, whole decimal integer to minimal big-endian bytes.',
    scope: 'Headers of zlib/gzip/ZIP/bzip2/XZ/7z; raw DEFLATE with no dictionary. FAED also tested with any dictionary of at most 38 bytes (DBBI decimal representation length).',
    exclusionsNotClaimed: 'Other symbol maps/bases, bytes removed/reordered, embedded streams at other offsets, Brotli, headerless LZMA, larger dictionaries, or all compression algorithms.',
    acceptance: 'Complete decompression, all input bytes consumed, arbitrary binary output allowed. Dictionary-length probes validate structure, not dictionary contents.',
    limits: {maxNodes: 100000, maxMs: 30000, maxOutputLength: 1048576, maxHits: 1000},
    optionalDictionaryProbes: {enabled: withDictionaryProbes, lengths: [91, 32768], maxNodes: 256, maxMs: 30000},
    proof: 'Each decimal branch encloses all remaining masks in an integer interval. Equal prefix bytes of the interval endpoints are fixed for all integers inside. A malformed DEFLATE prefix excludes every completion of that branch.',
    references: [
      'https://www.rfc-editor.org/rfc/rfc1951.html', 'https://www.rfc-editor.org/rfc/rfc1950.html',
      'https://www.rfc-editor.org/rfc/rfc1952.html', 'https://raw.githubusercontent.com/nodejs/node/v24.13.0/doc/api/zlib.md',
      'https://tukaani.org/xz/xz-file-format.txt', 'https://sourceware.org/bzip2/manual/manual.html',
      'https://www.7-zip.org/recover.html', 'https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT',
    ],
  });
  const checked = controls(); save('controls.json', checked);
  const headers = [], raw = [];
  for (const field of ['dbbi', 'faed']) {
    const pattern = toPattern(input[field]);
    headers.push(...headerChecks(pattern).map(r => ({field, ...r})));
    raw.push({field, ...solveRaw(pattern)});
  }
  const d = decimalModel(toPattern(input.dbbi));
  assert.equal(toBytes(d.minimum).length, 38); assert.equal(toBytes(d.minimum + d.tail[0]).length, 38);
  raw.push({field: 'faed', ...solveRaw(toPattern(input.faed), {dictionaryLength: 38})});
  save('results.json', {headers, raw});
  const dictionaryProbes = withDictionaryProbes ? [91, 32768].map(dictionaryLength =>
    solveRaw(toPattern(input.faed), {dictionaryLength, maxNodes: 256, maxMs: 30000})) : [];
  if (withDictionaryProbes) save('larger_dictionary_probes.json', {
    purpose: 'Bounded feasibility probes only. Literal DBBI could occupy 91 bytes; 32768 is the maximum DEFLATE history. Placeholder dictionaries validate structure only.',
    sourceSHA256: sha(fs.readFileSync(__filename)), limits: {maxNodes: 256, maxMs: 30000}, probes: dictionaryProbes,
  });
  const summary = {
    headerCases: headers.length, excludedHeaders: headers.filter(r => r.status === 'excluded_header').length,
    raw: raw.map(({field, dictionaryLength, ambiguousDigits, assignments, nodes, complete, certificates, hits, pendingAssignments}) => ({
      field, dictionaryLength, ambiguousDigits, assignments, nodes, complete,
      rejectionCertificates: certificates.length, hits: hits.length, pendingAssignments,
    })), controls: checked,
    dictionaryProbes: dictionaryProbes.map(r => ({dictionaryLength: r.dictionaryLength, nodes: r.nodes,
      complete: r.complete, hits: r.hits.length, pendingAssignments: r.pendingAssignments})),
    conclusion: raw.every(r => r.complete && r.hits.length === 0) && headers.every(r => r.status === 'excluded_header')
      ? 'No valid compressed payload in the explicitly tested complete models. No AES candidates derived.'
      : 'Inspect raw candidates, pending branches and any compatible headers; no negative conclusion is assumed.',
  };
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}

if (require.main === module) main();
module.exports = {decimalModel, commonPrefix, toBytes, toPattern, inflateWhole, solveRaw, headerChecks};
