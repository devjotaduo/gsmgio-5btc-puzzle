'use strict';
// Exact key-format and fixed-size grammars; selected plaintexts are samples only.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { graphs, pow } = require('./rsa_color_blocks.cjs');
const { minBytes, classify } = require('./rsa_color_multibyte.cjs');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'rsa_color_candidates_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const hex = '0123456789abcdefABCDEF';
const base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const formats = [
  { name: 'hex64', alphabet: hex, length: 64, prefix: [] },
  { name: 'prefixedHex66', alphabet: hex, length: 66, prefix: ['0', 'xX'] },
  { name: 'WIF51', alphabet: base58, length: 51, prefix: ['5'] },
  { name: 'WIF52', alphabet: base58, length: 52, prefix: ['KL'] }
];

function edgesOf(graph, length, n, d) {
  const result = Array.from({ length: length + 1 }, () => []);
  const cache = new Map();
  for (let at = 0; at < length; at++) {
    for (let k = graph.heads[at]; k < graph.heads[at + 1]; k += 2) {
      const end = graph.edges[k], c = graph.edges[k + 1];
      if (!cache.has(c)) {
        const m = pow(c, d, n);
        cache.set(c, classify(m) ? { m, bytes: minBytes(m) } : null);
      }
      const value = cache.get(c);
      if (value) result[at].push({ at, end, c, ...value });
    }
  }
  return result;
}

function keyShape(edges, format, byteOrder) {
  const length = edges.length - 1, reachable = Array(length + 1).fill(0n);
  const masks = new Map();
  reachable[0] = 1n;
  for (let at = 0; at < length; at++) if (reachable[at]) {
    for (const edge of edges[at]) {
      const bytes = byteOrder === 'BE' ? edge.bytes : Buffer.from(edge.bytes).reverse();
      const id = bytes.toString('hex');
      if (!masks.has(id)) {
        let mask = 0n;
        for (let p = 0; p + bytes.length <= format.length; p++) {
          if ([...bytes].every((v, j) => (format.prefix[p + j] || format.alphabet).includes(String.fromCharCode(v)))) mask |= 1n << BigInt(p);
        }
        masks.set(id, mask);
      }
      reachable[edge.end] |= (reachable[at] & masks.get(id)) << BigInt(bytes.length);
    }
  }
  return Boolean(reachable[length] & (1n << BigInt(format.length)));
}

function fixedSize(edges, size) {
  const length = edges.length - 1, counts = Array(length + 1).fill(0n);
  counts[0] = 1n;
  for (let at = 0; at < length; at++) if (counts[at]) for (const edge of edges[at]) {
    if (edge.bytes.length === size || edge.end === length && edge.bytes.length < size) counts[edge.end] += counts[at];
  }
  return String(counts[length]);
}

function score(bytes, strategy) {
  const controls = [...bytes].filter(v => v < 32).length;
  const other = [...bytes].filter(v => !(v === 32 || v >= 65 && v <= 90 || v >= 97 && v <= 122)).length;
  return strategy === 'fewestControls' ? [controls, other, bytes.length] : [other, bytes.length, controls];
}

function compare(a, b) {
  for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return a[k] - b[k];
  return 0;
}

function selectPath(edges, strategy, fixed = 0) {
  const length = edges.length - 1, costs = Array(length + 1).fill(null), parent = Array(length + 1).fill(null);
  costs[0] = [0, 0, 0];
  for (let at = 0; at < length; at++) if (costs[at]) for (const edge of edges[at]) {
    if (fixed && edge.bytes.length !== fixed && !(edge.end === length && edge.bytes.length < fixed)) continue;
    const cost = score(edge.bytes, strategy).map((v, i) => v + costs[at][i]);
    if (!costs[edge.end] || compare(cost, costs[edge.end]) < 0) {
      costs[edge.end] = cost;
      parent[edge.end] = edge;
    }
  }
  if (!costs[length]) return null;
  const blocks = [];
  let at = length;
  while (at) { const edge = parent[at]; assert(edge); blocks.push({ start: edge.at, end: edge.end, c: edge.c, m: edge.m }); at = edge.at; }
  return { cost: costs[length], blocks: blocks.reverse() };
}

function encodeControl(text, size, byteOrder) {
  const n = 1690721, e = 65537, lambda = 84060;
  let d = 1; while (e * d % lambda !== 1) d++;
  const digits = [];
  for (let i = 0; i < text.length; i += size) {
    const b = Buffer.from(text.subarray(i, i + size));
    if (byteOrder === 'LE') b.reverse();
    digits.push(String(pow(Number(BigInt('0x' + b.toString('hex'))), e, n)));
  }
  const source = digits.join('').replace(/\d/g, x => x === '0' ? 'g' : String.fromCharCode(96 + Number(x)));
  return edgesOf(graphs(source, 'g', n).minimal, source.length, n, d);
}

function controls() {
  let planted = 0;
  for (const f of formats) for (const order of ['BE', 'LE']) for (const size of [1, 2]) {
    const str = f.name === 'hex64' ? '0'.repeat(63) + '1' : f.name === 'prefixedHex66' ? '0x' + '0'.repeat(63) + '1' : (f.name === 'WIF51' ? '5' : 'K') + '1'.repeat(f.length - 1);
    const edges = encodeControl(Buffer.from(str), size, order);
    assert(keyShape(edges, f, order));
    assert(BigInt(fixedSize(edges, size)) > 0n);
    planted++;
  }
  // Exhaust all paths in small toy DAGs, with boundaries crossing the prefix.
  let exhaustive = 0;
  for (const order of ['BE', 'LE']) for (const prefix of [[], ['0', 'xX'], ['5']]) {
    const f = { alphabet: '0a15Kx', length: 4, prefix };
    const edges = Array.from({ length: 5 }, () => []);
    for (let i = 0; i < 4; i++) for (const word of ['0', 'a', '51', '0x', 'K1', 'aa']) if (i + word.length <= 4) {
      edges[i].push({ at: i, end: i + word.length, bytes: Buffer.from(word) });
    }
    let yes = false;
    function visit(at, text) {
      if (at === 4) { if (text.length === f.length && [...text].every((c, i) => (f.prefix[i] || f.alphabet).includes(c))) yes = true; return; }
      for (const edge of edges[at]) visit(edge.end, text + (order === 'BE' ? edge.bytes : Buffer.from(edge.bytes).reverse()).toString('ascii'));
    }
    visit(0, '');
    assert.equal(keyShape(edges, f, order), yes);
    exhaustive++;
  }
  return { planted, exhaustive };
}

function main() {
  fs.mkdirSync(out, { recursive: true });
  assert(!fs.existsSync(path.join(out, 'models.jsonl')), 'Existing run must be inspected, not overwritten');
  const inputRaw = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
  const input = JSON.parse(inputRaw);
  const rowsRaw = fs.readFileSync(path.join(root, '_work', 'rsa_color_multibyte_2026-09-16', 'valid.jsonl'));
  const rows = rowsRaw.toString().trim().split(/\r?\n/).map(JSON.parse);
  const spec = { inputSHA256: sha(inputRaw), validSHA256: sha(rowsRaw), formats, orders: ['BE', 'LE'], fixedSizes: [1, 2, 3], controls: controls(), sources: Object.fromEntries(['rsa_color_candidates.cjs', 'rsa_color_blocks.cjs', 'rsa_color_multibyte.cjs'].map(f => [f, sha(fs.readFileSync(path.join(__dirname, f)))])), scope: 'Exact format feasibility over all previously ASCII-compatible paths; no spaces, line wrapping or suffixes for key formats. Fixed-size counts allow a shorter final block. Selected passwords are the first previously saved BE witness, plus paths minimizing (controls, nonletters, length) and (nonletters, length, controls), both without a block-size restriction and restricted to two-byte blocks. BE/LE is per block; these samples are not exhaustive plaintext/password enumeration.' };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const modelFd = fs.openSync(path.join(out, 'models.jsonl'), 'wx');
  const selectedFd = fs.openSync(path.join(out, 'selected.jsonl'), 'wx');
  const candidateMap = new Map(), cache = new Map(), groups = {};
  let keyFormatHits = 0, selected = 0, fixedSizeModels = [0, 0, 0];
  const start = Date.now();
  function candidate(bytes, origin) {
    const id = bytes.toString('hex');
    if (!candidateMap.has(id)) candidateMap.set(id, { id: candidateMap.size, hex: id, firstOrigin: origin });
    return candidateMap.get(id).id;
  }
  for (const [index, row] of rows.entries()) {
    const source = row.reverse ? [...input[row.field]].reverse().join('') : input[row.field];
    const id = [row.n, row.field, row.reverse, row.aliases, row.format].join('/');
    if (!cache.has(id)) cache.set(id, graphs(source, row.aliases, row.n)[row.format]);
    const edges = edgesOf(cache.get(id), source.length, row.n, row.d);
    const keyFormats = spec.orders.flatMap(order => formats.map(f => row.minBytes > f.length || row.maxBytes < f.length ? false : keyShape(edges, f, order)));
    const fixed = spec.fixedSizes.map(size => fixedSize(edges, size));
    keyFormatHits += keyFormats.filter(Boolean).length;
    fixed.forEach((n, i) => { if (BigInt(n)) { fixedSizeModels[i]++; const key = row.field + '/' + row.n + '/' + (i + 1); groups[key] ||= { models: 0, paths: 0n }; groups[key].models++; groups[key].paths += BigInt(n); } });
    const witnessId = candidate(Buffer.from(row.witnessHex, 'hex'), { index, strategy: 'previousWitness', order: 'BE' });
    fs.writeSync(modelFd, JSON.stringify({ index, keyIndex: row.keyIndex, modelIndex: row.modelIndex, keyFormats, fixedPaths: fixed, witnessId }) + '\n');
    for (const fixedSize of [0, 2]) for (const strategy of ['fewestControls', 'fewestNonletters']) {
      const chosen = selectPath(edges, strategy, fixedSize);
      if (!chosen) continue;
      const candidates = spec.orders.map(order => candidate(Buffer.concat(chosen.blocks.map(b => order === 'BE' ? minBytes(b.m) : minBytes(b.m).reverse())), { index, strategy, fixedSize, order }));
      fs.writeSync(selectedFd, JSON.stringify({ index, strategy, fixedSize, ...chosen, candidates }) + '\n');
      selected++;
    }
  }
  fs.closeSync(modelFd); fs.closeSync(selectedFd);
  fs.writeFileSync(path.join(out, 'candidates.jsonl'), [...candidateMap.values()].map(r => JSON.stringify(r)).join('\n') + '\n');
  const summary = { complete: true, models: rows.length, keyFormatDecisions: rows.length * 8, keyFormatHits, fixedSizeModels, fixedGroups: groups, selectedPaths: selected, candidates: candidateMap.size, elapsedMs: Date.now() - start, files: Object.fromEntries(['models.jsonl', 'selected.jsonl', 'candidates.jsonl'].map(f => [f, sha(fs.readFileSync(path.join(out, f)))])) };
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, (_, v) => typeof v === 'bigint' ? String(v) : v, 2) + '\n');
  console.log(JSON.stringify(summary, (_, v) => typeof v === 'bigint' ? String(v) : v));
}
if (require.main === module) main();
module.exports = { formats, keyShape, fixedSize, score, selectPath };
