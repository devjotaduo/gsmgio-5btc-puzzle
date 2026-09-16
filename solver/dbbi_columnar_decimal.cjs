/* DBBI as a numeric column-ordering key, then whole-decimal -> seven-bit bytes.
 * Only the finite family in spec.json is claimed; this does not identify a cipher.
 * Run: node solver/dbbi_columnar_decimal.cjs
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {permutation, controls} = require('./columnar_decimal_constraints.cjs');
const {search, open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'dbbi_columnar_2026-09-16');
const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
const input = JSON.parse(inputBytes);
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

function lists(values) {
  const result = [{name: 'literal', values: values.slice()}];
  for (const width of [7, 13]) {
    const rows = Array(values.length / width).fill(0), cols = Array(width).fill(0);
    values.forEach((v, i) => { rows[Math.floor(i / width)] += v; cols[i % width] += v; });
    result.push({name: `width${width}/rows`, values: rows}, {name: `width${width}/cols`, values: cols});
  }
  const rows = Array(14).fill(0), cols = Array(14).fill(0);
  let i = 0;
  for (let r = 0; r < 14; r++) for (let c = r + 1; c < 14; c++) {
    rows[r] += values[i]; cols[c] += values[i++];
  }
  assert.equal(i, 91);
  result.push({name: 'upper/rows', values: rows}, {name: 'upper/cols', values: cols},
    {name: 'upper/symmetric', values: rows.map((v, j) => v + cols[j])});
  return result;
}

function keys() {
  assert.equal(input.dbbi.length, 91);
  assert.equal([...input.dbbi].filter(c => c === 'g').length, 10);
  const unique = new Map(), byFamily = {};
  let constructions = 0;
  for (let mask = 0; mask < 1024; mask++) {
    let at = 0;
    const values = [...input.dbbi].map(c => c === 'g' ? ((mask >> at++) & 1) * 7 : c.charCodeAt(0) - 96);
    for (const list of lists(values)) for (const reverse of [false, true]) {
      constructions++;
      const v = reverse ? list.values.slice().reverse() : list.values;
      const alphabet = [...new Set(v)].sort((a, b) => a - b);
      const ranks = v.map(x => alphabet.indexOf(x)), signature = ranks.join(',');
      byFamily[list.name] ??= new Set(); byFamily[list.name].add(signature);
      if (!unique.has(signature)) unique.set(signature, {
        id: unique.size, ranks, representative: {mask, list: list.name, reverse, values: v},
      });
    }
  }
  return {constructions, keys: [...unique.values()], byFamily: Object.fromEntries(
    Object.entries(byFamily).map(([name, set]) => [name, set.size]))};
}

function oracles(candidates) {
  const pw = new Map(), material = new Set(candidates.map(c => c.hex)), padding = [], scalarHits = [];
  const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  for (const hex of material) {
    const bytes = Buffer.from(hex, 'hex');
    for (const value of [bytes, Buffer.from(sha(bytes))]) pw.set(value.toString('hex'), value);
    const scalar = Buffer.from(sha(bytes), 'hex');
    if (BigInt('0x' + scalar.toString('hex')) > 0n && BigInt('0x' + scalar.toString('hex')) < n) {
      const ec = crypto.createECDH('secp256k1'); ec.setPrivateKey(scalar);
      if (ec.getPublicKey('hex', 'uncompressed') === input.target_pubkey) scalarHits.push({hex, scalar: scalar.toString('hex')});
    }
  }
  let aesAttempts = 0;
  for (const [passwordHex, bytes] of pw) for (const [blob, text] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
    aesAttempts++;
    const body = open(bytes, text, digest);
    if (body) padding.push({passwordHex, blob, digest, plaintextHex: body.toString('hex')});
  }
  return {materials: material.size, passwords: pw.size, aesAttempts, padding, scalarTests: material.size, scalarHits};
}

function main() {
  const start = Date.now(), inventory = keys(), checked = controls();
  const limits = {maxNodes: 200000, maxMs: 1000};
  fs.mkdirSync(out, {recursive: true});
  const spec = {
    hypothesis: 'DBBI directly or its integer sum lists order columns of FAED. Each DBBI g independently denotes 0 or 7. One FAED symbol may independently denote zero or its a=1..i=9 value. Interpret the transposed complete FAED as one decimal integer and require every minimal big-endian byte below 128.',
    scope: 'Original DBBI order for geometry, row-major rectangular and upper triangular placement. Eight lists, each also reversed; no decimal concatenation of list values. Ordinary incomplete columnar with ties left or right and Myszkowski; ascending/descending, apply/invert, independently reverse FAED input/output. No padding or omitted positions.',
    caveat: 'No creator source establishes g as zero, DBBI as a key, or columnar transposition. This is a conditional finite test, not a general exclusion of transposition.',
    limits, inventory, controls: checked, inputSHA256: sha(inputBytes), sourceSHA256: sha(fs.readFileSync(__filename)),
    helpers: Object.fromEntries(['columnar_decimal_constraints.cjs', 'decimal_keystream_constraints.cjs', 'zero_decimal_constraints.cjs'].map(f => [f, sha(fs.readFileSync(path.join(__dirname, f)))])),
  };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const previous = new Set(fs.readFileSync(path.join(root, '_work', 'feedback_decimal_2026-09-15', 'columnar', 'models.jsonl'), 'utf8')
    .trim().split('\n').map(JSON.parse).filter(r => r.field === 'faed').map(r => r.permutationSHA256));
  const seen = new Set(), candidates = [], partial = [];
  const fd = fs.openSync(path.join(out, 'models.jsonl'), 'w');
  const commitment = crypto.createHash('sha256');
  let proposed = 0, overlap = 0, cases = 0, nodes = 0, certificates = 0, log = '', lastProgress = Date.now();
  try {
    for (const key of inventory.keys) {
      for (const kind of ['columnar-left', 'columnar-right', 'myszkowski']) for (const descending of [false, true])
        for (const inverse of [false, true]) for (const reverseInput of [false, true]) for (const reverseOutput of [false, true]) {
          const model = {key: key.id, kind, descending, inverse, reverseInput, reverseOutput};
          const p = permutation(input.faed.length, key.ranks, model), signature = sha(p.join(','));
          commitment.update(signature + '\n'); proposed++;
          if (seen.has(signature)) continue;
          seen.add(signature); if (previous.has(signature)) overlap++;
          const source = p.map(i => input.faed[i]).join(''), results = [];
          for (const alias of 'abcdefghi') {
            const ds = [...source].map(c => c === alias ? [0, c.charCodeAt(0) - 96] : [c.charCodeAt(0) - 96]);
            const r = search(ds, limits); cases++; nodes += r.nodes; certificates += r.certificates.length;
            if (!r.complete) partial.push({model, alias, ...r});
            for (const h of r.hits) candidates.push({model, alias, ...h});
            delete r.elapsedMs;
            results.push({alias, ...r});
          }
          log += JSON.stringify({model, permutationSHA256: signature, sourceSHA256: sha(source), results}) + '\n';
          if (log.length > 1024 * 1024) { fs.writeSync(fd, log); log = ''; }
        }
      if (Date.now() - lastProgress >= 10000) {
        console.log(JSON.stringify({keysDone: key.id + 1, keys: inventory.keys.length, permutations: seen.size, cases, candidates: candidates.length, partial: partial.length, seconds: (Date.now() - start) / 1000}));
        lastProgress = Date.now();
      }
    }
    if (log) fs.writeSync(fd, log);
  } finally { fs.closeSync(fd); }
  const oracle = oracles(candidates);
  fs.writeFileSync(path.join(out, 'candidates.json'), JSON.stringify(candidates, null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'oracles.json'), JSON.stringify(oracle, null, 2) + '\n');
  const summary = {keyConstructions: inventory.constructions, rankKeys: inventory.keys.length,
    proposed, permutations: seen.size, overlapWithEarlierPermutations: overlap, newPermutations: seen.size - overlap,
    cases, complete: cases - partial.length, nodes, certificates, candidates: candidates.length, partial,
    passwords: oracle.passwords, aesAttempts: oracle.aesAttempts, scalarTests: oracle.scalarTests,
    proposalCommitmentSHA256: commitment.digest('hex'), elapsedMs: Date.now() - start};
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
module.exports = {lists, keys};
