/* Independent key construction, position ordering and integer interval counts.
 * Does not import the searcher or its cipher/ASCII helpers.
 * Run after dbbi_columnar_decimal.cjs.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const zlib = require('node:zlib');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work', 'dbbi_columnar_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
const input = JSON.parse(inputBytes);

function derivedLists(v) {
  const result = [{name: 'literal', values: v.slice()}];
  for (const w of [7, 13]) {
    const grid = Array.from({length: 91 / w}, (_, row) => v.slice(row * w, (row + 1) * w));
    result.push({name: `width${w}/rows`, values: grid.map(row => row.reduce((s, n) => s + n, 0))},
      {name: `width${w}/cols`, values: Array.from({length: w}, (_, c) => grid.reduce((s, row) => s + row[c], 0))});
  }
  const m = Array.from({length: 14}, () => Array(14).fill(0));
  for (let row = 0; row < 14; row++) for (let col = row + 1; col < 14; col++) {
    const position = row * (27 - row) / 2 + col - row - 1;
    m[row][col] = v[position];
  }
  const rows = m.map(row => row.reduce((s, n) => s + n, 0));
  const cols = Array.from({length: 14}, (_, c) => m.reduce((s, row) => s + row[c], 0));
  const sym = Array.from({length: 14}, (_, r) => m[r].reduce((s, n, c) => s + n + m[c][r], 0));
  result.push({name: 'upper/rows', values: rows}, {name: 'upper/cols', values: cols}, {name: 'upper/symmetric', values: sym});
  return result;
}

function keyInventory() {
  const distinct = new Map(), families = new Map(); let constructions = 0;
  for (let mask = 0; mask < 1024; mask++) {
    const choices = mask.toString(2).padStart(10, '0').split('').reverse(); let g = 0;
    const v = [...input.dbbi].map(c => c === 'g' ? (choices[g++] === '1' ? 7 : 0) : ' abcdefghi'.indexOf(c));
    assert.equal(g, 10);
    for (const list of derivedLists(v)) for (const reverse of [false, true]) {
      constructions++;
      const values = reverse ? Array.from({length: list.values.length}, (_, i) => list.values[list.values.length - i - 1]) : list.values;
      // Rank equals the number of distinct smaller values; no sorting/rank helper.
      const ranks = values.map(n => new Set(values.filter(v => v < n)).size), signature = ranks.toString();
      if (!families.has(list.name)) families.set(list.name, new Set()); families.get(list.name).add(signature);
      if (!distinct.has(signature)) distinct.set(signature, {
        id: distinct.size, ranks, representative: {mask, list: list.name, reverse, values},
      });
    }
  }
  return {constructions, keys: [...distinct.values()], byFamily: Object.fromEntries(
    [...families].map(([name, keys]) => [name, keys.size]))};
}

function baseRoute(n, key, kind, descending) {
  const positions = Array.from({length: n}, (_, i) => i), sign = descending ? -1 : 1, w = key.length;
  positions.sort((a, b) => {
    const ca = a % w, cb = b % w, ra = Math.floor(a / w), rb = Math.floor(b / w);
    const rank = sign * (key[ca] - key[cb]);
    if (rank) return rank;
    return kind === 'myszkowski' ? ra - rb || ca - cb : (kind === 'columnar-right' ? cb - ca : ca - cb) || ra - rb;
  });
  return positions;
}
function transform(route, m) {
  const n = route.length, p = Array(n);
  for (let i = 0; i < n; i++) {
    const before = m.inverse ? route[i] : i, after = m.inverse ? i : route[i];
    p[m.reverseOutput ? n - before - 1 : before] = m.reverseInput ? n - after - 1 : after;
  }
  return p;
}

const p10 = [1n], p128 = [1n];
for (let i = 1; i <= 600; i++) { p10.push(p10[i - 1] * 10n); p128.push(p128[i - 1] * 128n); }
function count(n) {
  if (n < 0n) return 0n;
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  const b = Buffer.from(h, 'hex'); let total = 0n;
  for (let i = 0; i < b.length; i++) {
    total += BigInt(Math.min(b[i], 128)) * p128[b.length - i - 1];
    if (b[i] >= 128) return total;
  }
  return total + 1n;
}

async function main() {
  const started = Date.now();
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'spec.json')));
  const saved = JSON.parse(fs.readFileSync(path.join(out, 'summary.json')));
  assert.equal(sha(inputBytes), spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(__dirname, 'dbbi_columnar_decimal.cjs'))), spec.sourceSHA256);
  for (const [file, hash] of Object.entries(spec.helpers)) assert.equal(sha(fs.readFileSync(path.join(__dirname, file))), hash);
  const inventory = keyInventory(); assert.deepEqual(inventory, spec.inventory);
  let accepted = 0n;
  for (let n = 0; n < 65536; n++) { if ((n & 255) < 128 && (n >> 8) < 128) accepted++; assert.equal(count(BigInt(n)), accepted); }
  for (let width = 1; width <= 300; width++) assert.equal(count(256n ** BigInt(width) - 1n), 128n ** BigInt(width));
  const columnarText = 'UNFILLEDBLOCK';
  assert.equal(baseRoute(columnarText.length, [3, 1, 2], 'columnar-left', false).map(i => columnarText[i]).join(''), 'NLDOFLBCUIELK');
  const myszText = 'Incomplete columnar with pattern word key and letters under same number taken off by row from top to bottom'.replace(/\W/g, '').toUpperCase();
  assert.equal(baseRoute(myszText.length, [2, 1, 3, 1, 3, 1], 'myszkowski', false).map(i => myszText[i]).join(''),
    'NOPEE OUNRI HATRW RKYNL TESNE SMNME TKNFB RWRMO TBTOI LLWTO ATDER OOTOC MTCMA TPEND EDERU RAUBA EFYFO POTM'.replaceAll(' ', ''));
  const previous = new Set(fs.readFileSync(path.join(root, '_work', 'feedback_decimal_2026-09-15', 'columnar', 'models.jsonl'), 'utf8')
    .trim().split('\n').map(JSON.parse).filter(r => r.field === 'faed').map(r => r.permutationSHA256));
  const expected = new Set(), commitment = crypto.createHash('sha256'); let proposed = 0, overlap = 0;
  const n = input.faed.length;
  for (const key of inventory.keys) {
    for (const kind of ['columnar-left', 'columnar-right', 'myszkowski']) for (const descending of [false, true]) {
      const route = baseRoute(n, key.ranks, kind, descending);
      for (const inverse of [false, true]) for (const reverseInput of [false, true]) for (const reverseOutput of [false, true]) {
        const p = transform(route, {inverse, reverseInput, reverseOutput}), sig = sha(p.toString());
        commitment.update(sig + '\n'); proposed++;
        if (!expected.has(sig) && previous.has(sig)) overlap++;
        expected.add(sig);
      }
    }
  }
  assert.equal(proposed, saved.proposed); assert.equal(expected.size, saved.permutations);
  assert.equal(overlap, saved.overlapWithEarlierPermutations); assert.equal(expected.size - overlap, saved.newPermutations);
  assert.equal(commitment.digest('hex'), saved.proposalCommitmentSHA256);
  console.log(JSON.stringify({stage: 'inventory', keys: inventory.keys.length, proposed, permutations: expected.size, overlap, seconds: (Date.now() - started) / 1000}));

  let models = 0, cases = 0, certificates = 0, nodes = 0, hits = 0, partial = 0, lastProgress = Date.now();
  const transcript = crypto.createHash('sha256');
  const plainLog = path.join(out, 'models.jsonl');
  const rawStream = fs.createReadStream(fs.existsSync(plainLog) ? plainLog : plainLog + '.gz');
  const stream = fs.existsSync(plainLog) ? rawStream : rawStream.pipe(zlib.createGunzip());
  stream.on('data', chunk => transcript.update(chunk));
  const lines = readline.createInterface({input: stream, crlfDelay: Infinity});
  for await (const line of lines) {
    const record = JSON.parse(line), m = record.model;
    assert(Number.isInteger(m.key) && m.key >= 0 && m.key < inventory.keys.length);
    assert(['columnar-left', 'columnar-right', 'myszkowski'].includes(m.kind));
    for (const b of ['descending', 'inverse', 'reverseInput', 'reverseOutput']) assert.equal(typeof m[b], 'boolean');
    const p = transform(baseRoute(n, inventory.keys[m.key].ranks, m.kind, m.descending), m), sig = sha(p.toString());
    assert.equal(sig, record.permutationSHA256); assert(expected.delete(sig), 'Missing or duplicate permutation');
    const source = p.map(i => input.faed[i]).join(''); assert.equal(sha(source), record.sourceSHA256);
    assert.deepEqual(record.results.map(r => r.alias), [...'abcdefghi']);
    for (const r of record.results) {
      const low = BigInt([...source].map(c => c === r.alias ? 0 : ' abcdefghi'.indexOf(c)).join(''));
      const weights = [...source].flatMap((c, i) => c === r.alias ? [BigInt(' abcdefghi'.indexOf(c)) * p10[n - i - 1]] : []);
      const tails = Array(weights.length + 1).fill(0n);
      for (let i = weights.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
      assert.equal(weights.length, r.ambiguous);
      const ranges = [...r.certificates.map(mask => ({mask, type: 'excluded'})),
        ...r.hits.map(hit => ({mask: hit.mask, type: 'hit', hit})), ...r.pending.map(mask => ({mask, type: 'pending'}))]
        .sort((a, b) => a.mask.localeCompare(b.mask));
      let cover = 0n;
      for (let j = 0; j < ranges.length; j++) {
        const item = ranges[j], mask = item.mask;
        assert.match(mask, /^[01]*$/); assert(mask.length <= weights.length);
        if (j) assert(!mask.startsWith(ranges[j - 1].mask));
        let lo = low; for (let bit = 0; bit < mask.length; bit++) if (mask[bit] === '1') lo += weights[bit];
        const hi = lo + tails[mask.length];
        if (item.type === 'excluded') { assert.equal(count(hi) - count(lo - 1n), 0n); certificates++; }
        if (item.type === 'hit') {
          assert.equal(mask.length, weights.length); assert.equal(item.hit.decimal, lo.toString());
          let h = lo.toString(16); if (h.length % 2) h = '0' + h;
          assert.equal(item.hit.hex, h); assert.equal(count(lo) - count(lo - 1n), 1n); hits++;
        }
        cover += 1n << BigInt(weights.length - mask.length);
      }
      assert.equal(cover, 1n << BigInt(weights.length)); assert.equal(r.complete, r.pending.length === 0);
      if (!r.complete) partial++; nodes += r.nodes; cases++;
    }
    models++;
    if (Date.now() - lastProgress >= 10000) {
      console.log(JSON.stringify({stage: 'certificates', models, cases, remainingModels: expected.size, seconds: (Date.now() - started) / 1000}));
      lastProgress = Date.now();
    }
  }
  assert.equal(expected.size, 0); assert.equal(models, saved.permutations); assert.equal(cases, saved.cases);
  assert.equal(nodes, saved.nodes); assert.equal(certificates, saved.certificates); assert.equal(hits, saved.candidates);
  assert.equal(partial, saved.partial.length); assert.equal(cases - partial, saved.complete);
  if (!hits) {
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out, 'candidates.json'))), []);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out, 'oracles.json'))),
      {materials: 0, passwords: 0, aesAttempts: 0, padding: [], scalarTests: 0, scalarHits: []});
  }
  const result = {verifiedAt: new Date().toISOString(), keyConstructions: inventory.constructions, rankKeys: inventory.keys.length,
    proposed, permutations: models, overlapWithEarlierPermutations: overlap, cases, nodes, certificates, hits, partial,
    allDeclaredModelsPresent: true, allMasksCovered: partial === 0, allExcluded: hits === 0 && partial === 0,
    controls: {integerCounts: 65536, largeWidths: 300, acaColumnar: true, acaMyszkowski: true},
    modelsSHA256: transcript.digest('hex'), verifierSHA256: sha(fs.readFileSync(__filename)), elapsedMs: Date.now() - started};
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
