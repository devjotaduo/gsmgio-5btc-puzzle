'use strict';
// Independent character-level suffix DP and base-128 digit counter.
// Checks every interval certificate and complete deletion/zero-mask coverage.
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), zeroMode = process.argv.includes('--with-zero'), fixedZero = process.argv.includes('--fixed-zero');
assert(!(zeroMode && fixedZero));
const dir = path.join(root, '_work/optional_null_decimal_2026-09-16', ...(zeroMode ? ['with_zero'] : fixedZero ? ['fixed_zero'] : []));
const hash = b => crypto.createHash('sha256').update(b).digest('hex'), read = f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
function countSeven(n) {
  if (n < 0n) return 0n;
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  const digits = [...Buffer.from(h, 'hex')]; let result = 0n;
  for (let i = 0; i < digits.length; i++) {
    result += BigInt(Math.min(digits[i], 128)) * 128n ** BigInt(digits.length - i - 1);
    if (digits[i] >= 128) return result;
  }
  return result + 1n;
}
function suffixes(digits, optional, zeros) {
  const low = Array.from({length: digits.length + 1}, () => []), high = Array.from({length: digits.length + 1}, () => []), counts = new Array(digits.length + 1).fill(0);
  low[digits.length][0] = high[digits.length][0] = '';
  for (let i = digits.length - 1; i >= 0; i--) {
    counts[i] = counts[i + 1] + Number(optional[i]);
    for (let deleted = 0; deleted <= counts[i]; deleted++) {
      const minCandidates = [], maxCandidates = [];
      if (low[i + 1][deleted] !== undefined) {
        minCandidates.push((zeros && optional[i] ? '0' : digits[i]) + low[i + 1][deleted]);
        maxCandidates.push(digits[i] + high[i + 1][deleted]);
      }
      if (optional[i] && deleted > 0 && low[i + 1][deleted - 1] !== undefined) {
        minCandidates.push(low[i + 1][deleted - 1]); maxCandidates.push(high[i + 1][deleted - 1]);
      }
      assert(minCandidates.length > 0);
      low[i][deleted] = minCandidates.sort()[0]; high[i][deleted] = maxCandidates.sort().at(-1);
      assert.equal(low[i][deleted].length, digits.length - i - deleted);
    }
  }
  return {low, high};
}
function choose(n, k) {if (k < 0 || k > n) return 0n; let result = 1n; for (let i = 1; i <= k; i++) result = result * BigInt(n - i + 1) / BigInt(i); return result;}
function main() {
  const spec = read('spec.json'), summary = read('summary.json'), raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
  assert.equal(hash(raw), spec.inputSHA256); assert.equal(spec.allowZero, zeroMode);
  assert.equal(hash(fs.readFileSync(path.join(root, 'solver/optional_null_decimal.cjs'))), spec.sourceSHA256);
  if (fixedZero) {assert(spec.fixedZero); assert.equal(hash(fs.readFileSync(path.join(root, 'solver/fixed_zero_optional_null.cjs'))), spec.runnerSHA256);}
  assert.equal(hash(fs.readFileSync(path.join(root, 'solver/zero_decimal_constraints.cjs'))), spec.successorSHA256);
  let counterControls = 0, counted = 0n;
  for (let n = 0; n < 65536; n++) {if ((n & 0x8080) === 0) counted++; assert.equal(countSeven(BigInt(n)), counted); counterControls++;}
  // Exhaustive optional-character suffix extrema, with both zero modes.
  let suffixControls = 0;
  for (const digits of ['10929', '99991', '999', '12780']) for (const alias of '19') for (const zeros of [false, true]) {
    const optional = [...digits].map(c => c === alias), positions = optional.flatMap((v, i) => v ? [i] : []), dp = suffixes(digits, optional, zeros), byDeleted = new Map();
    const radix = zeros ? 3 : 2;
    for (let mask = 0; mask < radix ** positions.length; mask++) {
      let code = mask, deleted = 0; const choices = new Map();
      for (const pos of positions) {choices.set(pos, code % radix); code = Math.floor(code / radix);}
      const text = [...digits].map((c, i) => {const action = choices.get(i) || 0; if (action === 1) {deleted++; return '';} return action === 2 ? '0' : c;}).join('');
      if (!byDeleted.has(deleted)) byDeleted.set(deleted, []); byDeleted.get(deleted).push(text);
    }
    for (const [deleted, strings] of byDeleted) {strings.sort(); assert.equal(dp.low[0][deleted], strings[0]); assert.equal(dp.high[0][deleted], strings.at(-1)); suffixControls++;}
  }
  const ids = new Set(), allCandidates = new Map(), totals = {nodes: 0, certificates: 0, roots: 0, terminalHits: 0}; const coverage = [];
  for (const record of summary.cases) {
    assert(!ids.has(record.id)); ids.add(record.id); assert(record.complete);
    assert(['dbbi', 'faed'].includes(record.field) && 'abcdefghi'.includes(record.alias) && record.alias.length === 1 && typeof record.reverse === 'boolean');
    assert.equal(record.id, [record.field, record.reverse ? 'reverse' : 'forward', record.alias, ...(fixedZero ? [record.zeroAlias] : [])].join('_'));
    const gz = fs.readFileSync(path.join(dir, record.file)); assert.equal(hash(gz), record.artifactSHA256);
    const r = JSON.parse(zlib.gunzipSync(gz)), text = record.reverse ? [...input[record.field]].reverse().join('') : input[record.field];
    for (const key of ['field', 'reverse', 'alias', ...(fixedZero ? ['zeroAlias'] : [])]) assert.equal(r[key], record[key]);
    if (fixedZero) assert(record.zeroAlias !== record.alias && record.zeroAlias.length === 1 && 'abcdefghi'.includes(record.zeroAlias));
    const digits = [...text].map(c => fixedZero && c === record.zeroAlias ? 0 : c.charCodeAt(0) - 96).join(''), optional = [...text].map(c => c === record.alias), positions = optional.flatMap((v, i) => v ? [i] : []);
    const chunks = []; let last = 0; for (const p of positions) {chunks.push(digits.slice(last, p)); last = p + 1;} chunks.push(digits.slice(last));
    assert.equal(r.digits, digits); assert.deepEqual(r.positions, positions); assert.deepEqual(r.chunks, chunks); assert.equal(r.allowZero, zeroMode);
    const m = positions.length, dp = suffixes(digits, optional, zeroMode), visited = new Set(), memo = new Map(), found = new Set(), identities = new Set();
    assert.equal(r.optionalCount, m); assert.equal(record.optionalCount, m);
    let certificates = 0, hits = 0;
    for (const n of r.nodes) {const key = [n.index, n.deleted, n.prefix].join('/'); assert(!identities.has(key)); identities.add(key);}
    function visit(id) {
      assert(Number.isInteger(id) && id >= 0 && id < r.nodes.length); if (memo.has(id)) return memo.get(id);
      const n = r.nodes[id], i = n.index, k = n.deleted, p = BigInt(n.prefix); assert(Number.isInteger(i) && i >= 0 && i <= m && Number.isInteger(k) && k >= 0 && k <= m - i); visited.add(id);
      const at = i < m ? positions[i] : digits.length, exponent = digits.length - at - k;
      const lo = p * 10n ** BigInt(exponent) + BigInt(dp.low[at][k] || '0'), hi = p * 10n ** BigInt(exponent) + BigInt(dp.high[at][k] || '0');
      const count = countSeven(hi) - countSeven(lo - 1n), expectedCoverage = choose(m - i, k) * BigInt(zeroMode ? 2 : 1) ** BigInt(m - i - k);
      let covered = 0n;
      if (n.kind === 'excluded') {assert.equal(count, 0n); certificates++; covered = expectedCoverage;}
      else if (n.kind === 'hit') {assert.equal(i, m); assert.equal(k, 0); assert.equal(lo, hi); assert.equal(count, 1n); hits++; found.add(String(p)); covered = 1n;}
      else {
        assert.equal(n.kind, 'branch'); assert(i < m && count > 0n);
        const width = chunks[i + 1].length, base = 10n ** BigInt(width), literal = BigInt(chunks[i + 1] || '0'), wanted = [];
        if (k <= m - i - 1) wanted.push({action: 'keep', index: i + 1, deleted: k, prefix: String((p * 10n + BigInt(digits[positions[i]])) * base + literal)});
        if (zeroMode && k <= m - i - 1) wanted.push({action: 'zero', index: i + 1, deleted: k, prefix: String(p * 10n * base + literal)});
        if (k > 0) wanted.push({action: 'delete', index: i + 1, deleted: k - 1, prefix: String(p * base + literal)});
        assert.equal(n.children.length, wanted.length);
        wanted.forEach((w, j) => {const child = n.children[j]; assert.equal(child.action, w.action); const actual = r.nodes[child.id]; assert(actual); assert.equal(actual.index, w.index); assert.equal(actual.deleted, w.deleted); assert.equal(actual.prefix, w.prefix); covered += visit(child.id);});
      }
      assert.equal(covered, expectedCoverage); memo.set(id, covered); return covered;
    }
    assert.equal(r.roots.length, m + 1); let totalMasks = 0n;
    r.roots.forEach((rr, deleted) => {assert.equal(rr.deleted, deleted); const node = r.nodes[rr.id]; assert(node); assert.equal(node.index, 0); assert.equal(node.deleted, deleted); assert.equal(node.prefix, String(BigInt(chunks[0] || '0'))); totalMasks += visit(rr.id);});
    assert.equal(totalMasks, BigInt(zeroMode ? 3 : 2) ** BigInt(m)); assert.equal(String(totalMasks), r.masks); assert.equal(r.masks, record.masks);
    assert.equal(visited.size, r.nodes.length); assert.equal(r.nodes.length, record.nodes); assert.equal(certificates, record.excluded); assert.equal(hits, record.hits);
    assert.deepEqual([...found].sort(), r.hits.slice().sort()); assert.equal(found.size, record.distinctCandidates);
    for (const decimal of r.hits) {let hex = BigInt(decimal).toString(16); if (hex.length % 2) hex = '0' + hex; if (!allCandidates.has(hex)) allCandidates.set(hex, {hex, decimal, source: record.id});}
    totals.nodes += visited.size; totals.certificates += certificates; totals.roots += r.roots.length; totals.terminalHits += hits;
    coverage.push({id: record.id, masks: String(totalMasks)});
  }
  const expectedCases = fixedZero ? 288 : 36;
  assert.equal(ids.size, expectedCases); assert.equal(summary.completeCases, expectedCases); assert.equal(summary.distinctCandidates, allCandidates.size); assert.deepEqual(read('candidates.json'), [...allCandidates.values()]);
  const result = {verifiedAt: new Date().toISOString(), verifierSHA256: hash(fs.readFileSync(__filename)), solverSHA256: spec.sourceSHA256, summarySHA256: hash(fs.readFileSync(path.join(dir, 'summary.json'))),
    allowZero: zeroMode, fixedZero, completeCases: ids.size, ...totals, distinctCandidates: allCandidates.size, counterControls, suffixControls, maskCoverage: coverage, allPassed: true, finalPasswordFound: false};
  fs.writeFileSync(path.join(dir, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({...result, maskCoverage: undefined}, null, 2));
}
if (require.main === module) main();
