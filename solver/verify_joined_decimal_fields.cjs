'use strict';
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib');
const crypto = require('node:crypto'), assert = require('node:assert/strict');
const readline = require('node:readline');
const {countUtf8} = require('./verify_utf8_decimal.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/joined_fields_2026-09-16');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const read = name => JSON.parse(fs.readFileSync(path.join(out, name), 'utf8'));
const strict = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});
function bytesOf(n) {
  const bytes = []; do { bytes.unshift(Number(n % 256n)); n /= 256n; } while (n); return Buffer.from(bytes);
}
function controls() {
  let small = 0, large = 0;
  for (const order of ['big', 'little']) {
    let expected = 0n;
    for (let n = 0n; n < 65536n; n++) {
      const b = bytesOf(n); if (order === 'little') b.reverse();
      try { strict.decode(b); expected++; } catch {}
      assert.equal(countUtf8(n, order), expected); small++;
    }
    for (let width = 1; width <= 300; width++) {
      const b = Buffer.alloc(width, width % 128); b[0] = 1;
      const n = BigInt('0x' + b.toString('hex'));
      assert.equal(countUtf8(n, order) - countUtf8(n - 1n, order), 1n); large++;
    }
  }
  return {smallIntegers: small, largeWidths: large};
}
function endpointFunction(symbols, alias, scale = 1n, offset = 0n) {
  const base = [...symbols].map(c => String(c.charCodeAt(0) - 96));
  const positions = [...symbols].flatMap((c, i) => alias.includes(c) ? [i] : []);
  return (mask, high) => {
    const digits = [...base];
    for (let branch = 0; branch < positions.length; branch++) if (!(branch < mask.length ? mask[branch] === '1' : high)) digits[positions[branch]] = '0';
    return BigInt(digits.join('')) * scale + offset;
  };
}
function verifyTree(r, endpoint, order, spill = 0n) {
  let coverage = 0n; const leaves = [];
  for (const mask of r.certificates) {
    assert.match(mask, /^[01]*$/); assert(mask.length <= r.ambiguous);
    const lo = endpoint(mask, false), hi = endpoint(mask, true) + spill;
    assert.equal(countUtf8(hi, order) - countUtf8(lo - 1n, order), 0n);
    coverage += 1n << BigInt(r.ambiguous - mask.length); leaves.push(mask);
  }
  for (const hit of r.hits) {
    assert.equal(hit.mask.length, r.ambiguous); assert.match(hit.mask, /^[01]*$/);
    const n = endpoint(hit.mask, false);
    if (spill) {
      assert.equal(hit.base, n.toString()); assert(countUtf8(n + spill, order) > countUtf8(n - 1n, order));
    } else {
      const b = bytesOf(n); if (order === 'little') b.reverse();
      assert.equal(hit.decimal, n.toString()); assert.equal(hit.hex, b.toString('hex')); assert.equal(hit.text, strict.decode(b));
      assert.equal(countUtf8(n, order) - countUtf8(n - 1n, order), 1n);
    }
    coverage++; leaves.push(hit.mask);
  }
  for (const mask of r.pending) {assert.match(mask, /^[01]*$/); assert(mask.length <= r.ambiguous); coverage += 1n << BigInt(r.ambiguous - mask.length); leaves.push(mask);}
  leaves.sort(); for (let i = 1; i < leaves.length; i++) assert(!leaves[i].startsWith(leaves[i - 1]));
  assert.equal(coverage, 1n << BigInt(r.ambiguous)); assert.equal(r.complete, r.pending.length === 0); assert(r.complete);
  assert.equal(r.nodes, 2 * leaves.length - 1);
}
async function main() {
  const prefixOnly = process.argv[2] === 'prefixes'; assert(process.argv[2] === undefined || prefixOnly);
  const started = Date.now(), spec = read('spec.json');
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
  assert.equal(sha(raw), spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/joined_decimal_fields.cjs'))), spec.sourceSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver/utf8_decimal_constraints.cjs'))), spec.helperSHA256);
  const options = [];
  for (let mask = 1; mask < 512; mask++) {
    const letters = [...'abcdefghi'].filter((_, i) => mask & (1 << i)).join('');
    if (letters.length <= 2) options.push(letters);
  }
  assert.deepEqual([...options].sort(), [...spec.aliases].sort());
  const checked = controls(), prefixBytes = zlib.gunzipSync(fs.readFileSync(path.join(out, 'prefixes.json.gz')));
  const prefixes = JSON.parse(prefixBytes), prefixIDs = new Set();
  const prefixSummary = {trees: prefixes.length, nodes: 0, certificates: 0, frontiers: 0, partial: 0, prefixesSHA256: sha(prefixBytes)};
  for (const p of prefixes) {
    assert(['dbbi', 'faed'].includes(p.first)); assert(typeof p.reverse === 'boolean'); assert(options.includes(p.alias)); assert(['big', 'little'].includes(p.order));
    const id = [p.first, p.reverse, p.alias, p.order].join('/'); assert(!prefixIDs.has(id)); prefixIDs.add(id);
    const s = p.reverse ? [...input[p.first]].reverse().join('') : input[p.first];
    const second = p.first === 'dbbi' ? 'faed' : 'dbbi'; assert.equal(p.tailLength, input[second].length);
    assert.equal(p.ambiguous, [...s].filter(c => p.alias.includes(c)).length);
    const scale = 10n ** BigInt(p.tailLength);
    verifyTree(p, endpointFunction(s, p.alias, scale), p.order, scale - 1n);
    prefixSummary.nodes += p.nodes; prefixSummary.certificates += p.certificates.length; prefixSummary.frontiers += p.hits.length;
  }
  assert.equal(prefixIDs.size, 360); assert.deepEqual(prefixSummary, read('prefix_summary.json'));
  if (prefixOnly) {
    const result = {verifiedAt: new Date().toISOString(), verifierSHA256: sha(fs.readFileSync(__filename)),
      independentCounterSHA256: sha(fs.readFileSync(path.join(root, 'solver/verify_utf8_decimal.cjs'))),
      prefixSummary, allFirstFieldMasksCovered: true, allPrefixIntervalsCountedIndependently: true,
      controls: checked, elapsedMs: Date.now() - started, scope: 'Only the relaxed prefix trees. Full concatenation cases must still be verified.', finalPasswordFound: false};
    fs.writeFileSync(path.join(out, 'prefix_verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2)); return;
  }
  const summary = read('summary.json'); assert.deepEqual(prefixSummary, summary.prefixSummary);
  const ids = new Set(), candidates = [], byFirst = {}, hash = crypto.createHash('sha256');
  let cases = 0, nodes = 0, certificates = 0, partial = 0, branches = 0;
  const stream = fs.createReadStream(path.join(out, 'cases.jsonl.gz')).pipe(zlib.createGunzip());
  const lines = readline.createInterface({input: stream, crlfDelay: Infinity});
  for await (const line of lines) {
    hash.update(line + '\n');
    const r = JSON.parse(line);
    assert(['dbbi', 'faed'].includes(r.first)); assert(['big', 'little'].includes(r.order));
    assert(typeof r.reverseD === 'boolean' && typeof r.reverseF === 'boolean');
    assert(options.includes(r.aliasD) && options.includes(r.aliasF));
    const model = {first: r.first, reverseD: r.reverseD, reverseF: r.reverseF, aliasD: r.aliasD, aliasF: r.aliasF, order: r.order};
    const id = JSON.stringify(model); assert(!ids.has(id)); ids.add(id);
    const p = prefixes[r.prefixId]; assert(p);
    const reverse = {dbbi: r.reverseD, faed: r.reverseF}, alias = {dbbi: r.aliasD, faed: r.aliasF};
    assert.equal(p.first, r.first); assert.equal(p.reverse, reverse[r.first]); assert.equal(p.alias, alias[r.first]); assert.equal(p.order, r.order);
    const second = r.first === 'dbbi' ? 'faed' : 'dbbi', symbols = reverse[second] ? [...input[second]].reverse().join('') : input[second];
    const ambiguous = [...symbols].filter(c => alias[second].includes(c)).length, seenBranches = new Set(); let hits = 0;
    for (const b of r.branches) {
      assert(Number.isInteger(b.frontier) && b.frontier >= 0 && b.frontier < p.hits.length); assert(!seenBranches.has(b.frontier)); seenBranches.add(b.frontier);
      assert.equal(b.ambiguous, ambiguous);
      verifyTree(b, endpointFunction(symbols, alias[second], 1n, BigInt(p.hits[b.frontier].base)), r.order);
      nodes += b.nodes; certificates += b.certificates.length; branches++;
      for (const hit of b.hits) {candidates.push({...model, firstMask: p.hits[b.frontier].mask, ...hit}); hits++;}
    }
    assert.equal(seenBranches.size, p.hits.length); assert(r.complete); cases++;
    byFirst[r.first] ||= {cases: 0, candidates: 0, partial: 0}; byFirst[r.first].cases++; byFirst[r.first].candidates += hits;
    if (cases % 4050 === 0) console.log(JSON.stringify({verifiedCases: cases, branches, certificates}));
  }
  assert.equal(ids.size, 32400); assert.equal(cases, spec.cases); assert.equal(cases, summary.cases);
  assert.equal(nodes, summary.nodes); assert.equal(certificates, summary.certificates); assert.equal(partial, 0);
  assert.deepEqual(summary.incomplete, []); assert.equal(cases, summary.complete);
  assert.equal(candidates.length, summary.candidates); assert.deepEqual(candidates, read('candidates.json')); assert.deepEqual(byFirst, summary.byFirst);
  const casesSHA256 = hash.digest('hex'); assert.equal(casesSHA256, summary.casesSHA256); assert.equal(branches, summary.branches);
  const result = {verifiedAt: new Date().toISOString(), verifierSHA256: sha(fs.readFileSync(__filename)),
    independentCounterSHA256: sha(fs.readFileSync(path.join(root, 'solver/verify_utf8_decimal.cjs'))),
    casesSHA256, cases, nodes, certificates, branches, prefixSummary, candidates: candidates.length, partial,
    allModelsPresent: true, allMasksCovered: true, allIntervalsCountedIndependently: true,
    controls: checked, elapsedMs: Date.now() - started, finalPasswordFound: false};
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
