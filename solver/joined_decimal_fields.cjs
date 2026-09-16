'use strict';
// A single decimal integer made from both numeric fields. The independently
// zeroable letters can differ between fields; no fitted plaintext or stripping.
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib');
const crypto = require('node:crypto'), assert = require('node:assert/strict');
const {once} = require('node:events');
const {nextUtf8, bytesOf} = require('./utf8_decimal_constraints.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/joined_fields_2026-09-16');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const strict = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});

function aliases() {
  const result = [...'abcdefghi'];
  for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) result.push(String.fromCharCode(97 + a, 97 + b));
  return result;
}

function search(parts, order, {maxNodes = 2000000, maxMs = 5000} = {}) {
  assert(['big', 'little'].includes(order));
  const domains = parts.flatMap(({symbols, alias}) => {
    assert.match(symbols, /^[a-i]+$/); assert.match(alias, /^[a-i]{1,2}$/);
    assert.equal(new Set(alias).size, alias.length);
    return [...symbols].map(c => { const digit = c.charCodeAt(0) - 96; return alias.includes(c) ? [0, digit] : [digit]; });
  });
  const low = BigInt(domains.map(d => d[0]).join('')), weights = [];
  let place = 1n;
  for (let i = domains.length - 1; i >= 0; i--) {
    if (domains[i].length === 2) weights.unshift(BigInt(domains[i][1]) * place);
    place *= 10n;
  }
  const tails = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  const certificates = [], hits = [], pending = [];
  let nodes = 0; const started = Date.now();
  function visit(i, value, mask) {
    if (nodes >= maxNodes || Date.now() - started >= maxMs) { pending.push(mask); return; }
    nodes++;
    if (nextUtf8(value, order) > value + tails[i]) { certificates.push(mask); return; }
    if (i === weights.length) {
      const bytes = bytesOf(value); if (order === 'little') bytes.reverse();
      hits.push({mask, decimal: value.toString(), hex: bytes.toString('hex'), text: strict.decode(bytes)}); return;
    }
    visit(i + 1, value, mask + '0'); visit(i + 1, value + weights[i], mask + '1');
  }
  visit(0, low, '');
  const excluded = certificates.reduce((n, mask) => n + (1n << BigInt(weights.length - mask.length)), 0n);
  const unfinished = pending.reduce((n, mask) => n + (1n << BigInt(weights.length - mask.length)), 0n);
  assert.equal(excluded + unfinished + BigInt(hits.length), 1n << BigInt(weights.length));
  return {ambiguous: weights.length, nodes, complete: pending.length === 0, certificates, hits, pending};
}

function controls() {
  let bruteForceMasks = 0, planted = 0;
  for (const first of ['a', 'bg', 'ce']) for (const second of ['b', 'ah', 'gi']) for (const order of ['big', 'little']) {
    const parts = [{symbols: 'abgc', alias: first}, {symbols: 'ighbe', alias: second}];
    const choices = parts.flatMap(p => [...p.symbols].map(c => p.alias.includes(c) ? [0, c.charCodeAt(0) - 96] : [c.charCodeAt(0) - 96]));
    let values = ['']; for (const c of choices) values = values.flatMap(v => c.map(d => v + d));
    const expected = [];
    for (const value of values) {
      const n = BigInt(value), bytes = bytesOf(n); if (order === 'little') bytes.reverse();
      try { strict.decode(bytes); expected.push(n.toString()); } catch {}
    }
    const result = search(parts, order);
    assert(result.complete); assert.deepEqual(result.hits.map(h => h.decimal).sort(), expected.sort()); bruteForceMasks++;
    const factor = 10n ** BigInt(parts[1].symbols.length);
    const prefix = walk(domain(parts[0].symbols, first, factor), order, 0n, factor - 1n), decomposed = [];
    assert(prefix.complete);
    for (const frontier of prefix.hits) {
      const r = walk(domain(parts[1].symbols, second), order, BigInt(frontier.base));
      assert(r.complete); decomposed.push(...r.hits.map(h => h.decimal));
    }
    assert.deepEqual(decomposed.sort(), expected.sort());
    for (const text of ['Matrix. Azul e amarelo.', 'Olá, escolha 🔑.', 'lastwordsbeforearchichoicethispassword']) {
      const bytes = Buffer.from(text); if (order === 'little') bytes.reverse();
      const n = BigInt('0x' + bytes.toString('hex')), decimal = n.toString(), cut = Math.floor(decimal.length / 3);
      const encode = (digits, alias) => [...digits].map(d => d === '0' ? alias[0] : String.fromCharCode(96 + Number(d))).join('');
      const encoded = [{symbols: encode(decimal.slice(0, cut), first), alias: first}, {symbols: encode(decimal.slice(cut), second), alias: second}];
      const recovered = search(encoded, order);
      assert(recovered.complete && recovered.hits.some(h => h.decimal === n.toString() && h.text === text)); planted++;
    }
  }
  return {bruteForceMasks, twoLevelBruteForceComparisons: bruteForceMasks, planted};
}

function domain(symbols, alias, scale = 1n) {
  let low = 0n, place = scale; const weights = [];
  for (const c of [...symbols].reverse()) {
    const digit = BigInt(c.charCodeAt(0) - 96);
    if (alias.includes(c)) weights.unshift(digit * place); else low += digit * place;
    place *= 10n;
  }
  const tails = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tails[i] = tails[i + 1] + weights[i];
  return {low, weights, tails};
}

function walk(d, order, offset = 0n, spill = 0n) {
  const certificates = [], hits = [], pending = [];
  let nodes = 0; const started = Date.now();
  function visit(i, n, mask) {
    if (nodes >= 2000000 || Date.now() - started > 30000) {pending.push(mask); return;}
    nodes++;
    if (nextUtf8(n, order) > n + d.tails[i] + spill) {certificates.push(mask); return;}
    if (i === d.weights.length) {
      if (spill) hits.push({mask, base: n.toString()});
      else {
        const b = bytesOf(n); if (order === 'little') b.reverse();
        hits.push({mask, decimal: n.toString(), hex: b.toString('hex'), text: strict.decode(b)});
      }
      return;
    }
    visit(i + 1, n, mask + '0'); visit(i + 1, n + d.weights[i], mask + '1');
  }
  visit(0, offset + d.low, '');
  const leaves = [...certificates, ...hits.map(h => h.mask), ...pending];
  assert.equal(leaves.reduce((n, m) => n + (1n << BigInt(d.weights.length - m.length)), 0n), 1n << BigInt(d.weights.length));
  return {ambiguous: d.weights.length, nodes, complete: pending.length === 0, certificates, hits, pending};
}

async function main() {
  fs.mkdirSync(out, {recursive: true});
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(raw);
  assert.equal(input.dbbi.length, 91); assert.equal(input.faed.length, 570);
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
  const checked = controls(), options = aliases();
  save('spec.json', {createdAt: new Date().toISOString(), inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)),
    helperSHA256: sha(fs.readFileSync(path.join(root, 'solver/utf8_decimal_constraints.cjs'))),
    hypothesis: 'DBBI and FAED form one decimal integer after removing the intervening binary matrixsumlist instruction. Test both field orders and independent reversals of each field. a..i retain 1..9; each field independently chooses one or two letters whose occurrences may additionally denote zero.',
    output: 'Canonical minimal integer bytes must form complete strict UTF-8 in either big- or little-endian order. Leading zero digits do not add byte padding. Control characters are allowed in the validity test.',
    fields: ['dbbi', 'faed'], aliases: options, cases: 2 * 2 * 2 * 45 * 45 * 2,
    controls: checked, limits: {maxNodesPerTree: 2000000, maxMsPerTree: 30000},
    decomposition: 'N = A * 10^length(B) + B. First enumerate A with B relaxed to the entire interval [0,10^length(B)-1]. Reuse those prefix exclusions across both orientations and every zeroable-letter set of B. At surviving A assignments, search the actual B domain.',
    scope: 'Only direct concatenation of these two complete fields with these digit values. No interleaving, other segments, insertions/deletions, more than two zeroable letters per field, or additional arithmetic/transposition.'});
  const prefixes = [], prefixIndex = new Map(), domains = new Map();
  for (const first of ['dbbi', 'faed']) for (const reverse of [false, true]) for (const alias of options) for (const order of ['big', 'little']) {
    const symbols = reverse ? [...input[first]].reverse().join('') : input[first];
    const second = first === 'dbbi' ? 'faed' : 'dbbi', factor = 10n ** BigInt(input[second].length);
    const result = walk(domain(symbols, alias, factor), order, 0n, factor - 1n);
    const key = [first, reverse, alias, order].join('/'); prefixIndex.set(key, prefixes.length);
    prefixes.push({first, reverse, alias, order, tailLength: input[second].length, ...result});
    domains.set([first, reverse, alias].join('/'), domain(symbols, alias));
  }
  const prefixBytes = Buffer.from(JSON.stringify(prefixes) + '\n');
  fs.writeFileSync(path.join(out, 'prefixes.json.gz'), zlib.gzipSync(prefixBytes));
  const prefixSummary = {trees: prefixes.length, nodes: prefixes.reduce((n, p) => n + p.nodes, 0),
    certificates: prefixes.reduce((n, p) => n + p.certificates.length, 0), frontiers: prefixes.reduce((n, p) => n + p.hits.length, 0),
    partial: prefixes.filter(p => !p.complete).length, prefixesSHA256: sha(prefixBytes)};
  save('prefix_summary.json', prefixSummary); console.log(JSON.stringify({prefixSummary}));
  const candidates = [], incomplete = [], byFirst = {};
  const compressed = zlib.createGzip(), destination = fs.createWriteStream(path.join(out, 'cases.jsonl.gz'));
  compressed.pipe(destination); const completed = once(destination, 'finish'), hash = crypto.createHash('sha256');
  let cases = 0, nodes = 0, certificates = 0, branches = 0;
  for (const first of ['dbbi', 'faed']) {
    byFirst[first] = {cases: 0, candidates: 0, partial: 0};
    for (const reverseD of [false, true]) for (const reverseF of [false, true]) {
      const symbols = {dbbi: reverseD ? [...input.dbbi].reverse().join('') : input.dbbi,
        faed: reverseF ? [...input.faed].reverse().join('') : input.faed};
      const second = first === 'dbbi' ? 'faed' : 'dbbi';
      for (const aliasD of options) for (const aliasF of options) for (const order of ['big', 'little']) {
        const alias = {dbbi: aliasD, faed: aliasF}, reverse = {dbbi: reverseD, faed: reverseF};
        const model = {first, reverseD, reverseF, aliasD, aliasF, order};
        const prefixId = prefixIndex.get([first, reverse[first], alias[first], order].join('/'));
        const prefix = prefixes[prefixId], records = []; let complete = prefix.complete, hitCount = 0;
        const secondDomain = domains.get([second, reverse[second], alias[second]].join('/'));
        for (let frontier = 0; frontier < prefix.hits.length; frontier++) {
          const result = walk(secondDomain, order, BigInt(prefix.hits[frontier].base));
          records.push({frontier, ...result}); nodes += result.nodes; certificates += result.certificates.length; branches++;
          if (!result.complete) complete = false;
          for (const hit of result.hits) {candidates.push({...model, firstMask: prefix.hits[frontier].mask, ...hit}); hitCount++;}
        }
        const line = JSON.stringify({...model, prefixId, complete, branches: records}) + '\n'; hash.update(line);
        if (!compressed.write(line)) await once(compressed, 'drain');
        cases++; byFirst[first].cases++; byFirst[first].candidates += hitCount;
        if (!complete) {incomplete.push(model); byFirst[first].partial++;}
      }
      console.log(JSON.stringify({first, reverseD, reverseF, cases, nodes, certificates, candidates: candidates.length, incomplete: incomplete.length}));
    }
  }
  compressed.end(); await completed; save('candidates.json', candidates);
  const summary = {cases, complete: cases - incomplete.length, nodes, certificates, candidates: candidates.length,
    incomplete, byFirst, branches, prefixSummary, casesSHA256: hash.digest('hex'), controls: checked, finalPasswordFound: false};
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
module.exports = {search, domain, walk};
