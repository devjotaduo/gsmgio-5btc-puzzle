'use strict';
// Strengthen the verified symbolic-sum result to ANY permutation of the sums.
// Equal coefficient groups must occupy distinct equal canonical substrings.
// Two implementations independently enumerate positions and test disjointness.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/symbolic_color_sums_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
const read = file => JSON.parse(fs.readFileSync(path.join(out, file), 'utf8'));

function combinations(values, count, use) {
  function visit(start, selected) {
    if (selected.length === count) {use(selected.slice()); return;}
    for (let i = start; i <= values.length - count + selected.length; i++) {
      selected.push(values[i]); visit(i + 1, selected); selected.pop();
    }
  }
  visit(0, []);
}

function placementsA(text, group) {
  const result = [];
  for (let length = group.minLength; length <= group.maxLength; length++) {
    const byText = new Map();
    for (let start = 0; start + length <= text.length; start++) {
      const piece = text.slice(start, start + length);
      if (!byText.has(piece)) byText.set(piece, []); byText.get(piece).push(start);
    }
    for (const starts of byText.values()) if (starts.length >= group.count) combinations(starts, group.count, selected => {
      let mask = 0n;
      for (const start of selected) {
        const bits = ((1n << BigInt(length)) - 1n) << BigInt(start);
        if (mask & bits) return; mask |= bits;
      }
      result.push({length, starts: selected, mask});
    });
  }
  return result;
}

function placementsB(text, group) {
  // Use each possible first occurrence and substring search, not buckets/bitsets.
  const result = [];
  for (let length = group.minLength; length <= group.maxLength; length++) for (let first = 0; first + length <= text.length; first++) {
    const word = text.substring(first, first + length);
    function extend(chosen) {
      if (chosen.length === group.count) {result.push({length, starts: chosen.slice()}); return;}
      let at = text.indexOf(word, chosen[chosen.length - 1] + length);
      while (at !== -1) {chosen.push(at); extend(chosen); chosen.pop(); at = text.indexOf(word, at + 1);}
    }
    extend([first]);
  }
  return result;
}

function searchA(choices, singleCapacity, targetLength) {
  let nodes = 0, survivors = 0;
  const future = new Array(choices.length + 1).fill(0);
  for (let i = choices.length - 1; i >= 0; i--) future[i] = future[i + 1] + Math.max(0, ...choices[i].map(p => p.length * p.starts.length));
  function visit(index, covered, mask) {
    nodes++;
    if (covered + singleCapacity + future[index] < targetLength) return;
    if (index === choices.length) {survivors++; return;}
    for (const p of choices[index]) if (!(p.mask & mask)) visit(index + 1, covered + p.length * p.starts.length, mask | p.mask);
  }
  visit(0, 0, 0n); return {nodes, survivors};
}

function searchB(choices, singleCapacity, targetLength) {
  // Breadth-first interval packing with no length pruning before the last layer.
  let states = [{length: 0, intervals: []}];
  for (const group of choices) {
    const next = [];
    for (const state of states) for (const placement of group) {
      const added = placement.starts.map(start => [start, start + placement.length]);
      if (added.some(([lo, hi]) => state.intervals.some(([a, b]) => lo < b && a < hi))) continue;
      next.push({length: state.length + placement.length * placement.starts.length, intervals: state.intervals.concat(added)});
    }
    states = next;
  }
  return states.filter(s => s.length + singleCapacity >= targetLength).length;
}

function normalizePlacements(list) {
  return list.map(p => [p.length, ...p.starts].join(',')).sort();
}

function main() {
  const spec = read('spec.json'), cases = read('cases.json'), verification = read('verification.json');
  assert(verification.allPassed);
  assert.equal(hash(fs.readFileSync(path.join(out, 'cases.json'))), verification.casesSHA256);
  assert.equal(hash(fs.readFileSync(path.join(root, 'solver/color_sum_symbolic.cjs'))), verification.solverSHA256);
  assert.equal(hash(fs.readFileSync(path.join(root, 'solver/verify_color_sum_symbolic.cjs'))), verification.sourceSHA256);
  const inputBytes = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')); assert.equal(hash(inputBytes), spec.inputSHA256);
  const input = JSON.parse(inputBytes), unique = cases.filter(c => !c.textReversed && !c.sumsReversed), results = [];
  let placementControls = 0, packingControls = 0;
  for (const text of ['abababab', 'aaaaaaaa', 'abcabcab', 'aabbaabb']) for (const count of [2, 3]) {
    const group = {count, minLength: 1, maxLength: 3};
    const a = placementsA(text, group), b = placementsB(text, group);
    assert.deepEqual(normalizePlacements(a), normalizePlacements(b)); placementControls++;
    for (const target of [4, 8, 12]) {
      assert.equal(searchA([a, a], 2, target).survivors, searchB([b, b], 2, target)); packingControls++;
    }
  }
  // Planted independent groups must survive the relaxed any-order proof.
  const planted = 'abcdeXYabcdeXY', plantedGroups = [{count: 2, minLength: 5, maxLength: 5}, {count: 2, minLength: 2, maxLength: 2}];
  assert(searchA(plantedGroups.map(g => placementsA(planted, g)), 0, planted.length).survivors > 0);
  assert(searchB(plantedGroups.map(g => placementsB(planted, g)), 0, planted.length) > 0);
  for (const record of unique) {
    const id = [record.field, record.aliases, record.axis, record.black, record.white].join('/');
    if (record.maxLength < input[record.field].length) {results.push({id, reason: 'length', survivors: 0}); continue;}
    const profile = spec.profiles.find(p => p.axis === record.axis && p.black === record.black && p.white === record.white);
    const groups = new Map();
    profile.sums.forEach((row, i) => {
      const key = row.join(',');
      if (!groups.has(key)) groups.set(key, {coefficients: row, count: 0, maxLength: record.maxLengths[i]});
      const group = groups.get(key); assert.equal(group.maxLength, record.maxLengths[i]); group.count++;
    });
    const all = [...groups.values()], singleCapacity = all.filter(g => g.count === 1).reduce((s, g) => s + g.maxLength, 0);
    const repeated = all.filter(g => g.count > 1), length = input[record.field].length;
    // Each group's lower bound allows all other groups to reach their upper
    // bounds and all singletons to use full capacity. Thus no solution is lost.
    for (const group of repeated) {
      const others = repeated.filter(g => g !== group).reduce((s, g) => s + g.maxLength * g.count, 0);
      group.minLength = Math.max(1, Math.ceil((length - singleCapacity - others) / group.count));
    }
    const text = [...input[record.field]].map(c => record.aliases.includes(c) ? '0' : c).join('');
    const a = repeated.map(g => placementsA(text, g)), b = repeated.map(g => placementsB(text, g));
    a.forEach((choices, i) => assert.deepEqual(normalizePlacements(choices), normalizePlacements(b[i])));
    const answerA = searchA(a, singleCapacity, length), answerB = searchB(b, singleCapacity, length);
    assert.equal(answerA.survivors, answerB); assert.equal(answerB, 0);
    results.push({id, reason: 'disjoint repeated substrings', singleCapacity, groups: repeated,
      placements: b, nodes: answerA.nodes, survivors: answerB});
  }
  assert.equal(unique.length, 736);
  fs.writeFileSync(path.join(out, 'any_order_cases.json'), JSON.stringify(results, null, 2) + '\n');
  const summary = {verifiedAt: new Date().toISOString(), sourceSHA256: hash(fs.readFileSync(__filename)),
    parentCasesSHA256: verification.casesSHA256, casesSHA256: hash(fs.readFileSync(path.join(out, 'any_order_cases.json'))),
    models: unique.length, lengthRejected: results.filter(r => r.reason === 'length').length,
    packingRejected: results.filter(r => r.reason !== 'length').length, survivors: results.filter(r => r.survivors > 0),
    controls: {placementAgreement: placementControls, packingAgreement: packingControls, planted: 1},
    coversEveryPermutationOfFourteenSums: true, coversEitherWholeTextDirection: true,
    independentPositionAndDisjointnessImplementationsAgree: true, finalPasswordFound: false};
  fs.writeFileSync(path.join(out, 'any_order_verification.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
