'use strict';
// Necessary-condition proof for direct concatenation of fourteen matrix sums.
// Arbitrary fixed bijection a..i -> 1..9; up to two letters can also mean zero.
// No finite prime list, cryptographic guesses, network calls, or old file edits.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const inputPath = path.join(root, '_work/prime_geometry_2026-09-11/inputs.json');
const out = path.join(root, '_work/symbolic_color_sums_2026-09-16');
const digest = b => crypto.createHash('sha256').update(b).digest('hex');
const letters = 'abcdefghi';

function canonical(text, aliases) {
  return [...text].map(c => aliases.includes(c) ? '0' : c).join('');
}

function repeated(text) {
  let length = 0, witness = null;
  for (let distance = 1; distance < text.length; distance++) {
    let run = 0;
    for (let i = 0; i + distance < text.length; i++) {
      run = text[i] === text[i + distance] ? run + 1 : 0;
      const available = Math.min(run, distance);
      if (available > length) {length = available; witness = [i - length + 1, i + distance - length + 1];}
    }
  }
  return {length, witness};
}

function profiles(input) {
  const colors = new Map(input.colored.map(([, color, r, c]) => [r + ',' + c, color]));
  const result = [];
  for (const axis of ['row', 'column']) for (const black of [0, 1]) for (const white of [0, 1]) {
    const sums = Array.from({length: 14}, (_, i) => {
      const a = [0, 0, 0];
      for (let j = 0; j < 14; j++) {
        const [r, c] = axis === 'row' ? [i, j] : [j, i], color = colors.get(r + ',' + c);
        if (color === 'B') a[0]++;
        else if (color === 'Y') a[1]++;
        else a[2] += input.matrix[r][c] ? white : black;
      }
      return a;
    });
    result.push({axis, black, white, sums});
  }
  return result;
}

function boundsFor(text, sums, repeat) {
  const counts = new Map();
  for (const row of sums) counts.set(row.join(','), (counts.get(row.join(',')) || 0) + 1);
  const limits = [0, 1].map(variable => {
    const occurrences = sums.filter(row => row[variable] > 0).length;
    assert(occurrences > 0);
    let maximum = 10n ** BigInt(Math.floor((text.length - sums.length + occurrences) / occurrences)) - 1n;
    for (const row of sums) if (row[variable] && counts.get(row.join(',')) > 1) {
      const numerator = 10n ** BigInt(repeat.length) - 1n - BigInt(row[2]) - 2n * BigInt(row[1 - variable]);
      // For negative numerators any limit below 2 already proves impossibility.
      const bound = numerator < 0n ? -1n : numerator / BigInt(row[variable]);
      if (bound < maximum) maximum = bound;
    }
    return maximum;
  });
  const possible = limits.every(n => n >= 2n);
  const maxLengths = possible ? sums.map(row => (BigInt(row[0]) * limits[0] + BigInt(row[1]) * limits[1] + BigInt(row[2])).toString().length) : [];
  return {limits: limits.map(String), maxLengths, maxLength: maxLengths.reduce((a, b) => a + b, 0)};
}

function segment(text, sums, maxLengths) {
  // Equal coefficient triples require equal canonical substrings, of equal length.
  // This is deliberately a relaxation: numeric feasibility is not required here.
  const suffix = new Array(sums.length + 1).fill(0), keys = sums.map(row => row.join(','));
  for (let i = sums.length - 1; i >= 0; i--) suffix[i] = suffix[i + 1] + maxLengths[i];
  let nodes = 0, matches = 0;
  function visit(index, position, groups) {
    nodes++;
    if (index === sums.length) {if (position === text.length) matches++; return;}
    const key = keys[index], previous = groups.get(key);
    for (let length = 1; length <= maxLengths[index]; length++) {
      if (position + length + suffix[index + 1] < text.length || position + length + sums.length - index - 1 > text.length) continue;
      const part = text.slice(position, position + length);
      if (previous !== undefined && previous !== part) continue;
      if (previous === undefined) groups.set(key, part);
      visit(index + 1, position + length, groups);
      if (previous === undefined) groups.delete(key);
    }
  }
  visit(0, 0, new Map());
  return {nodes, matches};
}

function encodeSums(sums, p, q, alphabet, aliases) {
  let zeros = 0;
  return sums.map(row => (BigInt(row[0]) * p + BigInt(row[1]) * q + BigInt(row[2])).toString()).join('').split('').map(digit => {
    if (digit === '0') return aliases[zeros++ % aliases.length];
    return alphabet[Number(digit) - 1];
  }).join('');
}

function main() {
  const inputBytes = fs.readFileSync(inputPath), input = JSON.parse(inputBytes), allProfiles = profiles(input);
  const aliasSets = [''];
  for (let a = 0; a < letters.length; a++) {
    aliasSets.push(letters[a]);
    for (let b = a + 1; b < letters.length; b++) aliasSets.push(letters[a] + letters[b]);
  }
  const controls = [];
  for (const profile of allProfiles) for (const [p, q] of [[3n, 17n], [37n, 101n], [1000003n, 1000033n]]) {
    const alphabet = 'ihgfedcba', aliases = 'be', text = encodeSums(profile.sums, p, q, alphabet, aliases);
    const normalized = canonical(text, aliases), rep = repeated(normalized), bounds = boundsFor(normalized, profile.sums, rep);
    assert(BigInt(bounds.limits[0]) >= p && BigInt(bounds.limits[1]) >= q);
    assert(bounds.maxLength >= text.length);
    // Check the planted segmentation directly; enumerating all permissive short
    // segmentations is unnecessary for this necessary-condition control.
    const values = profile.sums.map(row => (BigInt(row[0]) * p + BigInt(row[1]) * q + BigInt(row[2])).toString());
    const seen = new Map(); let at = 0;
    values.forEach((v, i) => {
      assert(v.length <= bounds.maxLengths[i]);
      const key = profile.sums[i].join(','), piece = normalized.slice(at, at + v.length); at += v.length;
      if (seen.has(key)) assert.equal(piece, seen.get(key)); else seen.set(key, piece);
    });
    assert.equal(at, normalized.length);
    controls.push({axis: profile.axis, black: profile.black, white: profile.white, p: String(p), q: String(q), aliases, alphabet, passed: true});
  }
  // A small exhaustive length oracle checks the DFS, including positive cases.
  let segmentationControls = 0;
  for (const text of ['abab', 'abba', 'aaaaaa', 'ababab', 'aabaab', 'abcabc']) {
    const sums = [[1, 0, 0], [0, 1, 0], [1, 0, 0]], max = [3, 3, 3]; let wanted = 0;
    for (let a = 1; a <= 3; a++) for (let b = 1; b <= 3; b++) if (2 * a + b === text.length && text.slice(0, a) === text.slice(a + b)) wanted++;
    assert.equal(segment(text, sums, max).matches, wanted); segmentationControls++;
  }
  const cases = [];
  for (const field of ['dbbi', 'faed']) for (const aliases of aliasSets) {
    const text = canonical(input[field], aliases), rep = repeated(text);
    for (const profile of allProfiles) {
      const bounds = boundsFor(text, profile.sums, rep);
      for (const textReversed of [false, true]) for (const sumsReversed of [false, true]) {
        const sums = sumsReversed ? profile.sums.slice().reverse() : profile.sums;
        const result = bounds.maxLength < text.length ? {reason: 'length', nodes: 0, matches: 0} : {
          reason: 'segmentation', ...segment(textReversed ? [...text].reverse().join('') : text, sums,
            sumsReversed ? bounds.maxLengths.slice().reverse() : bounds.maxLengths)};
        cases.push({field, aliases, axis: profile.axis, black: profile.black, white: profile.white,
          textReversed, sumsReversed, repeat: rep, ...bounds, ...result});
      }
    }
  }
  fs.mkdirSync(out, {recursive: true});
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
  save('spec.json', {sourceSHA256: digest(fs.readFileSync(__filename)), inputSHA256: digest(inputBytes), aliasSets,
    hypothesis: 'Fourteen minimal decimal sums, uniform blue p>=2 and yellow q>=2; fixed black/white weights each 0 or 1. Arbitrary bijection a..i to 1..9, up to two letters also denote 0 per occurrence.',
    scope: 'Original complete DBBI and FAED; both field directions and both line directions; rows or columns. No sum permutations, padding, separators, varying letter mapping or extra arithmetic.', profiles: allProfiles});
  save('controls.json', {planted: controls, segmentationControls}); save('cases.json', cases);
  const summary = {cases: cases.length, lengthRejected: cases.filter(c => c.reason === 'length').length,
    segmentationRejected: cases.filter(c => c.reason === 'segmentation' && c.matches === 0).length,
    segmentationNodes: cases.reduce((a, c) => a + c.nodes, 0), survivors: cases.filter(c => c.matches > 0),
    controls: {planted: controls.length, segmentation: segmentationControls}, casesSHA256: digest(fs.readFileSync(path.join(out, 'cases.json'))),
    finalPasswordFound: false};
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
module.exports = {canonical, repeated, profiles, boundsFor, segment};
if (require.main === module) main();
