/*
 * Bounded SalPhaseIon experiment. Node built-ins only; no network or wallet writes.
 * node solver/prime_geometry_constraints.cjs
 *
 * A: test DBBI as an injectively labelled complete graph on 14 scalar values.
 * B: put the 24 primes <= 91, or DBBI digits indexed by them, back into the
 *    24 coloured cells of the original matrix; retain geometry when summing.
 * The matching cardinalities motivate B; they do not establish its intention.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'prime_geometry_2026-09-11');
const inputPath = path.join(out, 'inputs.json');
const inputBytes = fs.readFileSync(inputPath);
const data = JSON.parse(inputBytes);
const sha = x => crypto.createHash('sha256').update(x).digest();
const mod = (x, n) => ((x % n) + n) % n;
const sum = a => a.reduce((x, y) => x + y, 0);
const range = n => Array.from({length: n}, (_, i) => i);
const prime = n => n >= 2 && range(Math.max(0, Math.floor(Math.sqrt(n)) - 1)).every(i => n % (i + 2));
const primes = range(92).filter(prime);
const pairs = range(14).flatMap(i => range(14).filter(j => j > i).map(j => [i, j]));
const sortPairs = fn => [...pairs].sort(fn);
const orders = {
  row: pairs,
  column: sortPairs((a, b) => a[1] - b[1] || a[0] - b[0]),
  diagonal: sortPairs((a, b) => (a[1] - a[0]) - (b[1] - b[0]) || a[0] - b[0]),
  diagonalDescending: sortPairs((a, b) => (b[1] - b[0]) - (a[1] - a[0]) || a[0] - b[0]),
};
for (const [k, v] of Object.entries(orders)) orders[k + '/reversed'] = [...v].reverse();

function graphCertificate(labels, edges, n = 14) {
  const g = range(n).map(() => Array(n).fill(null));
  edges.forEach(([i, j], k) => { g[i][j] = g[j][i] = labels[k]; });
  const twins = [];
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
    if (range(n).every(k => k === i || k === j || g[i][k] === g[j][k])) twins.push([i, j]);
  }
  let maxDegree = 0, witness = null;
  g.forEach((row, i) => {
    const groups = new Map();
    row.forEach((c, j) => {
      if (i === j) return;
      if (!groups.has(c)) groups.set(c, []);
      groups.get(c).push(j);
    });
    for (const [label, neighbours] of groups) if (neighbours.length > maxDegree) {
      maxDegree = neighbours.length; witness = {vertex: i, label, neighbours};
    }
  });
  // Equal scalar values imply twins for any symmetric pair function. When
  // there are no twins, values must be distinct. Sum in a cancellative group
  // then has <=1 neighbour per label; real absolute distance has <=2.
  return {twins, maxSameLabelDegree: maxDegree, witness,
    excludesInjectiveSum: twins.length === 0 && maxDegree > 1,
    excludesInjectiveRealDistance: twins.length === 0 && maxDegree > 2};
}

function spectrum(values) {
  const h = new Map();
  for (const v of values) h.set(v, (h.get(v) || 0) + 1);
  return [...h.values()].sort((a, b) => a - b).join(',');
}
function evp(password, salt, hash) {
  let previous = Buffer.alloc(0), material = Buffer.alloc(0);
  while (material.length < 48) {
    previous = crypto.createHash(hash).update(previous).update(password).update(salt).digest();
    material = Buffer.concat([material, previous]);
  }
  return [material.subarray(0, 32), material.subarray(32, 48)];
}
function decrypt(password, blob, hash) {
  const salt = Buffer.from(blob.salt, 'hex'), ct = Buffer.from(blob.ciphertext, 'hex');
  const [key, iv] = evp(password, salt, hash);
  const ecb = crypto.createDecipheriv('aes-256-ecb', key, null); ecb.setAutoPadding(false);
  const last = Buffer.concat([ecb.update(ct.subarray(-16)), ecb.final()]);
  const prev = ct.length === 16 ? iv : ct.subarray(-32, -16);
  for (let i = 0; i < 16; i++) last[i] ^= prev[i];
  const pad = last[15];
  if (pad < 1 || pad > 16 || !last.subarray(16 - pad).every(x => x === pad)) return null;
  const dec = crypto.createDecipheriv('aes-256-cbc', key, iv); dec.setAutoPadding(false);
  const full = Buffer.concat([dec.update(ct), dec.final()]);
  return full.subarray(0, full.length - pad);
}

// Controls before touching unknown passwords.
assert.equal(data.dbbi.length, 91); assert.equal(data.faed.length, 570);
assert.equal(primes.length, 24); assert.equal(data.colored.length, 24);
assert.equal(sum(data.matrix.map(sum)), 101);
assert.equal(data.colored.map(x => x[1]).join(''), data.color_sequence);
for (const [index, color, r, c] of data.colored) {
  assert.deepEqual(data.spiral[index], [r, c]);
  assert.equal(data.matrix[r][c], color === 'B' ? 1 : 0);
}
const permutation = [8, 2, 13, 0, 6, 10, 1, 9, 12, 4, 11, 3, 7, 5];
for (const order of Object.values(orders)) {
  const sums = order.map(([i, j]) => `symbol_${permutation[i] + permutation[j]}`);
  const distances = order.map(([i, j]) => `symbol_${Math.abs(permutation[i] - permutation[j])}`);
  assert.equal(graphCertificate(sums, order).excludesInjectiveSum, false);
  assert.equal(graphCertificate(distances, order).excludesInjectiveRealDistance, false);
  const repeats = order.map(([i, j]) => Math.floor(permutation[i] / 2) + Math.floor(permutation[j] / 2));
  assert.equal(graphCertificate(repeats, order).excludesInjectiveSum, false);
}
const controlRaw = Buffer.from(data.phase32_control_b64, 'base64');
const controlBlob = {salt: controlRaw.subarray(8, 16).toString('hex'), ciphertext: controlRaw.subarray(16).toString('hex')};
const controlPlain = decrypt(Buffer.from(data.phase32_control_password), controlBlob, 'sha256');
assert(controlPlain.toString().startsWith("I've been waiting for you."));
assert.equal(decrypt(Buffer.from(data.phase32_control_password), controlBlob, 'md5'), null);
for (const hash of ['sha256', 'md5']) {
  const password = Buffer.from('deterministic binary positive control');
  const salt = Buffer.from('0011223344556677', 'hex');
  for (const length of [1, 16, 64, 79, 1312, 1327]) {
    const plain = Buffer.from(range(length).map(i => (i * 131 + 17) % 256));
    const [key, iv] = evp(password, salt, hash);
    const enc = crypto.createCipheriv('aes-256-cbc', key, iv);
    const ct = Buffer.concat([enc.update(plain), enc.final()]);
    assert.deepEqual(decrypt(password, {salt: salt.toString('hex'), ciphertext: ct.toString('hex')}, hash), plain);
  }
}

const spec = {
  input_sha256: sha(inputBytes).toString('hex'),
  source_sha256: sha(fs.readFileSync(__filename)).toString('hex'),
  primes,
  mechanism: 'Place prime k or DBBI[prime k - indexBase] at coloured cell k in spiral order, then sum spatial rows/columns.',
  prime_order: ['ascending', 'descending'],
  weight_modes: ['prime', 'dbbi/index1/a1', 'dbbi/index1/a0', 'dbbi/index0/a1', 'dbbi/index0/a0'],
  masks: ['both', 'B', 'Y', 'BminusY'],
  uncoloured: ['zero', 'original bits'],
  extraction: 'List serializations and list+lastwords; 14 sums select from 14 README line-final words, with explicit wrap/strict, 0/1 base and forward/backward. Also select from DBBI/FAED and local phase32 words, strictly in bounds.',
  caution: 'The 14 line endings are README layout, not independently verified original wrapping. Each combination is a hypothesis, not an endorsed instruction.',
  acceptance: 'Exact original Bitcoin target or coherent/independently verifiable full plaintext. Padding and short readable fragments are triage only.',
};
fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
const graphResults = Object.fromEntries(Object.entries(orders).map(([name, order]) => [name, graphCertificate(data.dbbi, order)]));
const targetSpectrum = spectrum(data.dbbi);

const beforeChoice = data.phase32_text.split('SELECT')[0];
const words = beforeChoice.match(/[A-Z']+/g);
const lastWords = beforeChoice.trim().split(/\r?\n/).map(line => line.match(/[A-Z']+/g).at(-1));
assert.equal(lastWords.length, 14);
const anchors = ['', words.at(-1).toLowerCase(), 'reinsertingtheprimebasicsafterwhichyouwillberequiredto'];
const candidates = new Map(), listRecords = [], pairResults = [];
function addCandidate(label, text) {
  if (text.length && !candidates.has(text)) candidates.set(text, label);
}
function addList(label, values) {
  listRecords.push({label, values});
  for (const [direction, xs] of [['forward', values], ['reversed', [...values].reverse()]]) {
    for (const [format, text] of [['compact', xs.join('')], ['comma', xs.join(',')], ['bracket', JSON.stringify(xs)]]) {
      for (const anchor of anchors) addCandidate(`${label}/${direction}/${format}/anchor:${anchor}`, text + anchor);
    }
    if (xs.length !== 14) continue;
    for (const [wordOrder, ws] of [['forward', lastWords], ['reverse', [...lastWords].reverse()]]) {
      for (const base of [0, 1]) for (const side of ['start', 'end']) for (const wrap of [false, true]) {
        const idxs = xs.map(x => x - base);
        if (!wrap && !idxs.every((x, i) => x >= 0 && x < ws[i].length)) continue;
        const text = ws.map((w, i) => {
          const j = wrap ? mod(idxs[i], w.length) : idxs[i];
          return w[side === 'start' ? j : w.length - j - 1];
        }).join('');
        addCandidate(`${label}/${direction}/line-last:${wordOrder}/base${base}/${side}/wrap${wrap}`, text);
      }
    }
    for (const [source, arr] of [['dbbi', [...data.dbbi]], ['faed', [...data.faed]], ['phase32-words', words]]) {
      for (const base of [0, 1]) for (const side of ['start', 'end']) {
        const idxs = xs.map(x => x - base);
        if (!idxs.every(x => x >= 0 && x < arr.length)) continue;
        const selected = idxs.map(x => arr[side === 'start' ? x : arr.length - x - 1]);
        addCandidate(`${label}/${direction}/${source}/base${base}/${side}`, selected.join(''));
        if (source === 'phase32-words') for (const edge of [0, -1]) {
          addCandidate(`${label}/${direction}/${source}/base${base}/${side}/letter${edge}`, selected.map(x => x.at(edge)).join(''));
        }
      }
    }
  }
}

const weights = ['prime', 'dbbi/index1/a1', 'dbbi/index1/a0', 'dbbi/index0/a1', 'dbbi/index0/a0'];
let matrices = 0;
for (const reverse of [false, true]) for (const weight of weights) {
  for (const mask of ['both', 'B', 'Y', 'BminusY']) for (const background of [0, 1]) {
    const matrix = data.matrix.map(row => row.map(x => background * x));
    data.colored.forEach(([, color, r, c], k) => {
      const p = primes[reverse ? 23 - k : k];
      const indexBase = weight.includes('index0') ? 0 : 1;
      const alphabetBase = weight.endsWith('/a0') ? 97 : 96;
      const value = weight === 'prime' ? p : data.dbbi.charCodeAt(p - indexBase) - alphabetBase;
      const mult = mask === 'both' || color === mask ? 1 : mask === 'BminusY' ? (color === 'B' ? 1 : -1) : 0;
      matrix[r][c] = mult * value;
    });
    const rows = matrix.map(sum), columns = range(14).map(c => sum(matrix.map(row => row[c])));
    const label = `${weight}/${reverse ? 'descending' : 'ascending'}/${mask}/background${background}`;
    for (const [kind, values] of [['row', rows], ['column', columns], ['rowcolumn', [...rows, ...columns]], ['columnrow', [...columns, ...rows]]]) {
      addList(`${label}/${kind}`, values);
    }
    // Necessary invariant under ALL vertex orders and ALL bijective symbol labels.
    // A surviving histogram would need graph isomorphism; it is not a solution.
    for (const [kind, vectors] of [['row', matrix], ['column', range(14).map(c => matrix.map(row => row[c]))]]) {
      const sums = vectors.map(sum);
      const operations = {
        sum: (i, j) => sums[i] + sums[j],
        distance: (i, j) => Math.abs(sums[i] - sums[j]),
        product: (i, j) => sums[i] * sums[j],
        dot: (i, j) => sum(vectors[i].map((v, k) => v * vectors[j][k])),
      };
      for (const [op, fn] of Object.entries(operations)) for (const modulus of [null, 9, 10]) {
        const values = pairs.map(([i, j]) => modulus === null ? fn(i, j) : mod(fn(i, j), modulus));
        pairResults.push({label: `${label}/${kind}/${op}/mod${modulus}`, spectrum: spectrum(values), compatible: spectrum(values) === targetSpectrum});
      }
    }
    matrices++;
  }
}

fs.writeFileSync(path.join(out, 'lists.json'), JSON.stringify({lastWords, anchors, lists: listRecords}, null, 2) + '\n');
fs.writeFileSync(path.join(out, 'graph_constraints.json'), JSON.stringify({targetSpectrum, graphResults, pairResults}, null, 2) + '\n');
fs.writeFileSync(path.join(out, 'candidates.jsonl'), [...candidates].map(([text, label]) => JSON.stringify({label, text})).join('\n') + '\n');
console.log(JSON.stringify({controls: 'passed', matrices, lists: listRecords.length, candidates: candidates.size, histogramSurvivors: pairResults.filter(x => x.compatible).length}));

const passwords = new Map();
for (const [text, label] of candidates) for (const [caseName, value] of [['original', text], ['lower', text.toLowerCase()], ['upper', text.toUpperCase()]]) {
  const raw = Buffer.from(value);
  for (const [form, password] of [['raw', raw], ['sha256hex', Buffer.from(sha(raw).toString('hex'))]]) {
    const key = password.toString('hex');
    if (!passwords.has(key)) passwords.set(key, {label, caseName, form});
  }
}
const hitFd = fs.openSync(path.join(out, 'padding_results.jsonl'), 'w');
const hits = [], counts = {}, started = Date.now();
let attempts = 0, paddings = 0;
try {
  for (const [pwHex, provenance] of passwords) {
    for (const name of ['SMALL', 'TAIL32', 'COSMIC']) for (const hash of ['sha256', 'md5']) {
      const plain = decrypt(Buffer.from(pwHex, 'hex'), data.blobs[name], hash); attempts++;
      if (!plain) continue;
      paddings++;
      counts[`${name}/${hash}`] = (counts[`${name}/${hash}`] || 0) + 1;
      const asciiFraction = [...plain].filter(x => x >= 32 && x < 127 || [9, 10, 13].includes(x)).length / plain.length;
      const record = {name, hash, passwordHex: pwHex, ...provenance, length: plain.length, asciiFraction, plaintextHex: plain.toString('hex')};
      fs.writeSync(hitFd, JSON.stringify(record) + '\n');
      if (asciiFraction >= 0.85 || plain.subarray(0, 8).equals(Buffer.from('Salted__'))) hits.push(record);
    }
  }
} finally { fs.closeSync(hitFd); }
const summary = {
  ...spec, controls: {phase32_sha256: true, phase32_md5_fails: true, binary_roundtrips: 12, graph_controls: 24},
  matrices, lists: listRecords.length, candidates: candidates.size, distinctPasswords: passwords.size,
  graphReadings: Object.keys(graphResults).length,
  graphSumExcluded: Object.values(graphResults).filter(x => x.excludesInjectiveSum).length,
  graphDistanceExcluded: Object.values(graphResults).filter(x => x.excludesInjectiveRealDistance).length,
  pairHistogramTests: pairResults.length, histogramSurvivors: pairResults.filter(x => x.compatible),
  aesAttempts: attempts, paddingOnlyCount: paddings, expectedRandomPadding: attempts / 255,
  paddingByTarget: counts, semanticTriage: hits, bitcoinValidation: 'pending independent full-byte scan',
  elapsedAESSeconds: (Date.now() - started) / 1000,
};
fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({aesAttempts: attempts, paddingOnlyCount: paddings, semanticTriage: hits.length, seconds: summary.elapsedAESSeconds}));
