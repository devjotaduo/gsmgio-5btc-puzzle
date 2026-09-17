'use strict';
// Conditional continuation requested by the user: fix L84 and witness A.
// Every output is a candidate; only an authenticated opening/target key is a solve.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {parseHosts} = require('./prime_host_delta.cjs');
const {solve} = require('./zero_decimal_constraints.cjs');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const reverse = s => [...s].reverse().join('');
const toBytes = n => { const h = n.toString(16); return Buffer.from(h.padStart(Math.ceil(h.length / 2) * 2, '0'), 'hex'); };

function* permutations(values) {
  if (!values.length) { yield []; return; }
  for (let i = 0; i < values.length; i++) {
    for (const tail of permutations(values.filter((_, j) => i !== j))) yield [values[i], ...tail];
  }
}

// Ragged round-robin: emit one character from each non-exhausted stream.
function weave(parts) {
  let output = '';
  for (let i = 0; i < Math.max(...parts.map(p => p.length)); i++) {
    for (const p of parts) if (i < p.length) output += p[i];
  }
  return output;
}

function unweave(text, lengths) {
  const parts = lengths.map(() => ''); let at = 0;
  for (let i = 0; i < Math.max(...lengths); i++) {
    lengths.forEach((length, j) => { if (i < length) parts[j] += text[at++]; });
  }
  assert.equal(at, text.length); return parts;
}

function faedRecords(text, square) {
  assert.equal(text.length % 2, 0);
  return Array.from({length: text.length / 2}, (_, i) => {
    const a = square.indexOf(text[i]), b = square.indexOf(text[i + text.length / 2]);
    assert(a >= 0 && b >= 0);
    return {index: i + 1, input: text[i] + text[i + text.length / 2],
      output: square[5 * Math.floor(a / 5) + Math.floor(b / 5)] + square[5 * (a % 5) + b % 5]};
  });
}

function main() {
  const out = path.resolve(process.argv[2] || path.join(root, '_work/prime_host_l84_2026-09-17/run1'));
  assert(!fs.existsSync(out), 'Use a fresh output directory; evidence must not be overwritten.');
  fs.mkdirSync(out, {recursive: true});
  const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
  const raw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const data = JSON.parse(raw), tokens = parseHosts(data.dbbi).find(p => p.length === 84);
  assert(tokens); const hosts = tokens.filter(t => t.prime), yellow = hosts.filter(t => t.text === 'be');
  assert.equal(hosts.length, 23); assert.equal(yellow.length, 7);
  const events = [...data.colored.map(([index, color, row, col]) => ({index, color, row, col})),
    {index: 163, color: 'B', row: 7, col: 4}].sort((a, b) => a.index - b.index);
  const witness = events.filter((_, i) => ![21, 24].includes(i));
  assert.equal(witness.map(e => e.color).join(''), hosts.map(t => t.text === 'be' ? 'Y' : 'B').join(''));
  assert.deepEqual(witness.map(e => Math.floor(e.index / 8) + 1), Array.from({length: 23}, (_, i) => i + 1));
  const orders = [...permutations([0, 1, 2, 3, 4, 5, 6])];
  assert.equal(new Set(orders.map(x => x.join(''))).size, 5040);

  const materials = new Map(), groups = [], integerCounts = {models: 0, nodes: 0, complete: 0, hits: 0};
  function add(value, provenance) {
    const b = Buffer.isBuffer(value) ? value : Buffer.from(value);
    if (!b.length) return;
    const hex = b.toString('hex');
    if (!materials.has(hex)) materials.set(hex, {id: materials.size, hex, provenance});
  }
  function forms(value, provenance) {
    add(value, provenance + '/literal'); add(value.toUpperCase(), provenance + '/upper');
  }
  function list(values, provenance) {
    for (const vs of [values, [...values].reverse()]) {
      for (const sep of ['', ',', ' ']) add(vs.join(sep), provenance + '/list-' + JSON.stringify(sep));
      if (vs.every(v => v >= 0 && v < 256)) add(Buffer.from(vs), provenance + '/bytes');
      add(toBytes(BigInt(vs.join(''))), provenance + '/whole-decimal');
    }
  }
  function seven(parts, label, modes) {
    assert.equal(parts.length, 7); const before = materials.size;
    groups.push({label, parts, modes, orders: 5040});
    for (const order of orders) for (const backwards of [false, true]) {
      const selected = order.map(i => backwards ? reverse(parts[i]) : parts[i]);
      for (const mode of modes) forms(mode === 'weave' ? weave(selected) : selected.join(''),
        `${label}/${mode}/${order.join('')}/reverse-parts-${backwards}`);
    }
    console.log(JSON.stringify({stage: label, newMaterials: materials.size - before, total: materials.size}));
  }

  // A: the already-decoded 23-word note; selected by the seven Y host ordinals.
  // Atlas reports concatenation permutations as spent. This run only weaves characters.
  const sentence = 'IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE';
  const words = sentence.toLowerCase().split(' ');
  assert.equal(words.length, 23); assert.equal(words.join('').length, 91);
  const chosenWords = words.filter((_, i) => hosts[i].text === 'be');
  assert.deepEqual(chosenWords, ['to', 'private', 'keys', 'better', 'they', 'also', 'to']);
  seven(chosenWords, 'sentence/Y-hosts', ['weave']);

  // B: a conditional community Bifid square. Reproduce its 83 note anchors,
  // then follow exactly the seven D notes selected by the L84 logical ranks.
  const square = [...new Set(data.dbbi + 'abcdefghiklmnopqrstuvwxyz')].join('');
  assert.equal(square, 'dbifhcegaklmnopqrstuvwxyz');
  const records = faedRecords(data.faed, square);
  const decoded = records.map(r => r.output).join('');
  assert(decoded.startsWith('btcseed'));
  const notes = records.filter(r => /^[a-g]$/.test(r.output[1]));
  assert.equal(notes.length, 83);
  const selectedNotes = yellow.map(t => notes[t.rank - 1]);
  assert.equal(selectedNotes.map(n => n.output[1]).join(''), 'ddddddd');
  assert.deepEqual(selectedNotes.map(n => n.index), [39, 91, 113, 164, 207, 224, 269]);
  const gaps = []; let last = 0;
  for (const n of notes) { gaps.push(records.slice(last, n.index - 1)); last = n.index; }
  gaps.push(records.slice(last)); assert.equal(gaps.length, 84);
  for (const side of ['before', 'after']) for (const representation of ['input', 'output', 'payload']) {
    const parts = yellow.map(t => gaps[t.rank - 1 + (side === 'after' ? 1 : 0)]
      .map(r => representation === 'payload' ? r.output[1] : r[representation]).join(''));
    seven(parts, `faed/D-gaps-${side}/${representation}`, ['concat', 'weave']);
  }
  for (const field of ['input', 'output']) {
    const joined = selectedNotes.map(r => r[field]).join('');
    for (const s of [joined, reverse(joined), selectedNotes.map(r => r[field][0]).join(''), selectedNotes.map(r => r[field][1]).join('')]) {
      forms(s, `faed/selected-records/${field}`);
      list([...s].map(c => c.charCodeAt(0) - 96), `faed/selected-records/${field}/ordinals`);
    }
  }
  list(selectedNotes.map(n => n.index), 'faed/selected-record-indexes');
  list(yellow.map(t => t.rank), 'dbbi/Y-logical-ranks');
  list(yellow.map(t => t.offset + 1), 'dbbi/Y-physical-positions');

  // C: L84 has an exact 7 x 12 rectangle. Permute its seven streams, with no
  // substitution beyond the page's a1..i9 convention and independently zeroable g.
  const decimalModels = new Set(), integerFile = path.join(out, 'integer_models.jsonl');
  fs.writeFileSync(integerFile, '', {flag: 'wx'});
  for (const [view, s] of Object.entries({logical: tokens.map(t => t.text[0]).join(''),
    primeZero: tokens.map(t => t.prime ? 'o' : t.text).join('')})) {
    for (const direction of ['weave-rows', 'join-columns']) {
      const parts = direction === 'weave-rows' ? s.match(/.{12}/g) : Array.from({length: 7}, (_, j) => [...s].filter((_, i) => i % 7 === j).join(''));
      for (const order of orders) for (const backwards of [false, true]) {
        const ps = order.map(i => backwards ? reverse(parts[i]) : parts[i]);
        const text = direction === 'weave-rows' ? weave(ps) : ps.join('');
        const pattern = [...text].map(c => c === 'g' ? '?' : c === 'o' ? '0' : c.charCodeAt(0) - 96).join('');
        if (decimalModels.has(pattern)) continue; decimalModels.add(pattern);
        const result = solve(pattern, 2000000, true);
        assert(result.complete); integerCounts.models++; integerCounts.complete++;
        integerCounts.nodes += result.nodes; integerCounts.hits += result.hits.length;
        const label = `${view}/${direction}/${order.join('')}/reverse-parts-${backwards}`;
        fs.appendFileSync(integerFile, JSON.stringify({label, pattern, ...result}) + '\n');
        for (const hit of result.hits) add(Buffer.from(hit, 'ascii'), 'decimal/' + label);
      }
    }
    console.log(JSON.stringify({stage: 'decimal/' + view, ...integerCounts}));
  }

  const sampleParts = ['ab', '', 'cde', 'f', 'ghij', 'klm', 'n'];
  assert.deepEqual(unweave(weave(sampleParts), sampleParts.map(p => p.length)), sampleParts);
  const planted = 'A'.repeat(35), decimal = BigInt('0x' + Buffer.from(planted).toString('hex')).toString();
  assert.equal(decimal.length, 84);
  const encoded = [...decimal].map(c => c === '0' ? 'g' : String.fromCharCode(96 + +c)).join('');
  const encodedColumns = Array.from({length: 7}, (_, j) => [...encoded].filter((_, i) => i % 7 === j).join(''));
  assert.equal(weave(encodedColumns), encoded);
  const plantedResult = solve([...weave(encodedColumns)].map(c => c === 'g' ? '?' : c.charCodeAt(0) - 96).join(''), 2000000, true);
  assert(plantedResult.complete && plantedResult.hits.includes(planted));
  const control = Buffer.from(data.phase32_control_b64, 'base64');
  const controlBody = open(Buffer.from(data.phase32_control_password), {salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex')}, 'sha256');
  assert.equal(sha(controlBody), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');

  // Record overlap rather than describing already-tested candidates as new.
  const historical = new Set(JSON.parse(fs.readFileSync(path.join(root, '_work/prime_host_delta_2026-09-17/run1/materials.json'))).map(m => m.hex));
  const filtered = [...materials.values()].filter(m => !historical.has(m.hex));
  save('spec.json', {hypothesis: 'Assume L84 and witness A (omit picture events 22,25); test new downstream operations.',
    assumptions: ['FE as blue, representing byte 21; retain one event for each byte 1..23.', 'Y host ordinals select seven words; logical Y ranks select seven conditional FAED note anchors.', 'Seven-stream round-robin is a hypothesis, not an authenticated operation.'],
    scope: 'Sentence: all 7! orders, ragged character interleaving only, each part forward/reversed globally, lower/uppercase. FAED: 83 second-letter A-G anchors produce 84 gaps; before/after each selected D, input pairs/output pairs/payload letters, concatenate or weave in all 7! orders and both directions. D record/index serializations. Logical84 and prime-zero84: seven contiguous rows woven or seven interleaved columns concatenated; 7! orders, both part directions, all g=0/7 masks, whole-decimal minimal big-endian seven-bit bytes. Candidate passwords direct or lowercase SHA256 hex; original SMALL/TAIL32/COSMIC with EVP-SHA256 and EVP-MD5.',
    limits: 'No arbitrary new alphabet, no partial cipher slicing, no PBKDF2, no claim that other transpositions or keys were exhausted. Candidate overlap filtered only against the immediately prior prime-host campaign.',
    inputSHA256: sha(raw), sourceSHA256: sha(fs.readFileSync(__filename)), selectedHostRanks: yellow.map(t => t.rank),
    selectedWordOrdinals: hosts.flatMap((t, i) => t.text === 'be' ? [i + 1] : []), selectedRecordOrdinals: selectedNotes.map(n => n.index),
    square, knownSquareStatus: 'Community construction, not an authenticated cipher identification.'});
  save('controls.json', {permutations: orders.length, raggedWeaveRoundtrip: true, plantedDecimal84Recovered: true, phase32PlaintextSHA256: sha(controlBody)});
  save('extractions.json', {witness, words: chosenWords, selectedNotes, groups, gaps: gaps.map(g => g.map(r => r.index))});
  save('materials.json', filtered);
  console.log(JSON.stringify({stage: 'AES-start', generated: materials.size, excludedPriorMaterials: materials.size - filtered.length, materials: filtered.length}));
  let attempts = 0, maxPrintable = 0; const padding = [], semantic = [], decisionHash = crypto.createHash('sha256');
  for (const m of filtered) for (const form of ['direct', 'sha256-hex']) {
    const b = Buffer.from(m.hex, 'hex'), password = form === 'direct' ? b : Buffer.from(sha(b));
    for (const [blob, value] of Object.entries(data.blobs)) for (const digest of ['sha256', 'md5']) {
      const body = open(password, value, digest); attempts++;
      decisionHash.update([m.id, form, blob, digest, body ? body.toString('hex') : '-'].join('|') + '\n');
      if (!body) continue;
      const printable = [...body].filter(c => c >= 32 && c < 127 || [9, 10, 13].includes(c)).length / body.length;
      const p = {material: m.id, form, blob, digest, hex: body.toString('hex'), printable};
      padding.push(p); maxPrintable = Math.max(maxPrintable, printable);
      if (printable >= 0.85 || body.includes(Buffer.from('Salted__')) || body.includes(Buffer.from('U2FsdGVk'))) semantic.push(p);
    }
    if (m.id % 10000 === 0) console.log(JSON.stringify({stage: 'AES', materialID: m.id, attempts}));
  }
  save('padding.json', padding); save('semantic_candidates.json', semantic);
  const summary = {conditionalBranch: 'L84/A', generatedMaterials: materials.size, excludedPriorMaterials: materials.size - filtered.length,
    materials: filtered.length, passwordCases: filtered.length * 2, attempts, padding: padding.length, maxPrintable, semanticCandidates: semantic.length,
    integer: integerCounts, decisionsSHA256: decisionHash.digest('hex'), authenticatedSolution: false,
    qualification: 'Read independent_verification.json for cross-library AES and exact private-key checks. No finding is authenticated by padding.'};
  save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
}
if (require.main === module) main();
module.exports = {permutations, weave, unweave, faedRecords};
