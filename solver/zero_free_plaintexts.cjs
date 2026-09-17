'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {enumerate} = require('./zero_free_numerals.cjs');
const {vocabulary} = require('./prime_space_words.cjs');
const {characters} = require('./unbounded_zero_words.cjs');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), sha = b => crypto.createHash('sha256').update(b).digest('hex');

function indexedGraph(digits, codes) {
  const lookup = new Map();
  for (const c of codes) { if (!lookup.has(c.word)) lookup.set(c.word, []); lookup.get(c.word).push(c.m); }
  return Array.from({length: digits.length + 1}, (_, at) => {
    const edges = [];
    for (let length = 1; length <= 3 && at + length <= digits.length; length++) {
      for (const m of lookup.get(digits.slice(at, at + length)) || []) edges.push({end: at + length, m});
    }
    return edges;
  });
}

function fixedFormat(graph, alphabet, length, first = alphabet) {
  const allowed = new Set([...alphabet].map(c => c.charCodeAt(0))), starts = new Set([...first].map(c => c.charCodeAt(0)));
  const edges = graph.map((es, i) => es.filter(e => (i ? allowed : starts).has(e.m)));
  const n = graph.length - 1, counts = Array.from({length: n + 1}, () => Array(length + 1).fill(0n)); counts[n][0] = 1n;
  for (let at = n - 1; at >= 0; at--) for (let left = 1; left <= length; left++) for (const e of edges[at]) counts[at][left] += counts[e.end][left - 1];
  const texts = [], limit = 10000;
  function visit(at, left, text) {
    if (texts.length >= limit) return;
    if (at === n) { if (!left) texts.push(text); return; }
    if (!left) return;
    for (const e of edges[at]) if (counts[e.end][left - 1]) visit(e.end, left - 1, text + String.fromCharCode(e.m));
  }
  if (counts[0][length]) visit(0, length, '');
  return {paths: String(counts[0][length]), complete: BigInt(texts.length) === counts[0][length], texts};
}

function main() {
  const src = path.resolve(process.argv[2] || path.join(root, '_work/zero_free_numerals_2026-09-17/run1'));
  const out = path.resolve(process.argv[3] || path.join(root, '_work/zero_free_numerals_2026-09-17/plaintexts'));
  assert(!fs.existsSync(out), 'Use a fresh output directory.'); fs.mkdirSync(out, {recursive: true});
  const save = (f, v) => fs.writeFileSync(path.join(out, f), JSON.stringify(v, null, 2) + '\n', {flag: 'wx'});
  const read = f => JSON.parse(fs.readFileSync(path.join(src, f)));
  const spec = read('spec.json'), data = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')));
  const raw = fs.readFileSync(path.join(src, 'accepted.jsonl')), rows = raw.toString().trim().split(/\r?\n/).map(JSON.parse);
  const vocab = vocabulary(), materials = new Map(), language = [], formats = [], partial = [];
  let parsed = 0, allCP1141Paths = 0, cp1141Models = 0, dictionaryPaths = 0n;
  const fields = spec.fields.map(f => [...(f.reverse ? [...data[f.field]].reverse().join('') : data[f.field])].map(c => c.charCodeAt(0) - 97));
  const makeDigits = (source, mapping) => source.map(s => mapping[s]).join('');
  function add(text, provenance) { const hex = Buffer.from(text).toString('hex'); if (hex && !materials.has(hex)) materials.set(hex, {id: materials.size, hex, provenance}); }
  const base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const formatSpecs = [{name: 'hex64-lower', alphabet: '0123456789abcdef', length: 64}, {name: 'hex64-upper', alphabet: '0123456789ABCDEF', length: 64},
    {name: 'WIF-uncompressed', alphabet: base58, length: 51, first: '5'}, {name: 'WIF-compressed', alphabet: base58, length: 52, first: 'KL'}];
  // Cheap no-boundary grammar filter before the more expensive fixed-length DP.
  const {machine} = require('./zero_free_numerals.cjs');
  const formatMachines = spec.models.map(m => formatSpecs.map(f => machine(m.codes.filter(c => f.alphabet.includes(String.fromCharCode(c.m))))));
  const controlText = 'This decoded text is a test!';
  const controlCodes = spec.models[2].codes, byByte = new Map(controlCodes.map(c => [c.m, c.word]));
  const controlGraph = indexedGraph([...controlText].map(c => byByte.get(c.charCodeAt(0))).join(''), controlCodes);
  assert(characters(controlGraph.slice(0, -1), vocab).best);
  const hexControl = '0123456789abcdef'.repeat(4);
  const hexGraph = indexedGraph([...hexControl].map(c => byByte.get(c.charCodeAt(0))).join(''), controlCodes);
  assert(fixedFormat(hexGraph, formatSpecs[0].alphabet, 64).texts.includes(hexControl));
  const started = Date.now();
  for (const r of rows) {
    const mapping = [...r.mapping].map(Number), model = spec.models[r.model], digits = makeDigits(fields[r.field], mapping);
    const graph = indexedGraph(digits, model.codes), parsedModel = {rank: r.rank, model: r.model, field: r.field, mapping: r.mapping};
    if (model.encoding === 'CP1141') {
      const all = enumerate(graph, 100000); assert(all.complete);
      cp1141Models++; allCP1141Paths += all.texts.length;
      for (const text of all.texts) add(text, {...parsedModel, origin: 'all-CP1141-plaintexts'});
    }
    const lang = characters(graph.slice(0, -1), vocab); dictionaryPaths += BigInt(lang.paths);
    if (lang.best) { language.push({...parsedModel, ...lang}); add(lang.best.text, {...parsedModel, origin: 'best-dictionary-compatible-path'}); }
    for (let f = 0; f < formatSpecs.length; f++) {
      if (!formatMachines[r.model][f].accepts(fields[r.field], mapping)) continue;
      const def = formatSpecs[f], decoded = fixedFormat(graph, def.alphabet, def.length, def.first);
      if (BigInt(decoded.paths)) {
        formats.push({...parsedModel, format: def.name, ...decoded});
        if (!decoded.complete) partial.push({...parsedModel, format: def.name, paths: decoded.paths});
        for (const text of decoded.texts) add(text, {...parsedModel, origin: def.name});
      }
    }
    parsed++;
    if (parsed % 20000 === 0) console.log(JSON.stringify({stage: 'decoding', models: parsed, languageModels: language.length, formats: formats.length, materials: materials.size, elapsedMs: Date.now() - started}));
  }
  save('spec.json', {hypothesis: 'Follow every compatible zero-omitted numeral model using a pre-existing non-Telegram English dictionary and exact Bitcoin key text grammars.',
    languageScope: 'Every maximal alphabetic run must be a Norvig count_1w word, at most32 letters, singleton A/I only. Digits/punctuation/controls separate words. Count every compatible path; authenticate only the optimum per model (most letters, fewest nonletters, greatest unigram score). This is not exhaustion of ambiguous plaintexts.',
    formatSpecs, CP1141Scope: 'Enumerate every plaintext of all nine compatible CP1141 models.',
    formatLimit: 10000, priorAcceptedSHA256: sha(raw), corpusSHA256: vocab.rawSHA256, sourceSHA256: sha(fs.readFileSync(__filename))});
  save('controls.json', {dictionaryPlanted: true, hex64PlantedRecovered: true});
  save('language.json', language); save('formats.json', formats); save('materials.json', [...materials.values()]);
  let attempts = 0, maxPrintable = 0; const padding = [], semantic = [], decisions = crypto.createHash('sha256');
  for (const m of materials.values()) for (const form of ['direct', 'sha256-hex']) {
    const b = Buffer.from(m.hex, 'hex'), pw = form === 'direct' ? b : Buffer.from(sha(b));
    for (const [blob, record] of Object.entries(data.blobs)) for (const digest of ['sha256', 'md5']) {
      const body = open(pw, record, digest); attempts++;
      decisions.update([m.id, form, blob, digest, body ? body.toString('hex') : '-'].join('|') + '\n');
      if (body) {
        const printable = [...body].filter(x => x >= 32 && x <= 126 || [9,10,13].includes(x)).length / body.length;
        const hit = {material: m.id, form, blob, digest, hex: body.toString('hex'), printable}; padding.push(hit); maxPrintable = Math.max(maxPrintable, printable);
        if (printable >= 0.85 || body.includes(Buffer.from('Salted__')) || body.includes(Buffer.from('U2FsdGVk'))) semantic.push(hit);
      }
    }
  }
  save('padding.json', padding); save('semantic_candidates.json', semantic);
  const result = {models: parsed, dictionaryCompatibleModels: language.length, dictionaryCompatiblePaths: String(dictionaryPaths), dictionaryBestPathsAuthenticated: language.length,
    CP1141Models: cp1141Models, CP1141AllPlaintextPaths: allCP1141Paths, keyFormatModels: formats.length, keyFormatPartial: partial,
    materials: materials.size, attempts, padding: padding.length, maxPrintable, semanticCandidates: semantic.length,
    decisionsSHA256: decisions.digest('hex'), authenticatedSolution: false,
    limit: 'Arbitrary ASCII ambiguous paths and non-optimal dictionary paths were not all tested as passwords; key-format completeness is recorded separately.', elapsedMs: Date.now() - started};
  save('summary.json', result); console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) main();
module.exports = {indexedGraph, fixedFormat};
