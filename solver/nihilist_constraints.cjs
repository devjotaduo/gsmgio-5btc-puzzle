/* Exact numeric feasibility for ACA 5x5 Nihilist substitution.
 * No language score, guessed key alphabet, or cryptographic-password claim.
 */
'use strict';
const fs = require('node:fs'), path = require('node:path');
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'nihilist_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const coordinates = Array.from({length: 25}, (_, i) => 10 * (1 + Math.floor(i / 5)) + i % 5 + 1);
const allKeys = (1 << 25) - 1;
const keyMasks = Array(100).fill(0);
for (let k = 0; k < 25; k++) for (const p of coordinates) keyMasks[(coordinates[k] + p) % 100] |= 1 << k;
const popcount = x => x.toString(2).replace(/0/g, '').length;
const decodePairs = s => Array.from({length: s.length / 2}, (_, i) => [s.charCodeAt(2 * i) - 97, s.charCodeAt(2 * i + 1) - 97]);
function pairMasks(pairs, mapping) {
  return pairs.map(([a, b]) => {
    let mask = 0;
    // Unit 1 is impossible in a sum of two coordinates. Preserve both
    // choices here so the numeric test itself verifies this restriction.
    for (const x of mapping[a] === 1 ? [0, 1] : [mapping[a]]) {
      for (const y of mapping[b] === 1 ? [0, 1] : [mapping[b]]) mask |= keyMasks[x * 10 + y];
    }
    return mask;
  });
}
function compatibleKeys(masks, period) {
  const result = Array(period).fill(allKeys);
  for (let i = 0; i < masks.length; i++) if ((result[i % period] &= masks[i]) === 0) return null;
  return result;
}
function graphFor(pairs, period) {
  const edges = Array(9).fill(0);
  for (let i = 0; i < pairs.length; i++) for (let j = i + period; j < pairs.length; j += period) {
    const a = pairs[i][1], b = pairs[j][1];
    if (a !== b) { edges[a] |= 1 << b; edges[b] |= 1 << a; }
  }
  return edges;
}
function permutations(values, callback, prefix = []) {
  if (!values.length) { callback(prefix); return; }
  for (let i = 0; i < values.length; i++) permutations(values.filter((_, j) => i !== j), callback, [...prefix, values[i]]);
}
function witness(source, mapping, period) {
  const pairs = decodePairs(source), masks = compatibleKeys(pairMasks(pairs, mapping), period);
  assert(masks);
  const key = masks.map(mask => coordinates.find((_, i) => mask & (1 << i)));
  const cipherNumbers = [], plaintextCoordinates = [];
  for (let i = 0; i < pairs.length; i++) {
    const [a, b] = pairs[i]; let found = false;
    for (const x of mapping[a] === 1 ? [0, 1] : [mapping[a]]) {
      for (const y of mapping[b] === 1 ? [0, 1] : [mapping[b]]) {
        const n = x * 10 + y, plain = (n - key[i % period] + 100) % 100;
        if (!found && coordinates.includes(plain)) {
          cipherNumbers.push(n); plaintextCoordinates.push(plain); found = true;
        }
      }
    }
    assert(found);
  }
  const digits = cipherNumbers.map(n => String(n).padStart(2, '0')).join('');
  const inverse = Object.fromEntries(mapping.map((d, i) => [d, String.fromCharCode(97 + i)]));
  inverse[0] = inverse[1];
  assert.equal([...digits].map(d => inverse[d]).join(''), source);
  return {mapping, zeroAlias: inverse[1], period, keyCoordinates: key,
    ciphertextNumbers: cipherNumbers, plaintextCoordinates,
    status: 'Constructed numeric witness, not recovered plaintext or an authenticated password.'};
}
function analyze(source) {
  assert(/^[a-i]+$/.test(source) && source.length % 2 === 0);
  const pairs = decodePairs(source), seen = new Set(pairs.map(([a, b]) => 9 * a + b));
  assert.equal(new Set(pairs.map(p => p[1])).size, 9, 'All unit symbols are needed for the alias=1 theorem.');
  const missing = [];
  for (let a = 0; a < 9; a++) for (let b = 0; b < 9; b++) if (!seen.has(9 * a + b)) missing.push([a, b]);
  const endpoints = missing.filter(([a, b]) => a !== b);
  const periods = Array.from({length: pairs.length}, (_, i) => {
    const period = i + 1, edges = graphFor(pairs, period), degrees = edges.map(popcount);
    return {period, edges, degrees, endpointDegreeRejected: degrees.filter(d => d <= 4).length < 2,
      unitCompatibleMappings: 0, mappings: []};
  });
  let mappings = 0;
  for (const [low, high] of endpoints) {
    const middle = Array.from({length: 9}, (_, i) => i).filter(i => i !== low && i !== high);
    permutations(middle, values => {
      const order = [low, ...values, high], mapping = Array(9);
      order.forEach((symbol, i) => { mapping[symbol] = i === 8 ? 1 : i + 2; });
      const masks = pairMasks(pairs, mapping);
      assert(masks.every(Boolean)); mappings++;
      for (const rec of periods) {
        if (rec.endpointDegreeRejected) continue;
        let unitOK = true;
        for (let i = 0; i < 4 && unitOK; i++) for (let j = i + 5; j < 9; j++) {
          if (rec.edges[order[i]] & (1 << order[j])) { unitOK = false; break; }
        }
        if (!unitOK) continue;
        rec.unitCompatibleMappings++;
        if (compatibleKeys(masks, rec.period)) rec.mappings.push(mapping.join(''));
      }
    });
  }
  for (const rec of periods) rec.mappings.sort();
  const first = periods.find(r => r.mappings.length);
  const known = periods.filter(r => r.mappings.includes('123456789')).map(r => r.period);
  return {symbols: source.length, numbers: pairs.length, observedPairs: seen.size,
    missingPairs: missing.map(([a, b]) => String.fromCharCode(97 + a, 97 + b)),
    endpointPairs: endpoints.map(([a, b]) => String.fromCharCode(97 + a, 97 + b)),
    reducedMappings: mappings, periods, minimumPeriod: first?.period ?? null,
    knownMappingPeriods: known,
    witnesses: first ? first.mappings.map(s => witness(source, [...s].map(Number), first.period)) : []};
}
function controls() {
  const square = 'SIMPLEABCDFGHKNOQRTUVWXYZ', plain = 'THEEARLYBIRD', key = 'EASY';
  assert.equal(square.length, 25);
  const encode = (text, keyword, alphabet) => [...text].map((c, i) =>
    (coordinates[alphabet.indexOf(c)] + coordinates[alphabet.indexOf(keyword[i % keyword.length])]) % 100);
  assert.deepEqual(encode(plain, key, square), [65, 55, 32, 75, 43, 65, 26, 8, 44, 34, 54, 79]);
  let planted = 0;
  const text = 'INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE'.repeat(4);
  for (const mapping of [[1,2,3,4,5,6,7,8,9],[5,8,2,7,1,9,4,6,3],[9,8,7,6,5,4,3,2,1]]) {
    const values = encode(text, 'MATRIX', square), inverse = Object.fromEntries(mapping.map((v, i) => [v, String.fromCharCode(97+i)]));
    inverse[0] = inverse[1];
    const source = [...values.map(n => String(n).padStart(2, '0')).join('')].map(d => inverse[d]).join('');
    const pairs = decodePairs(source), masks = pairMasks(pairs, mapping), got = compatibleKeys(masks, 6);
    assert(got);
    for (let i = 0; i < 6; i++) assert(got[i] & (1 << square.indexOf('MATRIX'[i])));
    const order = Array.from({length:9}, (_,i)=>i).sort((a,b)=>(mapping[a]===1?10:mapping[a])-(mapping[b]===1?10:mapping[b]));
    const graph = graphFor(pairs, 6);
    for (let i=0;i<4;i++) for(let j=i+5;j<9;j++) assert(!(graph[order[i]] & (1<<order[j])));
    witness(source, mapping, 6); planted++;
  }
  return {acaPublishedExample: true, plantedMappings: planted};
}
function main() {
  fs.mkdirSync(out, {recursive:true});
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')), data=JSON.parse(raw);
  const save=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
  save('spec.json',{createdAt:new Date().toISOString(),inputSHA256:sha(raw),sourceSHA256:sha(fs.readFileSync(__filename)),
    reference:'https://www.cryptogram.org/downloads/aca.info/ciphers/NihilistSubstitution.pdf',
    model:'ACA 5x5 Nihilist substitution: C=(P+K) mod 100; P,K in {11..15,21..25,31..35,41..45,51..55}; two decimal digits per ciphertext number.',
    scope:'Entire FAED in both symbol orders; all bijections a..i -> 1..9; one chosen symbol may be 0 or its mapped value independently at each occurrence; all periods 1..285; unknown 25-letter square and arbitrary key coordinates.',
    reduction:'Every symbol appears in a units position. Unit 1 is impossible, hence the zero alias must map to 1 and all its unit occurrences must be 0. Ciphertext 20 is impossible, so the ordered symbol pair (digit2, zeroAlias) must be absent.',
    exclusionLimits:'Not 6x6 squares, untruncated three-digit sums, multiple zero aliases, transposed digits, homophones or binary encodings. DBBI itself has odd digit count and cannot be a complete stream of two-digit ciphertext numbers in this model.',
    acceptance:'Numeric compatibility is not English, a recovered password, or authenticated decryption.'});
  const checked=controls(), results=[];
  for(const reversed of [false,true])results.push({reversed,...analyze(reversed?[...data.faed].reverse().join(''):data.faed)});
  save('results.json',results);
  const summary={controls:checked,orientations:results.map(r=>({reversed:r.reversed,reducedMappings:r.reducedMappings,
    minimumPeriod:r.minimumPeriod,knownMappingPeriods:r.knownMappingPeriods,
    compatiblePeriods:r.periods.filter(p=>p.mappings.length).map(p=>({period:p.period,mappings:p.mappings.length})),
    minimumWitnesses:r.witnesses.length})),resultsSHA256:sha(fs.readFileSync(path.join(out,'results.json'))),
    aesTrials:0,finalPasswordFound:false};
  save('summary.json',summary);console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={analyze,compatibleKeys,pairMasks};
