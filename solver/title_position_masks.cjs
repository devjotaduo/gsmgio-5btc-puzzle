'use strict';
// A finite, unconfirmed reading of the exact capitalization of the two titles.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..');
const out = path.resolve(process.argv[2] || path.join(root, '_work/title_position_masks_2026-09-16'));
assert(!fs.existsSync(out), 'Choose a fresh output folder');
fs.mkdirSync(out, {recursive: true});
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
const inputPath = path.join(root, '_work/prime_geometry_2026-09-11/inputs.json');
const inputBytes = fs.readFileSync(inputPath), input = JSON.parse(inputBytes);
const files = ['_work/salphaseion.html', ...fs.readdirSync(path.join(root, '_work/archive/endgame')).filter(n => /^endgame_\d+\.html$/.test(n)).map(n => '_work/archive/endgame/' + n)];
const pages = files.map(file => {
  const bytes = fs.readFileSync(path.join(root, file)), html = bytes.toString('utf8');
  const headings = [...html.matchAll(/<h1\b[^>]*>(.*?)<\/h1>/gi)].map(m => m[1].trim());
  assert.deepEqual(headings, ['SalPhaseIon', 'Cosmic Duality'], file);
  return {file, sha256: sha(bytes), headings};
});
const titles = pages[0].headings.map(text => ({text, length: text.length, uppercasePositions: [...text].flatMap((c, i) => /[A-Z]/.test(c) ? [i + 1] : [])}));
assert.deepEqual(titles.map(t => t.uppercasePositions), [[1, 4, 9], [1, 8]]);
assert.deepEqual(titles.map(t => t.length), [11, 14]);
const rules = [];
for (const power of [2, 3]) for (const origin of [0, 1]) rules.push({name: `power${power}/origin${origin}`, power, origin});
for (const text of ['SalPhaseIon', 'Cosmic Duality', 'CosmicDuality']) rules.push({name: 'periodic/' + text, text, period: text.length, positions: [...text].flatMap((c, i) => /[A-Z]/.test(c) ? [i] : [])});
function selected(rule, index) {
  if (rule.period) return rule.positions.includes(index % rule.period);
  const number = index + rule.origin, r = Math.round(number ** (1 / rule.power));
  return r ** rule.power === number;
}
const controls = [];
for (const rule of rules) {
  const mask = Array.from({length: 100}, (_, i) => selected(rule, i));
  const explicit = new Set();
  if (rule.period) for (let offset = 0; offset < 100; offset += rule.period) for (const pos of rule.positions) explicit.add(offset + pos);
  else for (let n = 0; n ** rule.power - rule.origin < 100; n++) if (n ** rule.power >= rule.origin) explicit.add(n ** rule.power - rule.origin);
  assert.deepEqual(mask, mask.map((_, i) => explicit.has(i)));
  controls.push({rule: rule.name, firstHundredMaskVerified: true});
}
const transforms = [];
for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) {
  const source = reverse ? [...input[field]].reverse().join('') : input[field];
  for (const rule of rules) for (const complement of [false, true]) {
    const mask = [...source].map((_, i) => selected(rule, i) !== complement);
    for (const action of ['zero', 'keep', 'drop']) {
      const digits = [...source].flatMap((c, i) => action === 'keep' && !mask[i] || action === 'drop' && mask[i] ? [] : [action === 'zero' && mask[i] ? 0 : c.charCodeAt(0) - 96]).join('');
      transforms.push({id: transforms.length, field, reverse, rule: rule.name, complement, indexSpace: 'field', action, digits});
    }
    let rank = 0;
    const digits = [...source].map(c => c === 'g' && (selected(rule, rank++) !== complement) ? 0 : c.charCodeAt(0) - 96).join('');
    transforms.push({id: transforms.length, field, reverse, rule: rule.name, complement, indexSpace: 'g-occurrences', action: 'zero', digits});
  }
}
assert.equal(transforms.length, 224);
const contexts = ['', 'reinsertingtheprimebasicsafterwhichyouwillberequiredto', 'sheisgoingtodieandthereisnothingyoucandotostopit'];
const materials = new Map();
function add(bytes, provenance) {
  const hex = bytes.toString('hex');
  if (!materials.has(hex)) materials.set(hex, {id: materials.size, hex, provenance});
}
for (const t of transforms) {
  assert.match(t.digits, /^\d+$/);
  const symbols = [...t.digits].map(c => c === '0' ? 'o' : String.fromCharCode(96 + +c)).join('');
  let hex = BigInt(t.digits).toString(16); if (hex.length % 2) hex = '0' + hex;
  const forms = [['digits', Buffer.from(t.digits)], ['symbols', Buffer.from(symbols)], ['uppercase-symbols', Buffer.from(symbols.toUpperCase())], ['decimal-integer-bytes', Buffer.from(hex, 'hex')]];
  for (const [form, bytes] of forms) for (let context = 0; context < contexts.length; context++) for (const order of context ? ['before', 'after'] : ['bare']) {
    const clause = Buffer.from(contexts[context]);
    add(order === 'before' ? Buffer.concat([clause, bytes]) : Buffer.concat([bytes, clause]), {transform: t.id, form, context, order});
  }
}
save('spec.json', {createdAt: new Date().toISOString(), sourceSHA256: sha(fs.readFileSync(__filename)), inputSHA256: sha(inputBytes), pages, titles, rules, contexts,
  hypothesis: 'Uppercase positions 1,4,9 in SalPhaseIon match squares; 1,8 in Cosmic Duality match cubes only when the space is counted. These are observations, NOT confirmed instructions.',
  scope: 'Both fields in both directions. Square/cube masks indexed from zero or one, or periodic exact title capitalization with/without the Cosmic space. Mask and complement. Whole-field zero/keep/drop, or zero selected g occurrences only. Decimal digits, canonical a1..i9/o0, uppercase, and minimal integer bytes. Bare or each of two fixed last-word clauses before/after. Direct and SHA256-hex passwords; three AES blobs and two EVP digests.',
  limitations: 'No arbitrary offsets, unknown title spelling, transpositions, multiple operations, or claim that the finite family covers the intended puzzle.'});
save('controls.json', controls); save('transforms.json', transforms); save('materials.json', [...materials.values()]);
const control = Buffer.from(input.phase32_control_b64, 'base64');
assert.equal(sha(open(Buffer.from(input.phase32_control_password), {salt: control.subarray(8, 16).toString('hex'), ciphertext: control.subarray(16).toString('hex')}, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
let attempts = 0, maxPrintable = 0; const padding = [], decisions = crypto.createHash('sha256');
for (const m of materials.values()) for (const form of ['direct', 'sha256-hex']) {
  const raw = Buffer.from(m.hex, 'hex'), password = form === 'direct' ? raw : Buffer.from(sha(raw));
  for (const [blob, b] of Object.entries(input.blobs)) for (const digest of ['sha256', 'md5']) {
    const body = open(password, b, digest); attempts++;
    decisions.update([m.id, form, blob, digest, body ? body.toString('hex') : '-'].join('|') + '\n');
    if (body) {
      const printable = [...body].filter(x => x >= 32 && x <= 126 || [9, 10, 13].includes(x)).length / body.length;
      maxPrintable = Math.max(printable, maxPrintable);
      padding.push({material: m.id, form, blob, digest, hex: body.toString('hex'), printable});
    }
  }
}
const summary = {transforms: transforms.length, distinctMaterials: materials.size, passwordCases: materials.size * 2, attempts, padding: padding.length, maxPrintable, decisionsSHA256: decisions.digest('hex'), warning: 'Padding is not authentication. No coherent output or final key is implied by these counts.'};
save('padding.json', padding); save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));
