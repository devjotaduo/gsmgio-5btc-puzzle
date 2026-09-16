'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { graph } = require('./matrix_sum_words.cjs');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/matrix_sum_words_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
function materials(input, spec, results) {
  const normalized = input.phase32_text.replace(/[^a-z]/gi, '').toLowerCase(), start = normalized.indexOf('reinsertingtheprimebasics'), end = normalized.indexOf('select', start); assert(start >= 0 && end > start);
  const clauses = ['', normalized.slice(start, end), 'sheisgoingtodieandthereisnothingyoucandotostopit'], found = new Map();
  function add(text, provenance) { const hex = Buffer.from(text).toString('hex'); if (!found.has(hex)) found.set(hex, { id: found.size, hex, provenance }); }
  for (const r of results) if (r.best) {
    const p = spec.layouts[r.field][r.partition], edges = graph(input[r.field], p, r.zeroLetter, r.format), text = r.best.text;
    const sums = [...Buffer.from(text)].map((m, i) => { const e = edges[i].find(e => e.m === m); assert(e); return e.sum; });
    const forms = [['text', text], ['lowercase', text.toLowerCase()], ['uppercase', text.toUpperCase()], ['sum-digits', sums.join('')], ['sum-comma', sums.join(',')], ['sum-space', sums.join(' ')], ['sum-newline', sums.join('\n')], ['sum-json', JSON.stringify(sums)], ['sum-json-spaced', '[' + sums.join(', ') + ']']];
    for (const [form, value] of forms) for (const clause of clauses) add(value + clause, { configuration: r.id, form, clause });
  }
  return { clauses, values: [...found.values()] };
}
function main() {
  assert(!fs.existsSync(path.join(folder, 'oracles.json')), 'Inspect previous authentication first');
  const read = name => JSON.parse(fs.readFileSync(path.join(folder, name))), input = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'))), spec = read('spec.json'), results = read('results.json'), pre = materials(input, spec, results);
  fs.writeFileSync(path.join(folder, 'materials.json'), JSON.stringify(pre, null, 2) + '\n');
  const passwords = new Map(); for (const p of pre.values) for (const [form, pw] of [['direct', Buffer.from(p.hex,'hex')], ['sha256-hex', Buffer.from(sha(Buffer.from(p.hex,'hex')))]]) { const hex = pw.toString('hex'); if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, material: p.id, form, hex }); }
  const ctrl = Buffer.from(input.phase32_control_b64,'base64'); assert.equal(sha(open(Buffer.from(input.phase32_control_password), {salt:ctrl.subarray(8,16).toString('hex'),ciphertext:ctrl.subarray(16).toString('hex')}, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = [], scalars = new Set();
  for (const p of passwords.values()) { const pw = Buffer.from(p.hex,'hex'); scalars.add(sha(pw)); for (const [blob, data] of Object.entries(input.blobs)) for (const kdf of ['sha256','md5']) {
    const b = open(pw,data,kdf); flags.push(Number(b !== null)); if (b === null) continue;
    padding.push({password:p.id,blob,kdf,hex:b.toString('hex'),printable:[...b].filter(c=>c>=32&&c<=126||[9,10,13].includes(c)).length/b.length});
    if (b.length===32) scalars.add(b.toString('hex')); if (/^[0-9a-fA-F]{64}$/.test(b.toString())) scalars.add(b.toString().toLowerCase());
  } }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, values = [...scalars].filter(h=>BigInt('0x'+h)>0n&&BigInt('0x'+h)<order).sort(), matches = [], ec = crypto.createECDH('secp256k1');
  ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex')); assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  for (const h of values) {ec.setPrivateKey(Buffer.from(h,'hex')); const pub=ec.getPublicKey('hex','uncompressed');if(pub.slice(2,66)===input.target_pubkey.slice(2,66))matches.push({hex:h,exact:pub===input.target_pubkey});}
  const result = { complete:true, scope:'One lexically optimal witness per compatible configuration, decoded text/case forms and six serializations of its actual sum list, optionally followed by either fixed last-words clause. Direct/SHA256-hex passwords. Does not authenticate all compatible strings or zero assignments. Scalars are SHA256(password) and complete32-byte/64-hex padding bodies.', materials:pre.values.length,passwords:[...passwords.values()],attempts:flags.length,flags:Buffer.from(flags).toString('base64'),padding,maxPrintable:Math.max(0,...padding.map(p=>p.printable)),scalars:values.length,scalarStreamSHA256:sha(Buffer.concat(values.map(h=>Buffer.from(h,'hex')))),matches,sourceSHA256:sha(fs.readFileSync(__filename)),materialsSHA256:sha(fs.readFileSync(path.join(folder,'materials.json'))),resultsSHA256:sha(fs.readFileSync(path.join(folder,'results.json'))) };
  fs.writeFileSync(path.join(folder,'oracles.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({...result,passwords:passwords.size,flags:undefined,padding:padding.length}));
}
if (require.main === module) main();
module.exports = { materials };
