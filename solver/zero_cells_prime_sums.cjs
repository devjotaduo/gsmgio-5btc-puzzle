'use strict';
// A bounded composition of existing clues; this is not a confirmed recipe.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {derive} = require('./color_factor_sum_passwords.cjs');
const {open} = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..');
const folder = path.join(root, '_work/zero_cells_prime_sums_2026-09-16');
const hash = b => crypto.createHash('sha256').update(b).digest();
const sha = b => hash(b).toString('hex');
function geometry(input) {
  const matrix = input.matrix;
  assert.equal(matrix.length, 14); assert(matrix.every(r => r.length === 14 && r.every(x => x === 0 || x === 1)));
  assert.equal(input.spiral.length, 196);
  assert.equal(new Set(input.spiral.map(rc => rc.join(','))).size, 196);
  const bits = input.spiral.map(([r,c]) => matrix[r][c]);
  const url = Array.from({length:24}, (_,i) => String.fromCharCode(parseInt(bits.slice(i*8,i*8+8).join(''),2))).join('');
  assert.equal(url, 'gsmg.io/theseedisplanted'); assert.equal(bits.slice(192).join(''), '0000');
  const zeros = input.spiral.slice(0,192).filter(([r,c]) => matrix[r][c] === 0);
  assert.equal(zeros.length, 91); assert.equal(input.dbbi.length, zeros.length);
  assert.equal(matrix.flat().reduce((a,b) => a+b, 0), 101);
  const colors = new Map(input.colored.map(([i,color,r,c]) => [r+','+c,{i,color}]));
  assert.equal(input.colored.filter(c => c[1] === 'B').length, 15); assert.equal(input.colored.filter(c => c[1] === 'Y').length, 9);
  for (const [i,color,r,c] of input.colored) { assert.deepEqual(input.spiral[i], [r,c]); if (color === 'B' || color === 'Y') assert.equal(matrix[r][c], color === 'B' ? 1 : 0); }
  assert.deepEqual(input.spiral[163], [7,4]); assert(!colors.has('7,4')); assert.equal(matrix[7][4],0);
  return {url, tail:bits.slice(192), ones:101, fullZeros:95, urlZeros:91, zeros, colors};
}
function materials(input) {
  const g = geometry(input), derivation = derive(), matrices = [], lists = [], candidates = new Map();
  const lastwords = ['reinsertingtheprimebasicsafterwhichyouwillberequiredto','sheisgoingtodieandthereisnothingyoucandotostopit'];
  assert(input.phase32_text.replace(/[^a-z]/gi,'').toLowerCase().includes(lastwords[0]));
  function add(text, provenance) {
    const bytes = Buffer.from(text), hex = bytes.toString('hex');
    if (!candidates.has(hex)) candidates.set(hex, {id:candidates.size,hex,provenance});
  }
  for (const reverse of [false,true]) {
    const source = reverse ? [...input.dbbi].reverse().join('') : input.dbbi;
    const filled = input.matrix.map(r => r.slice());
    g.zeros.forEach(([r,c], i) => {filled[r][c] = source.charCodeAt(i)-96;});
    for (const [pair, weights] of derivation.pairs.entries()) for (const zeroNearWhite of [false,true]) {
      const matrix = filled.map((row,r) => row.map((v,c) => {
        const color = g.colors.get(r+','+c)?.color;
        return color === 'B' ? weights.blue : color === 'Y' ? weights.yellow : r === 7 && c === 4 && zeroNearWhite ? 0 : v;
      }));
      const row = matrix.map(r => r.reduce((a,b) => a+b,0)), col = Array.from({length:14},(_,c) => matrix.reduce((s,r) => s+r[c],0));
      assert.equal(row.reduce((a,b) => a+b,0),col.reduce((a,b) => a+b,0));
      const matrixId = matrices.length;
      matrices.push({id:matrixId,reverse,pair,zeroNearWhite,matrix,rows:row,columns:col});
      for (const [order, original] of [['rows',row],['columns',col],['rows-columns',[...row,...col]],['columns-rows',[...col,...row]],['interleaved',row.flatMap((x,i) => [x,col[i]])]]) for (const reverseList of [false,true]) {
        const values = reverseList ? [...original].reverse() : original, id = lists.length;
        lists.push({id,matrix:matrixId,order,reverse:reverseList,values});
        for (const [format,text] of [['digits',values.join('')],['comma',values.join(',')],['space',values.join(' ')],['newline',values.join('\n')],['json',JSON.stringify(values)],['bracket-spaces','['+values.join(', ')+']']]) {
          add(text,{list:id,format,composition:'list'});
          lastwords.forEach((words,k) => {
            add(text+words,{list:id,format,composition:'list-lastwords',words:k});
            add(String(weights.yellow)+weights.blue+text+words,{list:id,format,composition:'yellow-blue-list-lastwords',words:k});
          });
        }
      }
    }
  }
  const overwrites = g.zeros.flatMap(([r,c],i) => g.colors.get(r+','+c)?.color === 'Y' ? [{i,r,c,original:input.dbbi[i],reversed:input.dbbi.at(-1-i)}] : []);
  assert.equal(overwrites.length,9);
  const nearWhiteIndex = g.zeros.findIndex(([r,c]) => r === 7 && c === 4);
  return {geometry:{url:g.url,tail:g.tail,ones:g.ones,fullZeros:g.fullZeros,urlZeros:g.urlZeros,zeros:g.zeros,overwrites,nearWhiteIndex},derivation,lastwords,matrices,lists,candidates:[...candidates.values()]};
}
function run() {
  fs.mkdirSync(folder,{recursive:true}); assert(!fs.existsSync(path.join(folder,'spec.json')),'Inspect existing experiment before rerunning');
  const inputRaw = fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), pre = materials(input);
  const oldPath = 'solver/experiments/claude_endgame_2026_09_02/gsmg_common.py';
  const oldRaw = fs.readFileSync(path.join(root,oldPath)), match = oldRaw.toString().match(/MATRIX_IMG = \[list\(map\(int, r\)\) for r in """([\s\S]*?)"""\.split\(\)\]/);
  assert(match); const old = match[1].trim().split(/\s+/).map(r => [...r].map(Number));
  const differences = input.matrix.flatMap((row,r) => row.flatMap((v,c) => v === old[r][c] ? [] : [{r,c,old:old[r][c],current:v,spiral:input.spiral.findIndex(rc => rc[0] === r && rc[1] === c)}]));
  assert.deepEqual(differences,[{r:7,c:6,old:1,current:0,spiral:193}]);
  assert(input.spiral.slice(0,192).every(([r,c]) => old[r][c] === input.matrix[r][c]));
  const spec = {hypothesis:'Fill the 91 zero cells of the known 192-bit URL spiral with complete DBBI under a1..i9, original/reversed. Replace blue/yellow cells by prime factors of hex-digit sums, RGB-channel sums or packed RGB values; all14 previously declared factor pairs. Preserve ordinary black bits and the four centre zeros. The9 DBBI digits on yellow cells are overwritten. Either preserve the DBBI digit at the near-white cell [7,4], spiral163, or set it to zero. Sum rows/columns, five orders, both directions, six exact text formats; list alone, list+one of two fixed last-word clauses, or yellow+blue+list+clause. Direct and SHA256-hex passwords. This formula is not confirmed by the creator.',geometry:pre.geometry,derivation:pre.derivation,lastwords:pre.lastwords,inputSHA256:sha(inputRaw),sourceSHA256:sha(fs.readFileSync(__filename)),dependencies:Object.fromEntries(['color_factor_sum_passwords.cjs','decimal_keystream_constraints.cjs'].map(f => [f,sha(fs.readFileSync(path.join(__dirname,f)))])),historicalAudit:{file:oldPath,SHA256:sha(oldRaw),differences,urlRegionIdentical:true,meaning:'The102/101 discrepancy does not invalidate the old91-zero fill outside the centre. The old claim rejecting91 zeros in0..191 is incorrect; the full196 cells have95 zeros.'}};
  for (const [name,obj] of [['spec',spec],['matrices',pre.matrices],['lists',pre.lists],['materials',pre.candidates]]) fs.writeFileSync(path.join(folder,name+'.json'),JSON.stringify(obj,null,2)+'\n');
  const passwords = new Map();
  for (const c of pre.candidates) for (const [form,b] of [['direct',Buffer.from(c.hex,'hex')],['sha256-hex',Buffer.from(sha(Buffer.from(c.hex,'hex')))]]) if (!passwords.has(b.toString('hex'))) passwords.set(b.toString('hex'),{id:passwords.size,material:c.id,form,hex:b.toString('hex')});
  const ctrl = Buffer.from(input.phase32_control_b64,'base64');
  assert.equal(sha(open(Buffer.from(input.phase32_control_password),{salt:ctrl.subarray(8,16).toString('hex'),ciphertext:ctrl.subarray(16).toString('hex')},'sha256')),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const flags = [], padding = [], scalars = new Set(); let maxPrintable = 0;
  for (const p of passwords.values()) {
    const bytes = Buffer.from(p.hex,'hex'); scalars.add(sha(bytes));
    for (const [blob,b] of Object.entries(input.blobs)) for (const digest of ['sha256','md5']) {
      const body = open(bytes,b,digest); flags.push(Number(body !== null));
      if (body === null) continue;
      const printable = [...body].filter(x => x >= 32 && x <= 126 || [9,10,13].includes(x)).length/body.length;
      maxPrintable = Math.max(maxPrintable,printable); padding.push({password:p.id,blob,digest,hex:body.toString('hex'),printable});
      scalars.add(sha(body));
      if (body.length === 32) scalars.add(body.toString('hex'));
      if (/^[0-9a-fA-F]{64}$/.test(body.toString('latin1'))) scalars.add(body.toString('latin1').toLowerCase());
    }
  }
  const ec = crypto.createECDH('secp256k1'), n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const scalarList = [...scalars].filter(h => BigInt('0x'+h) > 0n && BigInt('0x'+h) < n).sort(), matches = [];
  ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex')); assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(crypto.createHash('ripemd160').update(hash(Buffer.from(input.target_pubkey,'hex'))).digest('hex'),input.target_h160);
  scalarList.forEach(h => {ec.setPrivateKey(Buffer.from(h,'hex'));const pub = ec.getPublicKey('hex','uncompressed');if (pub.slice(2,66) === input.target_pubkey.slice(2,66)) matches.push({hex:h,exact:pub === input.target_pubkey});});
  const result = {complete:true,matrices:pre.matrices.length,lists:pre.lists.length,materials:pre.candidates.length,passwords:[...passwords.values()],attempts:flags.length,flags:Buffer.from(flags).toString('base64'),padding,maxPrintable,scalarCount:scalarList.length,scalarStreamSHA256:sha(Buffer.concat(scalarList.map(h => Buffer.from(h,'hex')))),matches,sourceSHA256:sha(fs.readFileSync(__filename)),inputSHA256:sha(inputRaw),hashes:Object.fromEntries(['spec','matrices','lists','materials'].map(f => [f,sha(fs.readFileSync(path.join(folder,f+'.json')))]))};
  fs.writeFileSync(path.join(folder,'oracles.json'),JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify({...result,passwords:passwords.size,flags:flags.length,padding:padding.length,hashes:undefined}));
}
if (require.main === module) run();
module.exports = {geometry,materials};
