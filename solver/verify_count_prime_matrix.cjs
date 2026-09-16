/* Independent geometry, key-generation and interval-count audit.
 * The UTF8 counter uses scalar byte templates, not the searcher's automata.
 * node solver/verify_count_prime_matrix.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {countUtf8}=require('./verify_utf8_decimal.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','count_prime_matrix_2026-09-16');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const specBytes=fs.readFileSync(path.join(out,'spec.json')),spec=JSON.parse(specBytes),summaryBytes=fs.readFileSync(path.join(out,'summary.json')),summary=JSON.parse(summaryBytes);
assert.equal(spec.inputSHA256,sha(inputBytes));assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(root,'solver','count_prime_matrix.cjs'))));
for(const [file,hash]of Object.entries(spec.dependencies))assert.equal(hash,sha(fs.readFileSync(path.join(root,'solver',file))));
const counts={B:0,Y:0},cellColors=new Map();for(const [,color,r,c]of input.colored){counts[color]++;assert(!cellColors.has(r+','+c));cellColors.set(r+','+c,color);}
assert.deepEqual(counts,{B:15,Y:9});assert.deepEqual(counts,spec.geometry.counts);
function nth(n){let seen=0;for(let x=2;;x++){let prime=true;for(let d=2;d*d<=x;d++)if(x%d===0){prime=false;break;}if(prime&&++seen===n)return x;}}
const values={B:nth(counts.B),Y:nth(counts.Y)};assert.deepEqual(values,{B:47,Y:23});assert.deepEqual(values,spec.geometry.values);
const lists=new Map();
for(const background of ['bits','zero']) {
  const matrix=Array.from({length:14},()=>Array(14).fill(0));
  for(let r=0;r<14;r++)for(let c=0;c<14;c++){const color=cellColors.get(r+','+c);matrix[r][c]=color?values[color]:background==='bits'?input.matrix[r][c]:0;}
  assert.deepEqual(matrix,spec.geometry.matrices.find(m=>m.background===background).matrix);
  for(const dir of ['rows','columns']){const sums=Array(14).fill(0);for(let r=0;r<14;r++)for(let c=0;c<14;c++)sums[dir==='rows'?r:c]+=matrix[r][c];const name=background+'/'+dir;lists.set(name,sums);assert.deepEqual(sums,spec.geometry.lists.find(l=>l.name===name).values);}
}
assert.equal(spec.geometry.matrices.length,2);assert.equal(spec.geometry.lists.length,4);
const keys=new Map();
for(const [name,list]of lists)for(const repr of ['residue10','decimal-digits']) {
  const digits=repr==='residue10'?list.map(n=>n%10):[...list.join('')].map(Number);
  for(const reverse of [false,true])for(let offset=0;offset<digits.length;offset++) {
    const base=reverse?[...digits].reverse():digits,rotated=Array.from({length:base.length},(_,i)=>base[(i+offset)%base.length]);
    keys.set(rotated.join(''),rotated);
  }
}
assert.deepEqual([...keys.keys()].sort(),spec.keys.map(k=>k.id).sort());for(const k of spec.keys)assert.deepEqual(keys.get(k.id),k.values);
const casesBytes=fs.readFileSync(path.join(out,'cases.jsonl')),cases=casesBytes.toString('utf8').trim().split('\n').map(JSON.parse);
assert.equal(sha(casesBytes),summary.casesSHA256);
const ids=new Set();let certs=0,nodes=0;
const modulo=(x,m)=>((x%m)+m)%m;
for(const c of cases) {
  assert(['dbbi','faed'].includes(c.field)&&typeof c.reverse==='boolean');assert(['digits','carry'].includes(c.family));
  assert(['subtract','add','beaufort'].includes(c.mode)&&['big','little'].includes(c.order));
  const key=keys.get(c.key);assert(key);const id=[c.field,c.reverse,c.key,c.family,c.mode,c.order].join('/');assert(!ids.has(id));ids.add(id);
  const source=c.reverse?[...input[c.field]].reverse().join(''):input[c.field],length=source.length,M=10n**BigInt(length);
  const K=BigInt(Array.from({length},(_,i)=>key[i%key.length]).join(''));
  const sets=[...source].map((ch,i)=>{
    const choices=ch==='g'?[0,7]:[ch.charCodeAt(0)-96];
    if(c.family==='carry')return choices;
    return choices.map(v=>Number(modulo(BigInt(c.mode==='subtract'?v-key[i%key.length]:c.mode==='add'?v+key[i%key.length]:key[i%key.length]-v),10n))).sort((a,b)=>a-b);
  });
  const ambiguous=sets.filter(s=>s.length===2).length;assert.equal(ambiguous,c.ambiguous);
  function endpoint(mask,high){let j=0;return BigInt(sets.map(s=>{if(s.length===1)return s[0];const choice=j<mask.length?Number(mask[j]):Number(high);j++;return s[choice];}).join(''));}
  function checkRange(lo,hi){assert.equal(countUtf8(hi,c.order)-countUtf8(lo-1n,c.order),0n);}
  const prefixes=[];let covered=0n;
  assert(c.complete&&c.hits.length===0&&c.pending.length===0);
  for(const mask of c.certificates) {
    assert.match(mask,/^[01]*$/);assert(mask.length<=ambiguous);prefixes.push(mask);
    const lo=endpoint(mask,false),hi=endpoint(mask,true);
    if(c.family==='digits')checkRange(lo,hi);
    else {
      const start=c.mode==='subtract'?lo-K:c.mode==='add'?lo+K:K-hi,end=c.mode==='subtract'?hi-K:c.mode==='add'?hi+K:K-lo;
      const q0=(start-modulo(start,M))/M,q1=(end-modulo(end,M))/M;
      for(let q=q0;q<=q1;q++){const a=start>q*M?start:q*M,b=end<(q+1n)*M-1n?end:(q+1n)*M-1n;checkRange(a-q*M,b-q*M);}
    }
    covered+=1n<<BigInt(ambiguous-mask.length);certs++;
  }
  prefixes.sort();for(let i=1;i<prefixes.length;i++)assert(!prefixes[i].startsWith(prefixes[i-1]));assert.equal(covered,1n<<BigInt(ambiguous));nodes+=c.nodes;
}
assert.equal(cases.length,keys.size*2*2*2*3*2);assert.equal(summary.cases,cases.length);assert.equal(summary.complete,cases.length);assert.equal(summary.certificates,certs);assert.equal(summary.nodes,nodes);assert.deepEqual(summary.candidates,[]);assert.deepEqual(summary.partial,[]);
// Reconstruct every direct list-based preimage, independently of saved labels.
const preBytes=fs.readFileSync(path.join(out,'preimages.json')),pre=JSON.parse(preBytes),expected=new Set();
const words=['reinsertingtheprimebasicsafterwhichyouwillberequiredto','sheisgoingtodieandthereisnothingyoucandotostopit'];assert.deepEqual(pre.lastwords,words);
function add(b){expected.add(b.toString('hex'));}
for(const bg of ['bits','zero']) {
  const r=lists.get(bg+'/rows'),c=lists.get(bg+'/columns');
  const variants=[r,c,[...r,...c],[...c,...r],r.flatMap((v,i)=>[v,c[i]])];
  for(const list of variants)for(const reverse of [false,true]){
    const v=reverse?[...list].reverse():list,bytes=[...['',',',' ','\n'].map(s=>Buffer.from(v.join(s))),Buffer.from(v)];
    for(const b of bytes){add(b);for(const w of words){add(Buffer.concat([b,Buffer.from(w)]));add(Buffer.concat([Buffer.from(input.dbbi),b,Buffer.from(input.faed),Buffer.from(w)]));}}
  }
}
assert.deepEqual([...expected].sort(),pre.values.map(v=>v.hex).sort());assert.equal(pre.values.length,summary.preimages);
const result={allPassed:true,counts,primeValues:values,lists:lists.size,keys:keys.size,cases:cases.length,certificates:certs,allMasksCovered:true,allExcluded:true,preimagesChecked:expected.size,
  method:'Rebuild colours and primes, lists and every cyclic key; reconstruct each mask interval and count RFC3629 byte-template strings. No searcher or search automaton imported. Rebuild all password preimages.',
  hashes:{spec:sha(specBytes),cases:sha(casesBytes),summary:sha(summaryBytes),preimages:sha(preBytes),counter:sha(fs.readFileSync(path.join(root,'solver','verify_utf8_decimal.cjs'))),verifier:sha(fs.readFileSync(__filename))}};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
