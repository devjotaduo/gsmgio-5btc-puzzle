/* Independently count integers whose canonical-byte MSBs are periodic.
 * Does not import the searcher or its successor. Also enumerates every DBBI
 * g mask and confirms every compatible witness, not just exclusions.
 * node solver/verify_xor_period.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','xor_period_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(sha(inputBytes),spec.inputSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','xor_period_constraints.cjs'))),spec.sourceSHA256);
const p128=[1n],p2=[1n],ten=[1n];for(let i=1;i<=600;i++){p128.push(p128[i-1]*128n);p2.push(p2[i-1]*2n);ten.push(ten[i-1]*10n);}
function bytes(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
const cache=new Map();
function info(length,period) {
  const id=`${length}/${period}`;if(cache.has(id))return cache.get(id);
  let shorter=1n;for(let l=1;l<length;l++)shorter+=255n*p128[l-1]*p2[Math.min(period,l)-1];
  const weights=Array.from({length},(_,i)=>p128[length-i-1]*p2[Math.max(0,Math.min(period,length)-i-1)]);
  const r={shorter,weights};cache.set(id,r);return r;
}
function count(n,period) {
  if(n<0n)return 0n;if(n===0n)return 1n;
  const b=bytes(n),{shorter,weights}=info(b.length,period);let total=shorter;
  for(let i=0;i<b.length;i++) {
    if(i<period)total+=BigInt(b[i]-(i===0?1:0))*weights[i];
    else {
      const high=b[i%period]>=128?1:0,less=Math.min(128,Math.max(0,b[i]-128*high));total+=BigInt(less)*weights[i];
      if(Number(b[i]>=128)!==high)return total;
    }
  }
  return total+1n;
}
function periodic(n,p) {
  const b=bytes(n),bits=[...b].map(v=>v>=128);
  for(let i=0;i<bits.length;i++)for(let j=i+p;j<bits.length;j+=p)if(bits[i]!==bits[j])return false;return true;
}
let smallControls=0,rangeControls=0,largeControls=0;
for(let p=1;p<=4;p++) {
  let expected=0n;for(let n=0;n<65536;n++){if(periodic(BigInt(n),p))expected++;assert.equal(count(BigInt(n),p),expected);smallControls++;}
  for(let i=0;i<100;i++) {
    const lo=BigInt(65536+i*17713),hi=lo+1000n;let expected=0n;for(let n=lo;n<=hi;n++)if(periodic(n,p))expected++;
    assert.equal(count(hi,p)-count(lo-1n,p),expected);rangeControls++;
  }
}
for(const p of [1,2,3,14,32]) {
  let expected=1n;
  for(let l=1;l<=300;l++){expected+=255n*p128[l-1]*p2[Math.min(l,p)-1];assert.equal(count(256n**BigInt(l)-1n,p),expected);largeControls++;}
}
console.log(JSON.stringify({controls:{smallControls,rangeControls,largeControls}}));
const ids=new Set(),witnesses=[],fileHashes={};let cases=0,nodes=0,certificates=0,excluded=0,compatible=0,dbbiEnumerations=0;
for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of spec.fields[field]) {
  const source=reverse?[...input[field]].reverse().join(''):input[field],file=`${field}-${reverse?'reverse':'original'}-${alias}.json`,fileBytes=fs.readFileSync(path.join(out,file));fileHashes[file]=sha(fileBytes);
  const records=JSON.parse(fileBytes),low=BigInt([...source].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*ten[source.length-i-1]]:[]),tail=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tail[i]=tail[i+1]+weights[i];
  const values=field==='dbbi'?Array.from({length:1024},(_,mask)=>{
    const m=mask.toString(2).padStart(10,'0');let j=0;const n=BigInt([...source].map(c=>c==='g'?(m[j++]==='1'?7:0):c.charCodeAt(0)-96).join(''));return n;
  }):null;
  for(const r of records) {
    assert.equal(r.field,field);assert.equal(r.reverse,reverse);assert.equal(r.alias,alias);assert(r.period>=1&&r.period<=32&&Number.isInteger(r.period));
    const id=[field,reverse,alias,r.period].join('/');assert(!ids.has(id));ids.add(id);assert(r.complete&&r.pending.length===0);assert.equal(r.ambiguous,weights.length);
    const allPrefixes=[...r.certificates,...r.hits.map(h=>h.mask)].sort();for(let i=1;i<allPrefixes.length;i++)assert(!allPrefixes[i].startsWith(allPrefixes[i-1]));
    let coverage=0n;
    for(const m of r.certificates) {
      assert.match(m,/^[01]*$/);assert(m.length<=weights.length);let lo=low;for(let i=0;i<m.length;i++)if(m[i]==='1')lo+=weights[i];const hi=lo+tail[m.length];
      assert.equal(count(hi,r.period)-count(lo-1n,r.period),0n,`${id}/${m}`);coverage+=1n<<BigInt(weights.length-m.length);certificates++;
    }
    for(const h of r.hits) {
      assert.match(h.mask,/^[01]+$/);assert.equal(h.mask.length,weights.length);let n=low;for(let i=0;i<h.mask.length;i++)if(h.mask[i]==='1')n+=weights[i];
      assert.equal(n.toString(),h.decimal);assert.equal(bytes(n).toString('hex'),h.hex);assert(periodic(n,r.period));coverage++;
      witnesses.push({field,reverse,alias,period:r.period,mask:h.mask,hex:h.hex});
    }
    assert.equal(coverage,1n<<BigInt(weights.length));
    if(values) {
      const expected=values.filter(n=>periodic(n,r.period)).map(n=>n.toString()).sort();dbbiEnumerations+=values.length;
      assert.deepEqual(r.hits.map(h=>h.decimal).sort(),expected);
    }
    cases++;nodes+=r.nodes;if(r.hits.length)compatible++;else excluded++;
  }
  assert.equal(records.length,32);console.log(JSON.stringify({verified:file,cases,certificates}));
}
assert.equal(cases,640);assert.equal(cases,saved.cases);assert.equal(nodes,saved.nodes);assert.equal(certificates,saved.certificates);assert.equal(excluded,saved.excluded.length);assert.equal(compatible,saved.compatible.length);assert.equal(saved.partial.length,0);
const result={cases,nodes,certificates,excluded,compatible,witnesses:witnesses.length,allExclusionsAndWitnessesMatched:true,dbbiEnumerations,
  controls:{smallControls,rangeControls,largeControls},fileHashes,verifierSHA256:sha(fs.readFileSync(__filename)),
  conclusion:'All 576 FAED models excluded for every XOR byte key of periods 1..32. DBBI g models exclude periods 1..31; period32 has 32 original and 16 reverse-symbol witnesses. These are MSB-compatible ciphertexts, not recovered plaintexts or keys.'};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');fs.writeFileSync(path.join(out,'witnesses.json'),JSON.stringify(witnesses,null,2)+'\n');console.log(JSON.stringify({...result,fileHashes:undefined},null,2));
module.exports={count};
