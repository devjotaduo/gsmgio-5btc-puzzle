/* Independent certificate audit. No searcher or cipher helper imported.
 * Counts allowed integers rather than looking for the next allowed integer.
 * node solver/verify_feedback_decimal.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','feedback_decimal_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
assert.equal(sha(inputBytes),spec.inputSHA256);
assert.equal(sha(fs.readFileSync(path.join(root,'solver','feedback_decimal_constraints.cjs'))),spec.sourceSHA256);
const ten=[1n],p128=[1n];for(let i=1;i<=600;i++){ten.push(ten[i-1]*10n);p128.push(p128[i-1]*128n);}
function count(n) {
  if(n<0n)return 0n;
  let hex=n.toString(16);if(hex.length%2)hex='0'+hex;
  const b=Buffer.from(hex,'hex');let total=0n;
  for(let i=0;i<b.length;i++){total+=BigInt(Math.min(128,b[i]))*p128[b.length-i-1];if(b[i]>=128)return total;}
  return total+1n;
}
let integerCount=0n;for(let n=0;n<65536;n++){if((n&255)<128&&(n>>8)<128)integerCount++;assert.equal(count(BigInt(n)),integerCount);}
for(let i=1;i<=300;i++)assert.equal(count(256n**BigInt(i)-1n),128n**BigInt(i));
const mod=n=>(n+20)%10;
function step(c,k,mode) {return mod(mode==='subtract'?c-k:mode==='add'?c+k:k-c);}
function keyStream(seed,n,skip) {
  const queue=seed.slice(),result=[];
  for(let i=0;i<n+skip;i++) {
    const next=(queue[0]+queue[1])%10,front=queue.shift();queue.push(next);
    if(i>=skip)result.push(front);
  }
  return result;
}
assert.equal(keyStream([2,3,4,5,2],35,0).join(''),'23452579772664982037023072537978066');
// Reconstruct every seed from its recorded source. Matrix list values are
// cross-checked against the earlier serialized, separately audited experiment.
const earlier=JSON.parse(fs.readFileSync(path.join(root,'_work','decimal_keystream_2026-09-15','carry_color','spec.json')));
assert.deepEqual(spec.lists,earlier.lists);
const lists=new Map(spec.lists.map(l=>[l.name,l.values])),seeds=new Map();
let matrixSeeds=0,dbbiSeeds=0;
const provenanceIds=new Set();
for(const seed of spec.seeds) {
  assert(!seeds.has(seed.id));assert.equal(seed.id,seed.values.join(''));assert(seed.values.length>=2);
  const fields=new Set();
  for(const p of seed.provenance) {
    const pid=JSON.stringify(p);assert(!provenanceIds.has(pid));provenanceIds.add(pid);
    let v;
    if(p.field==='dbbi') {
      assert.match(p.mask,/^[01]{10}$/);let j=0;
      v=[...input.dbbi].map(c=>c==='g'?(p.mask[j++]==='1'?7:0):c.charCodeAt(0)-96);fields.add('faed');
    } else {
      const a=lists.get(p.list);assert(a);
      assert(['residue10','decimal-digits'].includes(p.representation));
      v=p.representation==='residue10'?a.map(x=>x%10):[...a.join('')].map(Number);fields.add('dbbi');fields.add('faed');
    }
    assert.equal(typeof p.reverse,'boolean');if(p.reverse)v.reverse();assert.deepEqual(v,seed.values);
  }
  assert.deepEqual([...fields].sort(),seed.fields.slice().sort());
  if(fields.has('dbbi'))matrixSeeds++;else dbbiSeeds++;
  seeds.set(seed.id,seed);
}
assert.equal(provenanceIds.size,43*2*2+1024*2);
const file=fs.readFileSync(path.join(out,'cases.jsonl')),records=file.toString('utf8').trim().split('\n').map(JSON.parse);
const seen=new Set(),byKind={};let certificates=0,nodes=0;
for(const r of records) {
  assert(['dbbi','faed'].includes(r.field)&&typeof r.reverse==='boolean');
  assert(spec.kinds.includes(r.kind)&&spec.modes.includes(r.mode));
  const seed=seeds.get(r.seed);assert(seed&&seed.fields.includes(r.field));
  const id=[r.field,r.reverse,r.seed,r.kind,r.mode].join('/');assert(!seen.has(id));seen.add(id);
  assert(r.complete&&r.pending.length===0&&r.hits.length===0);
  const s=r.reverse?[...input[r.field]].reverse().join(''):input[r.field],n=s.length,ambiguous=[...s].filter(c=>c==='g').length;
  assert.equal(ambiguous,r.ambiguous);
  const sorted=r.certificates.slice().sort();
  for(let i=1;i<sorted.length;i++)assert(!sorted[i].startsWith(sorted[i-1]));
  let low,weights,tails;
  if(r.kind.startsWith('chain-')) {
    const key=keyStream(seed.values,n,r.kind==='chain-after-seed'?seed.values.length:0);
    const ds=[...s].map((c,i)=>(c==='g'?[0,7]:[c.charCodeAt(0)-96]).map(v=>step(v,key[i],r.mode)).sort((a,b)=>a-b));
    low=BigInt(ds.map(x=>x[0]).join(''));weights=ds.flatMap((x,i)=>x.length===2?[BigInt(x[1]-x[0])*ten[n-i-1]]:[]);
    tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  }
  let coverage=0n;
  for(const mask of sorted) {
    assert.match(mask,/^[01]*$/);assert(mask.length<=ambiguous);
    let lo,hi;
    if(r.kind.startsWith('chain-')) {
      lo=low;for(let i=0;i<mask.length;i++)if(mask[i]==='1')lo+=weights[i];hi=lo+tails[mask.length];
    } else {
      const queue=seed.values.slice();let used=0,i=0,prefix='';
      while(i<n) {
        if(s[i]==='g'&&used===mask.length)break;
        const c=s[i]==='g'?(mask[used++]==='1'?7:0):s.charCodeAt(i)-96;
        const k=queue.shift(),p=step(c,k,r.mode);prefix+=p;
        queue.push(r.kind==='plaintext-feedback'?p:c);i++;
      }
      assert.equal(used,mask.length);const p=BigInt(prefix||'0');lo=p*ten[n-i];hi=lo+ten[n-i]-1n;
    }
    assert.equal(count(hi)-count(lo-1n),0n,`${id}/${mask}`);
    coverage+=1n<<BigInt(ambiguous-mask.length);certificates++;
  }
  assert.equal(coverage,1n<<BigInt(ambiguous));
  nodes+=r.nodes;byKind[r.kind]??={cases:0,certificates:0};byKind[r.kind].cases++;byKind[r.kind].certificates+=sorted.length;
}
const expectedCases=spec.seeds.reduce((n,s)=>n+s.fields.length*2*spec.kinds.length*spec.modes.length,0);
assert.equal(seen.size,expectedCases);assert.equal(seen.size,saved.cases);assert.equal(nodes,saved.nodes);assert.equal(certificates,saved.certificates);
assert.equal(saved.candidates,0);assert.equal(saved.partial.length,0);
assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))),[]);
assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'aes.json'))),{passwords:[],attempts:0,padding:[]});
const result={cases:seen.size,certificates,nodes,allExcluded:true,allExpectedModelsPresent:true,matrixSeeds,dbbiSeeds,byKind,
  controls:{integerCounts:65536,largeWidths:300,acaNumericStream:true},caveat:'Independently verifies arithmetic, seed serialization and certificates. Matrix-list definitions are shared with the previously serialized experiment.',
  casesSHA256:sha(file),verifierSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
