/* Exhaustive decimal periodic keys of lengths 1..6 on the original FAED.
 * Unlike a password dictionary, every decimal key in this length bound is used.
 * All g=0/7 assignments are covered by interval exclusion. Two cipher signs
 * and two complete source orientations. Addition duplicates subtraction over
 * the full key space and is deliberately omitted.
 * node solver/decimal_short_key.cjs [maximum-period, default 6]
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const reference=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','decimal_keystream_2026-09-15','short_keys');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const powers=[1n];for(let i=1;i<=600;i++)powers.push(powers[i-1]*10n);
const mod=n=>((n%10)+10)%10;
const bytesOf=n=>Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length/2)*2,'0'),'hex');
function prepare(source,period,mode) {
  const minimum=Array.from({length:period},()=>Array(10).fill(0n));
  const width=Array.from({length:period},()=>Array(10).fill(0n));
  const ambiguous=[];
  [...source].forEach((c,i)=>{
    const rank=i%period,power=powers[source.length-i-1],weights=[];
    for(let k=0;k<10;k++) {
      const values=(c==='g'?[0,7]:[c.charCodeAt(0)-96]).map(v=>mode==='subtract'?mod(v-k):mod(k-v)).sort((a,b)=>a-b);
      minimum[rank][k]+=BigInt(values[0])*power;
      const delta=BigInt(values.at(-1)-values[0])*power;width[rank][k]+=delta;weights.push(delta);
    }
    if(c==='g')ambiguous.push({rank,weights});
  });
  return {minimum,width,ambiguous,period};
}
function solveKey(model,key,maxNodes=200000) {
  let lo=0n,span=0n;
  for(let i=0;i<key.length;i++){lo+=model.minimum[i][key[i]];span+=model.width[i][key[i]];}
  const hits=[];let nodes=0,complete=true;
  function visit(i,a,w) {
    if(nodes>=maxNodes){complete=false;return;}
    nodes++;
    if(nextAscii(a,true)>a+w)return;
    if(i===model.ambiguous.length){hits.push({decimal:a.toString(),hex:bytesOf(a).toString('hex')});return;}
    const d=model.ambiguous[i],weight=d.weights[key[d.rank]];
    visit(i+1,a,w-weight);if(complete)visit(i+1,a+weight,w-weight);
  }
  visit(0,lo,span);return {nodes,complete,hits};
}
function controls() {
  let matches=0,recovered=0;
  for(const mode of ['subtract','beaufort'])for(let period=1;period<=6;period++) {
    const model=prepare(input.faed,period,mode);
    for(let n=0;n<20;n++) {
      const key=Array.from({length:period},(_,i)=>(n*7+i*3)%10);
      const actual=solveKey(model,key),expected=reference.search(reference.domains(input.faed,key,mode));
      assert(actual.complete&&expected.complete);assert.deepEqual(actual.hits.map(h=>h.hex).sort(),expected.hits.map(h=>h.hex).sort());matches++;
    }
    const key=Array.from({length:period},(_,i)=>(i*3+1)%10),plain=input.phase32_text.slice(0,237);
    const source=reference.encrypt(plain,key,mode),r=solveKey(prepare(source,period,mode),key);
    assert(r.complete&&r.hits.some(x=>x.hex===Buffer.from(plain).toString('hex')));recovered++;
  }
  return {referenceComparisons:matches,plantedRecoveries:recovered};
}
function main() {
  const maxPeriod=Number(process.argv[2]||6);assert(Number.isInteger(maxPeriod)&&maxPeriod>=1&&maxPeriod<=6);
  const checked=controls();fs.mkdirSync(out,{recursive:true});
  const summary={hypothesis:'P digits = (C-K) or (K-C) mod10, a1z26 cipher digits with every g independently 0 or 7. Whole P decimal integer to bytes all <=127.',
    scope:'FAED only; both complete symbol orientations; ALL keys of lengths 1..maximum, including leading-zero keys. Longer keys and other transformations are not covered.',
    maximumPeriod:maxPeriod,maxNodesPerKey:200000,controls:checked,sourceSHA256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
    fieldSHA256:crypto.createHash('sha256').update(input.faed).digest('hex'),groups:[],totalKeys:0,totalNodes:0,hits:[],partial:[]};
  for(const reverse of [false,true])for(const mode of ['subtract','beaufort'])for(let period=1;period<=maxPeriod;period++) {
    const source=reverse?[...input.faed].reverse().join(''):input.faed,model=prepare(source,period,mode),key=Array(period).fill(0),limit=10**period;
    const counts=Buffer.alloc(limit*4);let nodes=0;const start=Date.now();
    for(let n=0;n<limit;n++) {
      const r=solveKey(model,key);counts.writeUInt32LE(r.nodes,n*4);nodes+=r.nodes;
      if(!r.complete)summary.partial.push({reverse,mode,period,key:key.join(''),nodes:r.nodes});
      for(const h of r.hits)summary.hits.push({reverse,mode,period,key:key.join(''),...h});
      for(let i=period-1;i>=0;i--){key[i]++;if(key[i]<10)break;key[i]=0;}
    }
    const name=`${reverse?'reverse':'forward'}-${mode}-${period}.nodes`;
    fs.writeFileSync(path.join(out,name),counts);
    const group={reverse,mode,period,keys:limit,nodes,elapsedMs:Date.now()-start,nodeCountsFile:name,nodeCountsSHA256:crypto.createHash('sha256').update(counts).digest('hex')};
    summary.groups.push(group);summary.totalKeys+=limit;summary.totalNodes+=nodes;
    fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(group));
  }
  console.log(JSON.stringify({keys:summary.totalKeys,nodes:summary.totalNodes,hits:summary.hits.length,partial:summary.partial.length,controls:checked}));
}
if(require.main===module)main();
module.exports={prepare,solveKey};
