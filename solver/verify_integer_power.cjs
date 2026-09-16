/* Independent integer-power exclusion verifier: binary-search roots and a
 * digit-count of canonical 7-bit byte integers. Imports no search routines.
 * node solver/verify_integer_power.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','integer_power_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(sha(inputBytes),spec.inputSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','integer_power_constraints.cjs'))),spec.sourceSHA256);
function rootByBisection(n,e) {
  assert(n>=0n&&Number.isInteger(e)&&e>=2);
  let lo=0n,hi=1n<<BigInt(Math.ceil(n.toString(2).length/e)),E=BigInt(e);
  while(hi-lo>1n){const m=(lo+hi)/2n;if(m**E<=n)lo=m;else hi=m;}
  assert(lo**E<=n&&(lo+1n)**E>n);return lo;
}
function count(n) {
  if(n<0n)return 0n;
  let h=n.toString(16);if(h.length%2)h='0'+h;
  const b=Buffer.from(h,'hex');let total=0n;
  for(let i=0;i<b.length;i++) {
    total+=BigInt(Math.min(b[i],128))*128n**BigInt(b.length-i-1);
    if(b[i]>127)return total;
  }
  return total+1n;
}
let rootControls=0,countControls=0,widthControls=0;
for(let e=2;e<=12;e++)for(let n=0n;n<2000n;n++) {
  let r=0n;while((r+1n)**BigInt(e)<=n)r++;assert.equal(rootByBisection(n,e),r);rootControls++;
}
for(const e of [2,3,5,7,17,41,301,1892])for(let i=1;i<=10;i++) {
  const r=BigInt('0x'+sha(`independent-power/${e}/${i}`).slice(0,Math.max(1,Math.floor(300/e))))+2n,p=r**BigInt(e);
  assert.equal(rootByBisection(p,e),r);assert.equal(rootByBisection(p-1n,e),r-1n);assert.equal(rootByBisection(p+1n,e),r);rootControls+=3;
}
let expected=0n;
for(let n=0;n<65536;n++) {if(n%256<128&&Math.floor(n/256)<128)expected++;assert.equal(count(BigInt(n)),expected);countControls++;}
for(let width=1;width<=300;width++){assert.equal(count(256n**BigInt(width)-1n),128n**BigInt(width));widthControls++;}
console.log(JSON.stringify({controls:{rootControls,countControls,widthControls}}));
const fileHashes={},ids=new Set();let cases=0,nodes=0,certificates=0;
for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of 'abcdefghi') {
  const source=reverse?[...input[field]].reverse().join(''):input[field];
  const file=`${field}-${reverse?'reverse':'original'}-${alias}.json`,b=fs.readFileSync(path.join(out,file)),records=JSON.parse(b);fileHashes[file]=sha(b);
  const low=BigInt([...source].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*10n**BigInt(source.length-i-1)]:[]);
  const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  assert(low>1n);const maxExponent=(low+tails[0]).toString(2).length-1;
  assert.equal(records.length,maxExponent-1);
  for(const r of records) {
    assert.equal(r.field,field);assert.equal(r.reverse,reverse);assert.equal(r.alias,alias);assert.equal(r.ambiguous,weights.length);
    assert(Number.isInteger(r.e)&&r.e>=2&&r.e<=maxExponent);assert(r.complete&&r.pending.length===0);assert.equal(r.hits.length,0);
    const id=[field,reverse,alias,r.e].join('/');assert(!ids.has(id));ids.add(id);
    const prefixes=[...r.certificates].sort();for(let i=1;i<prefixes.length;i++)assert(!prefixes[i].startsWith(prefixes[i-1]));
    let coverage=0n;
    for(const m of prefixes) {
      assert.match(m,/^[01]*$/);assert(m.length<=weights.length);
      let lo=low;for(let i=0;i<m.length;i++)if(m[i]==='1')lo+=weights[i];const hi=lo+tails[m.length];
      const lr=rootByBisection(lo,r.e),lower=lr**BigInt(r.e)===lo?lr:lr+1n,upper=rootByBisection(hi,r.e);
      assert(lower>upper||count(upper)-count(lower-1n)===0n,`${id}/${m}`);
      coverage+=1n<<BigInt(weights.length-m.length);certificates++;
    }
    assert.equal(coverage,1n<<BigInt(weights.length));cases++;nodes+=r.nodes;
  }
  console.log(JSON.stringify({verified:file,cases,certificates}));
}
assert.equal(cases,39438);assert.equal(cases,saved.cases);assert.equal(nodes,saved.nodes);assert.equal(certificates,saved.certificates);
assert.equal(saved.partial.length,0);assert.equal(saved.candidates,0);assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))),[]);
assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'aes.json'))),{passwords:[],attempts:0,padding:[]});
const result={cases,nodes,certificates,allComplete:true,allExclusionsMatched:true,candidates:0,aesAttempts:0,
  controls:{rootControls,countControls,widthControls},fileHashes,verifierSHA256:sha(fs.readFileSync(__filename)),
  conclusion:'No N=P**e with integer e>=2 and canonical 7-bit P in this whole-decimal, single-zero-alias, two-direction model. Does not address modular powers, split fields, transpositions or different encodings.'};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({...result,fileHashes:undefined},null,2));
