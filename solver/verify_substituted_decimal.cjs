/* Independent exhaustive verifier: counts seven-bit integers in intervals.
 * It imports neither the searcher nor nextAscii. Permutations use lexicographic
 * recursion, rather than Heap's algorithm. node ... [g|all|another a..i]
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_decimal_2026-09-15');
const raw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(raw);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const p128=[1n];for(let i=1;i<=600;i++)p128.push(p128[i-1]*128n);
function countAllowed(n) {
  if(n<0n)return 0n;
  let hex=n.toString(16);if(hex.length%2)hex='0'+hex;
  const bs=Buffer.from(hex,'hex');let total=0n;
  for(let i=0;i<bs.length;i++) {
    const ways=p128[bs.length-i-1];
    if(bs[i]>=128)return total+128n*ways;
    total+=BigInt(bs[i])*ways;
  }
  return total+1n;
}
function allMaps(fn,prefix=[],used=0) {
  if(prefix.length===9){fn(prefix);return;}
  for(let n=1;n<=9;n++)if(!(used&(1<<n))){prefix.push(n);allMaps(fn,prefix,used|(1<<n));prefix.pop();}
}
function model(source,alias) {
  const coefficients=[...'abcdefghi'].map(c=>c===alias?0n:BigInt([...source].map(x=>x===c?'1':'0').join('')));
  const places=[];for(let i=0;i<source.length;i++)if(source[i]===alias)places.push(10n**BigInt(source.length-i-1));
  const scaled=Array.from({length:10},(_,n)=>places.map(p=>p*BigInt(n)));
  return {coefficients,scaled,alias:alias.charCodeAt(0)-97};
}
function verifyMap(m,map,expected) {
  const increments=m.scaled[map[m.alias]];
  const lower=m.coefficients.reduce((s,v,i)=>s+v*BigInt(map[i]),0n),width=increments.reduce((s,v)=>s+v,0n);
  const found=[];let nodes=0;
  function visit(i,lo,span) {
    nodes++;
    if(countAllowed(lo+span)===countAllowed(lo-1n))return;
    if(i===increments.length){assert.equal(span,0n);found.push(lo.toString());return;}
    const remaining=span-increments[i];
    // Visit high branch first, opposite to the searcher's order.
    visit(i+1,lo+increments[i],remaining);visit(i+1,lo,remaining);
  }
  visit(0,lower,width);
  assert.deepEqual(found.sort(),expected.sort());return {nodes,hits:found.length};
}
let running=0n;for(let n=0;n<65536;n++){if((n&255)<128&&(n>>8)<128)running++;assert.equal(countAllowed(BigInt(n)),running);}
for(let k=1;k<=300;k++)assert.equal(countAllowed(256n**BigInt(k)-1n),128n**BigInt(k));
const selected=process.argv[2]||'g';assert(selected==='all'||/^[a-i]$/.test(selected));const aliases=selected==='all'?[...'abcdefghi']:[selected];
const result={controls:{smallIntegers:65536,largeBoundaries:300},aliases:[],cases:0,nodes:0,hits:0,verifierSHA256:sha(fs.readFileSync(__filename))};
for(const alias of aliases) {
  const saved=JSON.parse(fs.readFileSync(path.join(out,`alias-${alias}.json`)));
  assert.equal(saved.inputSHA256,sha(raw));assert.equal(saved.sourceSHA256,sha(fs.readFileSync(path.join(root,'solver','substituted_decimal_constraints.cjs'))));
  assert.equal(saved.groups.length,4);assert.equal(saved.partial.length,0);
  const expected=new Map();for(const c of saved.candidates) {
    const key=[c.field,c.reverse,c.mapping].join('/');if(!expected.has(key))expected.set(key,[]);expected.get(key).push(c.decimal);
    const bytes=Buffer.from(c.hex,'hex');assert.equal(BigInt('0x'+bytes.toString('hex')).toString(),c.decimal);assert([...bytes].every(b=>b<128));
  }
  const groups=[];
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    const g=saved.groups.find(x=>x.field===field&&x.reverse===reverse);assert(g);
    const bytes=fs.readFileSync(path.join(out,g.countFile));assert.equal(sha(bytes),g.countSHA256);assert.equal(bytes.length,362880*4);
    let recorded=0;for(let i=0;i<bytes.length;i+=4)recorded+=bytes.readUInt32LE(i);assert.equal(recorded,g.nodes);
    const source=reverse?[...input[field]].reverse().join(''):input[field],m=model(source,alias);
    let cases=0,nodes=0,hits=0;const started=Date.now();
    allMaps(map=>{const r=verifyMap(m,map,expected.get([field,reverse,map.join('')].join('/'))||[]);cases++;nodes+=r.nodes;hits+=r.hits;});
    assert.equal(cases,g.cases);assert.equal(nodes,g.nodes);assert.equal(hits,g.hits);
    const group={field,reverse,cases,nodes,hits,elapsedMs:Date.now()-started};groups.push(group);result.cases+=cases;result.nodes+=nodes;result.hits+=hits;
    console.log(JSON.stringify({alias,...group}));
  }
  result.aliases.push({alias,groups});fs.writeFileSync(path.join(out,`verification-${selected}.json`),JSON.stringify({...result,complete:false},null,2)+'\n');
}
result.complete=true;fs.writeFileSync(path.join(out,`verification-${selected}.json`),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({complete:true,cases:result.cases,nodes:result.nodes,hits:result.hits}));
