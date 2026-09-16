/* Exhaustive symbol substitution before decimal-integer decoding.
 * node solver/substituted_decimal_constraints.cjs [g|all|another a..i]
 * Every permutation a..i -> 1..9; the selected symbol may independently
 * encode zero OR its assigned nonzero digit at each occurrence.
 * No transposition except full reversal; all decoded bytes must be <128.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..');
const out=path.join(root,'_work','substituted_decimal_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'));
const input=JSON.parse(inputBytes),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const powers=[1n];for(let i=1;i<=600;i++)powers.push(powers[i-1]*10n);
function bytesOf(n){let h=n.toString(16);return Buffer.from(h.length%2?'0'+h:h,'hex');}
function prepare(source,alias) {
  assert.match(source,/^[a-i]+$/);assert.match(alias,/^[a-i]$/);
  const coefficients=Array(9).fill(0n),positions=[];
  [...source].forEach((c,i)=>{const p=powers[source.length-i-1];if(c===alias)positions.push(p);else coefficients[c.charCodeAt(0)-97]+=p;});
  const weights=Array.from({length:10},(_,digit)=>positions.map(p=>p*BigInt(digit)));
  const tails=weights.map(ws=>{const t=Array(ws.length+1).fill(0n);for(let i=ws.length-1;i>=0;i--)t[i]=t[i+1]+ws[i];return t;});
  return {coefficients,weights,tails,aliasIndex:alias.charCodeAt(0)-97};
}
function search(model,map,maxNodes=200000) {
  const digit=map[model.aliasIndex],weights=model.weights[digit],tails=model.tails[digit];
  let low=0n;for(let i=0;i<9;i++)low+=model.coefficients[i]*BigInt(map[i]);
  let nodes=0,complete=true;const hits=[];
  function visit(i,n) {
    if(nodes>=maxNodes){complete=false;return;}nodes++;
    if(nextAscii(n,true)>n+tails[i])return;
    if(i===weights.length){hits.push({decimal:n.toString(),hex:bytesOf(n).toString('hex')});return;}
    visit(i+1,n);if(complete)visit(i+1,n+weights[i]);
  }
  visit(0,low);return {nodes,complete,hits};
}
function eachPermutation(callback) {
  const a=Array.from({length:9},(_,i)=>i+1),c=Array(9).fill(0);let rank=0;callback(a,rank++);
  for(let i=0;i<9;){if(c[i]<i){const j=i%2?c[i]:0;[a[j],a[i]]=[a[i],a[j]];callback(a,rank++);c[i]++;i=0;}else{c[i]=0;i++;}}
  assert.equal(rank,362880);
}
function encode(plain,map,alias) {
  const reverse=new Map(map.map((v,i)=>[v,String.fromCharCode(97+i)]));
  return [...BigInt('0x'+Buffer.from(plain).toString('hex')).toString()].map(v=>Number(v)===0?alias:reverse.get(Number(v))).join('');
}
function controls() {
  let brute=0,planted=0;
  const maps=[[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]];
  for(const alias of 'abcdefghi')for(const map of maps) {
    for(const s of [alias.repeat(5),`abc${alias}${alias}fg`,`i${alias}a${alias}b`]) {
      const expected=[],count=[...s].filter(c=>c===alias).length;
      for(let mask=0;mask<2**count;mask++) {
        let bit=0;const n=BigInt([...s].map(c=>c===alias?(((mask>>bit++)&1)?map[c.charCodeAt(0)-97]:0):map[c.charCodeAt(0)-97]).join(''));
        if([...bytesOf(n)].every(b=>b<128))expected.push(n.toString());
      }
      const result=search(prepare(s,alias),map);assert(result.complete);assert.deepEqual(result.hits.map(x=>x.decimal).sort(),expected.sort());brute++;
    }
    const plain=input.phase32_text.slice(0,90),source=encode(plain,map,alias),result=search(prepare(source,alias),map);
    assert(result.complete&&result.hits.some(h=>h.hex===Buffer.from(plain).toString('hex')));planted++;
  }
  const seen=new Set();eachPermutation(a=>{assert.deepEqual([...a].sort(),[1,2,3,4,5,6,7,8,9]);seen.add(a.join(''));});assert.equal(seen.size,362880);
  return {bruteForceCases:brute,plantedRecoveries:planted,distinctPermutationControl:seen.size};
}
function testPasswords(candidates) {
  const passwords=new Map(),padding=[];
  for(const c of candidates) {
    const preimage=Buffer.from(c.hex,'hex');
    for(const form of ['direct','sha256-hex']) {
      const password=form==='direct'?preimage:Buffer.from(sha(preimage)),id=password.toString('hex');
      if(!passwords.has(id))passwords.set(id,{form,preimageHex:c.hex,passwordHex:id,source:{field:c.field,reverse:c.reverse,alias:c.alias,mapping:c.mapping}});
    }
  }
  const raw=Buffer.from(input.phase32_control_b64,'base64'),control={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
  assert.equal(sha(open(Buffer.from(input.phase32_control_password),control,'sha256')),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  let attempts=0;
  for(const p of passwords.values())for(const [name,blob]of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    attempts++;const plain=open(Buffer.from(p.passwordHex,'hex'),blob,digest);if(!plain)continue;
    padding.push({passwordHex:p.passwordHex,blob:name,kdf:digest,plaintextHex:plain.toString('hex'),printable:[...plain].filter(b=>(b>=32&&b<=126)||[9,10,13].includes(b)).length/plain.length});
  }
  return {passwords:[...passwords.values()],attempts,padding};
}
function main() {
  const selected=process.argv[2]||'g';assert(selected==='all'||/^[a-i]$/.test(selected));
  const aliases=selected==='all'?[...'abcdefghi']:[selected],checked=controls();fs.mkdirSync(out,{recursive:true});
  console.log(JSON.stringify({controls:checked}));
  const spec={hypothesis:'Every bijection a..i to 1..9, with the selected symbol independently 0 or its assigned digit; decimal integer to minimal big-endian bytes all below 128. Complete original/reversed DBBI and FAED only.',
    scope:'No other substitutions, byte encodings, interleaving, removed/inserted symbols, arithmetic keys, or transpositions are claimed.',sourceSHA256:sha(fs.readFileSync(__filename)),inputSHA256:sha(inputBytes),controls:checked};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  for(const alias of aliases) {
    const filename=path.join(out,`alias-${alias}.json`);
    if(fs.existsSync(filename)) {
      const old=JSON.parse(fs.readFileSync(filename));
      if(old.sourceSHA256===spec.sourceSHA256&&old.inputSHA256===spec.inputSHA256&&old.groups.length===4&&old.partial.length===0){console.log(JSON.stringify({alias,reusedCompleted:true,cases:old.cases,hits:old.candidates.length}));continue;}
    }
    const summary={alias,...spec,groups:[],cases:0,nodes:0,candidates:[],partial:[]};
    for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
      const source=reverse?[...input[field]].reverse().join(''):input[field],model=prepare(source,alias),counts=Buffer.alloc(362880*4);
      const start=Date.now();let nodes=0,hits=0;
      eachPermutation((map,rank)=>{
        const r=search(model,map);counts.writeUInt32LE(r.nodes,rank*4);nodes+=r.nodes;
        if(!r.complete)summary.partial.push({field,reverse,mapping:map.join(''),rank,nodes:r.nodes});
        for(const h of r.hits){hits++;summary.candidates.push({alias,field,reverse,mapping:map.join(''),rank,...h});}
      });
      const countFile=`${alias}-${field}-${reverse?'reverse':'forward'}.nodes`;
      fs.writeFileSync(path.join(out,countFile),counts);
      const group={field,reverse,cases:362880,nodes,hits,elapsedMs:Date.now()-start,countFile,countSHA256:sha(counts)};
      summary.groups.push(group);summary.cases+=362880;summary.nodes+=nodes;fs.writeFileSync(filename,JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({alias,...group,partial:summary.partial.length}));
    }
    const aes=testPasswords(summary.candidates);fs.writeFileSync(path.join(out,`aes-${alias}.json`),JSON.stringify(aes,null,2)+'\n');
    summary.aes={passwords:aes.passwords.length,attempts:aes.attempts,padding:aes.padding.length};fs.writeFileSync(filename,JSON.stringify(summary,null,2)+'\n');
    console.log(JSON.stringify({alias,cases:summary.cases,nodes:summary.nodes,candidates:summary.candidates.length,partial:summary.partial.length,aes:summary.aes}));
  }
}
if(require.main===module)main();module.exports={prepare,search,eachPermutation,encode};
