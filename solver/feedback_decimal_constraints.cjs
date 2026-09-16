/* Conditional decimal models: chain-added key and plain/cipher autokey.
 * Every g independently means 0 or 7. The resulting whole decimal integer
 * must have minimal big-endian bytes <128. This is NOT a confirmed recipe.
 * node solver/feedback_decimal_constraints.cjs [controls|run]
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {domains,search:fixedSearch,baseLists,open}=require('./decimal_keystream_constraints.cjs');
const {colorLists}=require('./decimal_carry_color.cjs');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','feedback_decimal_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),data=JSON.parse(inputBytes);
const sha=x=>crypto.createHash('sha256').update(x).digest();
const mod=x=>((x%10)+10)%10;
const bytes=n=>Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length/2)*2,'0'),'hex');
const pow10=[1n];for(let i=1;i<=600;i++)pow10.push(pow10[i-1]*10n);
const modes=['subtract','add','beaufort'],kinds=['chain-including-seed','chain-after-seed','plaintext-feedback','ciphertext-feedback'];
const decryptDigit=(c,k,mode)=>mod(mode==='subtract'?c-k:mode==='add'?c+k:k-c);
const encryptDigit=(p,k,mode)=>mod(mode==='subtract'?p+k:mode==='add'?p-k:k-p);

function chain(seed,n,skip=0) {
  assert(seed.length>=2&&seed.every(x=>Number.isInteger(x)&&x>=0&&x<=9));
  const s=seed.slice(),L=seed.length;
  while(s.length<n+skip)s.push((s[s.length-L]+s[s.length-L+1])%10);
  return s.slice(skip,skip+n);
}
function derive(cipher,seed,kind,mode) {
  const p=[],key=kind.startsWith('chain-')?chain(seed,cipher.length,kind==='chain-after-seed'?seed.length:0):null;
  for(let i=0;i<cipher.length;i++) {
    const k=key?key[i]:i<seed.length?seed[i]:(kind==='plaintext-feedback'?p:cipher)[i-seed.length];
    p.push(decryptDigit(cipher[i],k,mode));
  }
  return p;
}
function feedbackSearch(source,seed,kind,mode,{maxNodes=200000,maxMs=1000}={}) {
  assert.match(source,/^[a-i]+$/);assert(source.length<=600);
  assert(seed.length>=2&&seed.every(x=>Number.isInteger(x)&&x>=0&&x<=9));
  assert(['plaintext-feedback','ciphertext-feedback'].includes(kind)&&modes.includes(mode));
  const ambiguous=[...source].filter(c=>c==='g').length,c=[],p=[],certificates=[],pending=[],hits=[];
  const start=Date.now();let nodes=0,covered=0n;
  function append(n,prefix) {
    const i=c.length,k=i<seed.length?seed[i]:(kind==='plaintext-feedback'?p:c)[i-seed.length];
    const d=decryptDigit(n,k,mode);c.push(n);p.push(d);return prefix*10n+BigInt(d);
  }
  function visit(prefix,mask) {
    if(nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}
    nodes++;
    const before=c.length;
    while(c.length<source.length&&source[c.length]!=='g')prefix=append(source.charCodeAt(c.length)-96,prefix);
    const places=pow10[source.length-c.length],lo=prefix*places,hi=lo+places-1n;
    if(nextAscii(lo,true)>hi) {
      certificates.push(mask);covered+=1n<<BigInt(ambiguous-mask.length);
    } else if(c.length===source.length) {
      const b=bytes(prefix);assert([...b].every(x=>x<128));
      hits.push({mask,decimal:prefix.toString(),hex:b.toString('hex')});
    } else {
      const at=c.length;
      for(const [bit,n] of [['0',0],['1',7]]) {
        const next=append(n,prefix);visit(next,mask+bit);c.length=at;p.length=at;
      }
    }
    c.length=before;p.length=before;
  }
  visit(0n,'');
  const unvisited=pending.reduce((sum,m)=>sum+(1n<<BigInt(ambiguous-m.length)),0n);
  assert.equal(covered+BigInt(hits.length)+unvisited,1n<<BigInt(ambiguous));
  return {ambiguous,nodes,complete:pending.length===0,certificates,hits,pending,elapsedMs:Date.now()-start};
}
function runCase(source,seed,kind,mode,limits) {
  if(kind.startsWith('chain-'))return fixedSearch(domains(source,chain(seed,source.length,kind==='chain-after-seed'?seed.length:0),mode),limits);
  return feedbackSearch(source,seed,kind,mode,limits);
}
function makeSeeds() {
  const lists=[...baseLists(),...colorLists().lists],seeds=new Map();
  function add(values,provenance,fields) {
    if(values.length<2)return;
    const id=values.join('');
    if(!seeds.has(id))seeds.set(id,{id,values,provenance:[],fields:[]});
    const item=seeds.get(id);item.provenance.push(provenance);item.fields=[...new Set([...item.fields,...fields])];
  }
  for(const list of lists)for(const representation of ['residue10','decimal-digits'])for(const reverse of [false,true]) {
    const v=representation==='residue10'?list.values.map(mod):[...list.values.join('')].map(Number);
    add(reverse?v.reverse():v,{list:list.name,representation,reverse},['dbbi','faed']);
  }
  const count=[...data.dbbi].filter(c=>c==='g').length;
  assert.equal(count,10);
  for(let i=0;i<2**count;i++) {
    const mask=i.toString(2).padStart(count,'0');let j=0;
    const v=[...data.dbbi].map(c=>c==='g'?(mask[j++]==='1'?7:0):c.charCodeAt(0)-96);
    for(const reverse of [false,true])add(reverse?[...v].reverse():v,{field:'dbbi',mask,reverse},['faed']);
  }
  return {lists,seeds:[...seeds.values()]};
}
function encode(text,seed,kind,mode) {
  const plain=[...BigInt('0x'+Buffer.from(text).toString('hex')).toString()].map(Number),cipher=[];
  const key=kind.startsWith('chain-')?chain(seed,plain.length,kind==='chain-after-seed'?seed.length:0):null;
  for(let i=0;i<plain.length;i++) {
    const k=key?key[i]:i<seed.length?seed[i]:(kind==='plaintext-feedback'?plain:cipher)[i-seed.length];
    cipher.push(encryptDigit(plain[i],k,mode));
  }
  assert.deepEqual(derive(cipher,seed,kind,mode),plain);
  return cipher.map(c=>String.fromCharCode(96+(c||7))).join('');
}
function controls() {
  const aca='23452579772664982037023072537978066';
  assert.equal(chain([2,3,4,5,2],aca.length).join(''),aca);
  let planted=0,bruteForce=0;
  for(const seed of [[2,3,4,5,2],[6,0,8,7,6,6,5,4,9,9,7,8,7,9],[0,9]])for(const kind of kinds)for(const mode of modes) {
    for(const text of ['matrixsumlist','thispassword',data.phase32_text.slice(0,90)]) {
      const source=encode(text,seed,kind,mode),r=runCase(source,seed,kind,mode,{maxMs:5000,maxNodes:1000000});
      assert(r.complete);assert(r.hits.some(h=>h.hex===Buffer.from(text).toString('hex')));planted++;
    }
    for(const source of ['ggbg','abcgg','gggggg','faedgg']) {
      const count=[...source].filter(c=>c==='g').length,expected=[];
      for(let i=0;i<2**count;i++) {
        let j=0;const cipher=[...source].map(c=>c==='g'?((i>>j++)&1?7:0):c.charCodeAt(0)-96);
        const n=BigInt(derive(cipher,seed,kind,mode).join(''));
        if([...bytes(n)].every(b=>b<128))expected.push(n.toString());
      }
      const r=runCase(source,seed,kind,mode);assert(r.complete);assert.deepEqual(r.hits.map(h=>h.decimal).sort(),expected.sort());bruteForce++;
    }
  }
  const raw=Buffer.from(data.phase32_control_b64,'base64'),control={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
  const body=open(Buffer.from(data.phase32_control_password),control,'sha256');
  assert.equal(sha(body).toString('hex'),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  return {acaNumericStream:aca,planted,bruteForce,phase32SHA256:sha(body).toString('hex')};
}
function aesCandidates(candidates) {
  const pass=new Map(),padding=[];
  for(const c of candidates) {
    const raw=Buffer.from(c.hex,'hex');
    for(const [form,b] of [['direct',raw],['sha256-hex',Buffer.from(sha(raw).toString('hex'))]]) {
      const passwordHex=b.toString('hex');if(!pass.has(passwordHex))pass.set(passwordHex,{form,passwordHex,candidate:c});
    }
  }
  let attempts=0;
  for(const p of pass.values())for(const [blob,b] of Object.entries(data.blobs))for(const digest of ['sha256','md5']) {
    attempts++;const body=open(Buffer.from(p.passwordHex,'hex'),b,digest);
    if(body)padding.push({passwordHex:p.passwordHex,blob,digest,plaintextHex:body.toString('hex'),printable:[...body].filter(c=>c>=32&&c<=126||[9,10,13].includes(c)).length/body.length});
  }
  return {passwords:[...pass.values()],attempts,padding};
}
function main() {
  const checked=controls();console.log(JSON.stringify({controls:checked}));if(process.argv[2]==='controls')return;
  const {lists,seeds}=makeSeeds(),limits={maxNodes:200000,maxMs:1000};
  fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify({hypothesis:'All g=0/7 masks; fixed a=1..i=9 otherwise; decimal digit arithmetic then whole integer to minimum big-endian bytes <128.',
    caveat:'Unconfirmed conditional models, not full Gromark or VIC. Seeds start at list boundary; no cyclic rotations. DBBI seeds apply only to FAED.',
    kinds,modes,limits,lists,seeds,controls:checked,sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),inputSHA256:sha(inputBytes).toString('hex'),
    sourceURL:'https://www.cryptogram.org/downloads/aca.info/ciphers/Gromark.pdf'},null,2)+'\n');
  const logfile=path.join(out,'cases.jsonl');fs.writeFileSync(logfile,'');
  let cases=0,nodes=0,certificates=0;const candidates=[],partial=[],byKind={};
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    const source=reverse?[...data[field]].reverse().join(''):data[field];
    for(const seed of seeds.filter(s=>s.fields.includes(field)))for(const kind of kinds)for(const mode of modes) {
      const r=runCase(source,seed.values,kind,mode,limits),id={field,reverse,seed:seed.id,kind,mode};
      cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      byKind[kind]??={cases:0,partial:0,candidates:0,nodes:0};byKind[kind].cases++;byKind[kind].nodes+=r.nodes;byKind[kind].candidates+=r.hits.length;byKind[kind].partial+=Number(!r.complete);
      fs.appendFileSync(logfile,JSON.stringify({...id,...r})+'\n');
      if(!r.complete)partial.push({...id,nodes:r.nodes});
      for(const hit of r.hits)candidates.push({...id,...hit});
      if(cases%5000===0)console.log(JSON.stringify({cases,nodes,candidates:candidates.length,partial:partial.length}));
    }
    console.log(JSON.stringify({field,reverse,cases,nodes,candidates:candidates.length,partial:partial.length}));
  }
  const aes=aesCandidates(candidates);
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');
  fs.writeFileSync(path.join(out,'aes.json'),JSON.stringify(aes,null,2)+'\n');
  const summary={lists:lists.length,seeds:seeds.length,matrixSeeds:seeds.filter(s=>s.fields.includes('dbbi')).length,cases,complete:cases-partial.length,nodes,certificates,candidates:candidates.length,partial,byKind,passwords:aes.passwords.length,aesAttempts:aes.attempts,padding:aes.padding.length,controls:checked};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={chain,derive,feedbackSearch,runCase,makeSeeds,encode,controls};
