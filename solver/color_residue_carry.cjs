/* Same complete colour-residue keys, now with integer carries. Two declared
 * families: modulo 10^L and ordinary nonnegative integer results.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),zlib=require('node:zlib'),assert=require('node:assert/strict');
const {pipeline}=require('node:stream/promises'),{once}=require('node:events');
const {operators}=require('./color_residue_decimal.cjs');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','color_carry_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex'),mod=(n,m)=>(n%m+m)%m;
const ten=[1n];for(let i=1;i<=600;i++)ten.push(ten[i-1]*10n);
const bytes=n=>Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length/2)*2,'0'),'hex');
function keyInventory() {
  const source=operators();
  // Its negative-coefficient operators are exactly P_i=K_i-C_i, one per key.
  const keys=source.operators.filter(o=>o.sign===-1).map(o=>({id:o.offset.join(''),values:o.offset,representative:o.representative}));
  assert.equal(keys.length,source.keys);assert.equal(new Set(keys.map(k=>k.id)).size,keys.length);
  return {constructions:source.constructions,coefficients:source.coefficients,keys};
}
function domain(source,alias) {
  const low=BigInt([...source].map(c=>c===alias?'0':c.charCodeAt(0)-96).join('')),weights=[];
  for(let i=0;i<source.length;i++)if(source[i]===alias)weights.push(BigInt(cValue(alias))*ten[source.length-i-1]);
  const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  return {low,weights,tails,length:source.length,modulus:ten[source.length]};
}
function cValue(c){return c.charCodeAt(0)-96;}
function keyNumber(key,n){return BigInt(Array.from({length:n},(_,i)=>key[i%key.length]).join(''));}
function ranges(lo,hi,K,mode,family,M) {
  const a=mode==='subtract'?lo-K:mode==='add'?lo+K:K-hi,b=mode==='subtract'?hi-K:mode==='add'?hi+K:K-lo;
  if(family==='nonnegative')return b<0n?[]:[[a<0n?0n:a,b]];
  assert.equal(family,'modulo');
  const start=mod(a,M),end=start+(b-a);
  return end<M?[[start,end]]:[[start,M-1n],[0n,end-M]];
}
function search(d,K,mode,family,{maxNodes=200000,maxMs=1500}={}) {
  const {low,weights,tails,modulus:M}=d,certificates=[],hits=[],pending=[];let nodes=0,covered=0n;const started=Date.now();
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-started>=maxMs){pending.push(mask);return;}
    nodes++;const r=ranges(lo,lo+tails[i],K,mode,family,M);
    if(r.every(([a,b])=>nextAscii(a,true)>b)){certificates.push(mask);covered+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length){assert.equal(r.length,1);assert.equal(r[0][0],r[0][1]);const value=r[0][0];hits.push({mask,decimal:value.toString(),hex:bytes(value).toString('hex')});covered++;return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,low,'');assert.equal(covered+pending.reduce((s,m)=>s+(1n<<BigInt(weights.length-m.length)),0n),1n<<BigInt(weights.length));
  return {ambiguous:weights.length,nodes,complete:pending.length===0,certificates,hits,pending};
}
function controls() {
  let brute=0,planted=0;const plantedByModel={};
  for(const key of [[0],[1],[9],[0,9,1,8],[6,1,0,8,7,6,6,5,4,9,9,7,8,7]])for(const mode of ['add','subtract','beaufort'])for(const family of ['modulo','nonnegative']) {
    for(const source of ['abggb','abcdefghi','eeeeee','iiib','bbbib'])for(const alias of 'abcdefghi') {
      const d=domain(source,alias),K=keyNumber(key,source.length),expected=[];
      for(let m=0;m<2**d.weights.length;m++) {
        let at=0;const C=BigInt([...source].map(c=>c===alias?((m>>at++)&1?cValue(c):0):cValue(c)).join(''));
        let P=mode==='add'?C+K:mode==='subtract'?C-K:K-C;
        if(family==='modulo')P=mod(P,d.modulus);
        if(P>=0n&&[...bytes(P)].every(v=>v<128))expected.push(P.toString());
      }
      const got=search(d,K,mode,family);assert(got.complete);assert.deepEqual(got.hits.map(h=>h.decimal).sort(),expected.sort());brute++;
    }
    for(const text of ['matrixsumlist','thispassword','Integer addition with decimal carries.'])for(const alias of ['b','g','i']) {
      const b=Buffer.from(text),P=BigInt('0x'+b.toString('hex')),L=P.toString().length,M=ten[L],K=keyNumber(key,L);
      let C=mode==='add'?P-K:mode==='subtract'?P+K:K-P;
      if(family==='modulo')C=mod(C,M);else if(C<0n||C>=M)continue;
      const source=[...C.toString().padStart(L,'0')].map(c=>c==='0'?alias:String.fromCharCode(96+Number(c))).join('');
      const got=search(domain(source,alias),K,mode,family);assert(got.complete&&got.hits.some(h=>h.hex===b.toString('hex')));planted++;plantedByModel[family+'/'+mode]=(plantedByModel[family+'/'+mode]||0)+1;
    }
  }
  for(const family of ['modulo','nonnegative'])for(const mode of ['add','subtract','beaufort'])assert(plantedByModel[family+'/'+mode]>0);
  assert.deepEqual(ranges(9n,12n,2n,'add','modulo',10n),[[1n,4n]]);
  assert.deepEqual(ranges(7n,9n,2n,'add','modulo',10n),[[9n,9n],[0n,1n]]);
  assert.deepEqual(ranges(0n,2n,9n,'subtract','nonnegative',10n),[]);
  return {brute,planted,plantedByModel};
}
function oracles(candidates) {
  const materials=new Map();for(const c of candidates)for(const order of ['big','little']){const b=Buffer.from(c.hex,'hex');if(order==='little')b.reverse();const hex=b.toString('hex');if(!materials.has(hex))materials.set(hex,{hex,order,origin:{field:c.field,reverse:c.reverse,key:c.key,mode:c.mode,family:c.family,alias:c.alias,mask:c.mask}});}
  const raw=Buffer.from(input.phase32_control_b64,'base64'),control=open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256');
  assert.equal(sha(control),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const passwords=new Map(),padding=[],scalars=new Set(),pointHits=[];let aesAttempts=0;
  for(const m of materials.values()) {
    const b=Buffer.from(m.hex,'hex'),h=sha(b);scalars.add(h);for(let i=0;i+32<=b.length;i++)scalars.add(b.subarray(i,i+32).toString('hex'));
    for(const [form,pw]of [['direct',b],['sha256-hex',Buffer.from(h)]]) {
      const hex=pw.toString('hex');if(passwords.has(hex))continue;passwords.set(hex,{hex,form,material:m.hex});
      for(const [blob,value]of Object.entries(input.blobs))for(const digest of ['sha256','md5']){aesAttempts++;const plain=open(pw,value,digest);if(plain)padding.push({passwordHex:hex,blob,digest,plaintextHex:plain.toString('hex'),printable:[...plain].filter(v=>v>=32&&v<127||[9,10,13].includes(v)).length/plain.length});}
    }
  }
  const N=BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),ec=crypto.createECDH('secp256k1');let validScalars=0;
  ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  for(const scalar of scalars){const n=BigInt('0x'+scalar);if(n===0n||n>=N)continue;validScalars++;ec.setPrivateKey(Buffer.from(scalar,'hex'));const pub=ec.getPublicKey('hex','uncompressed');if(pub.slice(2,66)===input.target_pubkey.slice(2,66))pointHits.push({scalar,pub,relation:pub===input.target_pubkey?'target':'negation'});}
  return {materials:[...materials.values()],passwords:[...passwords.values()],aesAttempts,padding,scalars:[...scalars],validScalars,pointHits,controlSHA256:sha(control)};
}
async function main() {
  const started=Date.now(),inventory=keyInventory(),checked=controls(),limits={maxNodes:200000,maxMs:1500};fs.mkdirSync(out,{recursive:true});
  const spec={hypothesis:'The complete integer colour-weight residue family supplies a 14-digit repeating key K of the same decimal width L as C. Decode C+K, C-K, or K-C, either modulo 10^L or as an ordinary nonnegative integer. Every occurrence of any ONE selected source letter independently denotes zero or its a=1..i=9 value. Require all minimal bytes below 128.',
    scope:'All blue/yellow integer weights via residues modulo ten; black/white each fixed to zero or one; original row/column sums, both list directions and every cyclic alignment. Both complete fields and both source orders. Sums are reduced modulo ten BEFORE constructing the repeated key; full unreduced sum concatenations are not covered.',
    keyConstructions:inventory.constructions,keys:inventory.keys.length,keyIDsSHA256:sha(inventory.keys.map(k=>k.id).join('\n')),coefficients:inventory.coefficients,
    families:['modulo','nonnegative'],modes:['add','subtract','beaufort'],controls:checked,limits,inputSHA256:sha(inputBytes),sourceSHA256:sha(fs.readFileSync(__filename)),
    helpers:Object.fromEntries(['color_residue_decimal.cjs','zero_decimal_constraints.cjs','decimal_keystream_constraints.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))]))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');fs.writeFileSync(path.join(out,'keys.json.gz'),zlib.gzipSync(Buffer.from(JSON.stringify(inventory.keys))));
  const gz=zlib.createGzip({level:6}),done=pipeline(gz,fs.createWriteStream(path.join(out,'cases.jsonl.gz'))),commitment=crypto.createHash('sha256');
  const candidates=[],partial=[];let records=0,cases=0,nodes=0,certificates=0,log='',lastProgress=Date.now();
  async function flush(){if(!log)return;commitment.update(log);if(!gz.write(log))await once(gz,'drain');log='';}
  try {
    for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
      const source=reverse?[...input[field]].reverse().join(''):input[field],domains=[...'abcdefghi'].map(c=>domain(source,c));
      for(const key of inventory.keys) {
        const K=keyNumber(key.values,source.length);
        for(const family of spec.families)for(const mode of spec.modes) {
          const results=[];
          for(let a=0;a<9;a++) {
            const r=search(domains[a],K,mode,family,limits),alias='abcdefghi'[a];cases++;nodes+=r.nodes;certificates+=r.certificates.length;
            if(!r.complete)partial.push({field,reverse,key:key.id,family,mode,alias,...r});
            for(const h of r.hits)candidates.push({field,reverse,key:key.id,family,mode,alias,...h});results.push({alias,...r});
          }
          log+=JSON.stringify({field,reverse,key:key.id,family,mode,results})+'\n';records++;if(log.length>512*1024)await flush();
        }
        if(Date.now()-lastProgress>=10000){console.log(JSON.stringify({field,reverse,records,cases,candidates:candidates.length,partial:partial.length,seconds:(Date.now()-started)/1000}));lastProgress=Date.now();}
      }
    }
    await flush();gz.end();await done;
  }catch(e){gz.destroy(e);await done.catch(()=>{});throw e;}
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');const oracle=oracles(candidates);fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(oracle,null,2)+'\n');
  const summary={keyConstructions:inventory.constructions,keys:inventory.keys.length,records,cases,complete:cases-partial.length,nodes,certificates,candidates:candidates.length,partial,
    materials:oracle.materials.length,passwords:oracle.passwords.length,aesAttempts:oracle.aesAttempts,padding:oracle.padding.length,validScalars:oracle.validScalars,pointHits:oracle.pointHits,
    casesSHA256:commitment.digest('hex'),elapsedMs:Date.now()-started};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main().catch(e=>{console.error(e);process.exitCode=1;});
module.exports={keyInventory,domain,ranges,search};
