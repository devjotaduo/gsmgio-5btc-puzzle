/* Entire integer colour-weight family modulo 10, not a bounded prime list.
 * Conditional model: row/column sums are a repeating decimal additive key.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const zlib=require('node:zlib'),assert=require('node:assert/strict');
const {pipeline}=require('node:stream/promises'),{once}=require('node:events');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const {search:referenceSearch,open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','color_residue_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex'),mod=x=>(x%10+10)%10;
const ten=[1n];for(let i=1;i<=600;i++)ten.push(ten[i-1]*10n);
const bytes=n=>Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length/2)*2,'0'),'hex');

function coefficients() {
  const colors=new Map(input.colored.map(([,co,r,c])=>[r+','+c,co]));
  const out={rows:Array.from({length:14},()=>[0,0,0,0]),columns:Array.from({length:14},()=>[0,0,0,0])};
  for(let r=0;r<14;r++)for(let c=0;c<14;c++) {
    const co=colors.get(r+','+c),which=co==='B'?0:co==='Y'?1:input.matrix[r][c]?2:3;
    out.rows[r][which]++;out.columns[c][which]++;
  }
  return out;
}
function operators() {
  const coeff=coefficients(),keys=new Set(),ops=new Map();let constructions=0;
  for(let black=0;black<2;black++)for(let white=0;white<2;white++)for(let blue=0;blue<10;blue++)for(let yellow=0;yellow<10;yellow++) {
    for(const axis of ['rows','columns']) {
      const list=coeff[axis].map(([b,y,k,w])=>b*blue+y*yellow+k*black+w*white);
      for(const reverse of [false,true])for(let shift=0;shift<14;shift++) {
        const key=Array.from({length:14},(_,i)=>mod(list[reverse?13-(i+shift)%14:(i+shift)%14]));
        constructions++;keys.add(key.join(''));
        for(const mode of ['add','subtract','beaufort']) {
          const sign=mode==='beaufort'?-1:1,offset=key.map(v=>mode==='subtract'?mod(-v):v),id=sign+':'+offset.join('');
          if(!ops.has(id))ops.set(id,{id,sign,offset,representative:{black,white,blue,yellow,axis,reverse,shift,mode}});
        }
      }
    }
  }
  return {coefficients:coeff,constructions,keys:keys.size,operators:[...ops.values()]};
}

// Build the nine sets of digit domains in one pass. Mask bits select the
// smaller/larger transformed digit, not necessarily zero/nonzero ciphertext.
function numericDomains(source,op) {
  const groups=Array.from({length:9},()=>({adjust:0n,weights:[]}));let digits='';
  for(let i=0;i<source.length;i++) {
    const c=source.charCodeAt(i)-96,k=op.offset[i%14],normal=mod(op.sign*c+k),zero=k;
    digits+=normal;
    const lo=Math.min(normal,zero),hi=Math.max(normal,zero),unit=ten[source.length-i-1],g=groups[c-1];
    g.adjust+=BigInt(lo-normal)*unit;g.weights.push(BigInt(hi-lo)*unit);
  }
  const baseline=BigInt(digits);
  return groups.map(g=>({low:baseline+g.adjust,weights:g.weights}));
}
function search({low,weights},{maxNodes=200000,maxMs=1500}={}) {
  const tails=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  const certificates=[],hits=[],pending=[];let nodes=0,covered=0n;const started=Date.now();
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-started>=maxMs){pending.push(mask);return;}
    nodes++;
    if(nextAscii(lo,true)>lo+tails[i]){certificates.push(mask);covered+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length){hits.push({mask,decimal:lo.toString(),hex:bytes(lo).toString('hex')});covered++;return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,low,'');
  assert.equal(covered+pending.reduce((s,m)=>s+(1n<<BigInt(weights.length-m.length)),0n),1n<<BigInt(weights.length));
  return {ambiguous:weights.length,nodes,complete:pending.length===0,certificates,hits,pending};
}
function controls() {
  let crossChecked=0,planted=0;
  const choices=[{sign:1,offset:[0,1,2,3,4,5,6,7,8,9,1,2,3,4]},
    {sign:-1,offset:[9,8,7,6,5,4,3,2,1,0,9,8,7,6]}];
  for(const op of choices)for(const source of ['aabbccgg','abcdefghi','gggggg','bbbib','abcefgic'])for(const alias of 'abcdefghi') {
    const numeric=numericDomains(source,op)['abcdefghi'.indexOf(alias)];
    const ds=[...source].map((c,i)=>(c===alias?[0,c.charCodeAt(0)-96]:[c.charCodeAt(0)-96]).map(v=>mod(op.sign*v+op.offset[i%14])).sort((a,b)=>a-b));
    const reference=referenceSearch(ds),actual=search(numeric);delete reference.elapsedMs;assert.deepEqual(actual,reference);
    crossChecked++;
  }
  for(const op of choices)for(const alias of 'abcdefghi')for(const text of ['matrixsumlist','thispassword','A controlled test of the entire decimal number.']) {
    const plain=Buffer.from(text),decimal=BigInt('0x'+plain.toString('hex')).toString();
    const cipher=[...decimal].map((c,i)=>{const n=mod(op.sign*(Number(c)-op.offset[i%14]));return n===0?alias:String.fromCharCode(96+n);}).join('');
    const r=search(numericDomains(cipher,op)['abcdefghi'.indexOf(alias)]);
    assert(r.complete&&r.hits.some(h=>h.hex===plain.toString('hex')));planted++;
  }
  return {crossChecked,planted};
}
function oracles(candidates) {
  const materials=new Map();for(const c of candidates)for(const order of ['big','little']) {
    const b=Buffer.from(c.hex,'hex');if(order==='little')b.reverse();const hex=b.toString('hex');
    if(!materials.has(hex))materials.set(hex,{hex,order,origin:{field:c.field,reverse:c.reverse,operator:c.operator,alias:c.alias,mask:c.mask}});
  }
  const raw=Buffer.from(input.phase32_control_b64,'base64');
  const control=open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256');
  assert.equal(sha(control),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const passwords=new Map(),padding=[],scalars=new Set(),pointHits=[];let aesAttempts=0;
  const curveOrder=BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  for(const m of materials.values()) {
    const b=Buffer.from(m.hex,'hex'),h=sha(b);scalars.add(h);
    for(let i=0;i+32<=b.length;i++)scalars.add(b.subarray(i,i+32).toString('hex'));
    for(const [form,pw]of [['direct',b],['sha256-hex',Buffer.from(h)]]) {
      const hex=pw.toString('hex');if(passwords.has(hex))continue;passwords.set(hex,{hex,form,material:m.hex});
      for(const [name,blob]of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
        aesAttempts++;const plain=open(pw,blob,digest);if(plain)padding.push({passwordHex:hex,blob:name,digest,plaintextHex:plain.toString('hex'),printable:[...plain].filter(v=>v>=32&&v<127||[9,10,13].includes(v)).length/plain.length});
      }
    }
  }
  const ec=crypto.createECDH('secp256k1');let validScalars=0;
  ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  for(const scalar of scalars) {const n=BigInt('0x'+scalar);if(n===0n||n>=curveOrder)continue;validScalars++;ec.setPrivateKey(Buffer.from(scalar,'hex'));const pub=ec.getPublicKey('hex','uncompressed');if(pub.slice(2,66)===input.target_pubkey.slice(2,66))pointHits.push({scalar,pub,relation:pub===input.target_pubkey?'target':'negation'});}
  return {materials:[...materials.values()],passwords:[...passwords.values()],aesAttempts,padding,scalars:[...scalars],validScalars,pointHits,controlSHA256:sha(control)};
}

async function main() {
  const started=Date.now(),inventory=operators(),checked=controls(),limits={maxNodes:200000,maxMs:1500};
  fs.mkdirSync(out,{recursive:true});
  const spec={hypothesis:'Blue and yellow have arbitrary fixed integer weights; original black and white each have one fixed value in {0,1}. Sum each original row/column, reduce modulo ten, repeat the 14 values as a digitwise additive/subtractive/Beaufort key. Either complete field/order and any one independent zero alias, then whole decimal -> seven-bit bytes.',
    reduction:'Only the residue of each colour weight modulo ten affects this operation. All 100 blue/yellow residue pairs therefore cover every integer pair, including primes of any size. This does not cover decimal concatenation of the unreduced sums or arbitrary cell-specific values.',
    keyConstructions:inventory.constructions,keys:inventory.keys,operators:inventory.operators.length,coefficients:inventory.coefficients,
    operatorIDsSHA256:sha(inventory.operators.map(o=>o.id).join('\n')),controls:checked,limits,inputSHA256:sha(inputBytes),sourceSHA256:sha(fs.readFileSync(__filename)),
    helpers:Object.fromEntries(['zero_decimal_constraints.cjs','decimal_keystream_constraints.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))]))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  fs.writeFileSync(path.join(out,'operators.json.gz'),zlib.gzipSync(Buffer.from(JSON.stringify(inventory.operators)),{level:6}));
  const gz=zlib.createGzip({level:6}),sink=fs.createWriteStream(path.join(out,'cases.jsonl.gz')),done=pipeline(gz,sink),transcript=crypto.createHash('sha256');
  let log='',records=0,cases=0,nodes=0,certificates=0,lastProgress=Date.now();const candidates=[],partial=[];
  async function flush(){if(!log)return;transcript.update(log);if(!gz.write(log))await once(gz,'drain');log='';}
  try {
    for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
      const source=reverse?[...input[field]].reverse().join(''):input[field];
      for(const op of inventory.operators) {
        const domains=numericDomains(source,op),results=[];
        for(let alias=0;alias<9;alias++) {
          const r=search(domains[alias],limits),label='abcdefghi'[alias];cases++;nodes+=r.nodes;certificates+=r.certificates.length;
          if(!r.complete)partial.push({field,reverse,operator:op.id,alias:label,...r});
          for(const h of r.hits)candidates.push({field,reverse,operator:op.id,alias:label,...h});
          results.push({alias:label,...r});
        }
        log+=JSON.stringify({field,reverse,operator:op.id,results})+'\n';records++;
        if(log.length>512*1024)await flush();
        if(Date.now()-lastProgress>=10000){console.log(JSON.stringify({field,reverse,records,cases,candidates:candidates.length,partial:partial.length,seconds:(Date.now()-started)/1000}));lastProgress=Date.now();}
      }
    }
    await flush();gz.end();await done;
  } catch(e) {gz.destroy(e);await done.catch(()=>{});throw e;}
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');
  const oracle=oracles(candidates);fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(oracle,null,2)+'\n');
  const summary={keyConstructions:inventory.constructions,keys:inventory.keys,operators:inventory.operators.length,records,cases,complete:cases-partial.length,nodes,certificates,candidates:candidates.length,partial,
    materials:oracle.materials.length,passwords:oracle.passwords.length,aesAttempts:oracle.aesAttempts,padding:oracle.padding.length,validScalars:oracle.validScalars,pointHits:oracle.pointHits,
    casesSHA256:transcript.digest('hex'),elapsedMs:Date.now()-started};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main().catch(e=>{console.error(e);process.exitCode=1;});
module.exports={operators,numericDomains,search};
