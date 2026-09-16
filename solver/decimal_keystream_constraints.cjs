/* Matrix-derived decimal keystreams, with ALL 0/7 assignments for g.
 * node solver/decimal_keystream_constraints.cjs
 * C = P+K, P-K, or K-P (digitwise mod10); then decimal integer -> bytes.
 * Conditional experiment, not an assertion that this is the intended cipher.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','decimal_keystream_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'));
const data=JSON.parse(inputBytes);
const sha=x=>crypto.createHash('sha256').update(x).digest();
const mod=(n,m)=>((n%m)+m)%m;
const prime=n=>n>=2&&Array.from({length:Math.max(0,Math.floor(Math.sqrt(n))-1)},(_,i)=>i+2).every(d=>n%d);
const primes=[];for(let n=2;primes.length<196;n++)if(prime(n))primes.push(n);
const bytesOf=n=>Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length/2)*2,'0'),'hex');
const powers=[1n];for(let i=1;i<=600;i++)powers.push(powers[i-1]*10n);
const modes={subtract:(c,k)=>mod(c-k,10),add:(c,k)=>mod(c+k,10),beaufort:(c,k)=>mod(k-c,10)};

function domains(source,key,mode) {
  assert(key.length>0&&key.every(k=>Number.isInteger(k)&&k>=0&&k<=9));
  assert.match(source,/^[a-i]+$/);assert(mode in modes);
  return [...source].map((c,i)=>[...new Set((c==='g'?[0,7]:[c.charCodeAt(0)-96]).map(n=>modes[mode](n,key[i%key.length])))].sort((a,b)=>a-b));
}
function search(ds,{maxNodes=200000,maxMs=1000}={}) {
  assert(ds.length>0&&ds.length<=600&&ds.every(d=>(d.length===1||d.length===2)&&d.every(n=>Number.isInteger(n)&&n>=0&&n<=9)&&new Set(d).size===d.length&&d[0]<=d.at(-1)));
  const minimum=BigInt(ds.map(d=>d[0]).join(''));
  const weights=ds.flatMap((d,i)=>d.length===2?[BigInt(d[1]-d[0])*powers[ds.length-i-1]]:[]);
  const tail=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tail[i]=tail[i+1]+weights[i];
  const certificates=[],hits=[],pending=[];
  let nodes=0,excluded=0n;const start=Date.now();
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}
    nodes++;
    const hi=lo+tail[i];
    if(nextAscii(lo,true)>hi){certificates.push(mask);excluded+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length){const b=bytesOf(lo);assert([...b].every(x=>x<128));hits.push({mask,decimal:lo.toString(),hex:b.toString('hex')});return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,minimum,'');
  const uncovered=pending.reduce((s,m)=>s+(1n<<BigInt(weights.length-m.length)),0n);
  assert.equal(excluded+BigInt(hits.length)+uncovered,1n<<BigInt(weights.length));
  return {ambiguous:weights.length,nodes,complete:pending.length===0,certificates,hits,pending,elapsedMs:Date.now()-start};
}
function baseLists() {
  const lists=[];
  const add=(name,values,reason)=>{assert(values.length&&values.every(Number.isSafeInteger));lists.push({name,values,reason});};
  function sums(name,matrix,reason) {
    for(const dir of ['rows','columns'])add(`${name}/${dir}`,Array.from({length:14},(_,i)=>Array.from({length:14},(_,j)=>dir==='rows'?matrix[i][j]:matrix[j][i]).reduce((s,x)=>s+x,0)),reason);
  }
  const colors=new Map(data.colored.map(([,color,r,c])=>[`${r},${c}`,color]));
  sums('binary',data.matrix,'The literal row/column sum lists of the original 14x14 matrix.');
  for(const color of ['B','Y'])sums(`count-${color}`,data.matrix.map((row,r)=>row.map((_,c)=>Number(colors.get(`${r},${c}`)===color))),'Row/column counts of the named colour.');
  for(const [blue,yellow] of [[2,3],[3,2]])for(const background of ['bits','zero']) {
    sums(`colours-${blue}-${yellow}/${background}`,data.matrix.map((row,r)=>row.map((v,c)=>colors.get(`${r},${c}`)==='B'?blue:colors.get(`${r},${c}`)==='Y'?yellow:background==='bits'?v:0)),
      'Hypothesis: assign the two smallest primes to the two colours; retain original non-colour bits or zero them. Both colour assignments are explicit alternatives.');
  }
  for(const dir of ['rows','columns'])add(`binary-values/${dir}`,Array.from({length:14},(_,i)=>parseInt(Array.from({length:14},(_,j)=>dir==='rows'?data.matrix[i][j]:data.matrix[j][i]).join(''),2)),
    'Interpret each full matrix row/column as a binary integer.');
  for(const order of ['row-major','spiral']) {
    const matrix=data.matrix.map(row=>row.map(()=>0));
    const cells=order==='row-major'?Array.from({length:196},(_,i)=>[Math.floor(i/14),i%14]):data.spiral;
    cells.forEach(([r,c],i)=>{matrix[r][c]=data.matrix[r][c]*primes[i];});
    sums(`prime-weighted/${order}`,matrix,'Hypothesis: replace each live bit by the prime at its 1-based cell rank before summing.');
    for(const color of ['B','Y']) {
      const indexes=cells.flatMap(([r,c],i)=>colors.get(`${r},${c}`)===color?[i+1]:[]);
      add(`colour-indexes/${order}/${color}`,indexes,'1-based positions of coloured cells.');
      const selected=indexes.filter(prime);
      // Spiral colour ranks are byte boundaries, all multiples of eight:
      // their prime subset is empty and cannot serve as a cyclic key.
      if(selected.length)add(`prime-colour-indexes/${order}/${color}`,selected,'Only prime-valued positions of coloured cells.');
    }
  }
  const basic=lists.filter(x=>x.name.startsWith('binary/'));
  for(const b of basic)add(`nth-prime/${b.name}`,b.values.map(n=>primes[n-1]),'Hypothesis: replace each binary-matrix sum by that numbered prime.');
  return lists;
}
function keysFromLists(lists) {
  const keys=new Map();
  for(const item of lists)for(const representation of ['residue10','decimal-digits']) {
    const base=representation==='residue10'?item.values.map(v=>mod(v,10)):[...item.values.join('')].map(Number);
    for(const reverse of [false,true]) {
      const k=reverse?[...base].reverse():base;
      for(let shift=0;shift<k.length;shift++) {
        const key=[...k.slice(shift),...k.slice(0,shift)],id=key.join('');
        const provenance={list:item.name,representation,reverse,shift};
        if(!keys.has(id))keys.set(id,{id,values:key,provenance:[provenance]});else keys.get(id).provenance.push(provenance);
      }
    }
  }
  return [...keys.values()];
}
function encrypt(text,key,mode) {
  const decimal=BigInt('0x'+Buffer.from(text).toString('hex')).toString();
  return [...decimal].map((ch,i)=>{
    const p=Number(ch),k=key[i%key.length];
    const c=mode==='subtract'?mod(p+k,10):mode==='add'?mod(p-k,10):mod(k-p,10);
    return String.fromCharCode(96+(c===0?7:c));
  }).join('');
}
function open(password,blob,digest) {
  const salt=Buffer.from(blob.salt,'hex');let prev=Buffer.alloc(0),material=Buffer.alloc(0);
  while(material.length<48){prev=crypto.createHash(digest).update(prev).update(password).update(salt).digest();material=Buffer.concat([material,prev]);}
  const d=crypto.createDecipheriv('aes-256-cbc',material.subarray(0,32),material.subarray(32,48));
  try{return Buffer.concat([d.update(Buffer.from(blob.ciphertext,'hex')),d.final()]);}
  catch(e){if(e.code==='ERR_OSSL_BAD_DECRYPT')return null;throw e;}
}
function controls() {
  let planted=0,bruteForce=0;
  for(const key of [[6,1,0,8,7,6,6,5,4,9,9,7,8,7,9],[2,3,5,7,1,1],[0,9]])for(const mode of Object.keys(modes)) {
    for(const text of ['matrixsumlist','lastwordsbeforearchichoice','thispassword',data.phase32_text.slice(0,237)]) {
      const source=encrypt(text,key,mode),r=search(domains(source,key,mode),{maxMs:5000});
      assert(r.complete);assert(r.hits.some(x=>x.hex===Buffer.from(text).toString('hex')));planted++;
    }
    for(const source of ['ggbg','abcgg','gggggg','faedgg']) {
      const ds=domains(source,key,mode),expected=[];
      function enumerate(i,prefix){if(i===ds.length){const n=BigInt(prefix);if([...bytesOf(n)].every(b=>b<128))expected.push(n.toString());return;}for(const d of ds[i])enumerate(i+1,prefix+d);}
      enumerate(0,'');const r=search(ds);assert(r.complete);assert.deepEqual(r.hits.map(x=>x.decimal).sort(),expected.sort());bruteForce++;
    }
  }
  const raw=Buffer.from(data.phase32_control_b64,'base64');
  const control={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
  const p=open(Buffer.from(data.phase32_control_password),control,'sha256');
  assert(p.toString().startsWith("I've been waiting for you."));
  assert.equal(open(Buffer.from(data.phase32_control_password),control,'md5'),null);
  return {planted,bruteForce,phase32PlaintextSHA256:sha(p).toString('hex')};
}
function testCandidates(candidates) {
  const passwords=new Map();
  for(const c of candidates) {
    const raw=Buffer.from(c.hex,'hex');
    for(const [form,pw] of [['direct',raw],['sha256-hex',Buffer.from(sha(raw).toString('hex'))]]) {
      const k=pw.toString('hex');if(!passwords.has(k))passwords.set(k,{passwordHex:k,form,candidate:c});
    }
  }
  const padding=[];let attempts=0;
  for(const p of passwords.values())for(const [name,blob] of Object.entries(data.blobs))for(const digest of ['sha256','md5']) {
    attempts++;const body=open(Buffer.from(p.passwordHex,'hex'),blob,digest);if(!body)continue;
    padding.push({passwordHex:p.passwordHex,blob:name,kdf:digest,plaintextHex:body.toString('hex'),printable:[...body].filter(b=>(b>=32&&b<127)||[9,10,13].includes(b)).length/body.length});
  }
  return {passwords:[...passwords.values()],attempts,padding};
}
function main() {
  const checked=controls(),lists=baseLists(),keys=keysFromLists(lists);
  const readme=fs.readFileSync(path.join(root,'README.md'),'utf8');
  const line=readme.split(/\r?\n/).find(l=>l.startsWith('> d b b i')).slice(2).replace(/[ *]/g,'');
  assert.equal(line.slice(0,91),data.dbbi);assert.equal(line.slice(195,765),data.faed);
  assert.equal(data.matrix.flat().reduce((a,b)=>a+b,0),101);
  fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify({hypothesis:'Known cyclic decimal keystream, independently choose each g as 0 or 7, inverse digitwise mod10, whole decimal integer to minimal big-endian bytes all <=127.',
    caveat:'The lists and operations are hypotheses. Nothing in the source uniquely specifies a decimal keystream. All cyclic alignments and both directions are tested.',
    limits:{maxNodesPerCase:200000,maxMsPerCase:1000},controls:checked,sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),inputSHA256:sha(inputBytes).toString('hex'),lists,keys},null,2)+'\n');
  const logfile=path.join(out,'cases.jsonl');fs.writeFileSync(logfile,'');
  const candidates=[],partial=[];let cases=0,nodes=0,certificates=0;
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    const source=reverse?[...data[field]].reverse().join(''):data[field];
    for(const k of keys)for(const mode of Object.keys(modes)) {
      const r=search(domains(source,k.values,mode)),record={field,reverse,key:k.id,mode,...r};
      cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      fs.appendFileSync(logfile,JSON.stringify(record)+'\n');
      if(!r.complete)partial.push({field,reverse,key:k.id,mode,nodes:r.nodes});
      for(const hit of r.hits)candidates.push({field,reverse,key:k.id,mode,...hit});
    }
    console.log(JSON.stringify({field,reverse,cases,nodes,candidates:candidates.length,partial:partial.length}));
  }
  const aes=testCandidates(candidates);
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');
  fs.writeFileSync(path.join(out,'aes.json'),JSON.stringify(aes,null,2)+'\n');
  const summary={lists:lists.length,distinctKeys:keys.length,cases,complete:cases-partial.length,nodes,certificates,candidates:candidates.length,partial,aesAttempts:aes.attempts,paddings:aes.padding.length,controls:checked};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={domains,search,baseLists,keysFromLists,encrypt,open};
