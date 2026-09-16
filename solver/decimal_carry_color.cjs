/* Further explicit hypotheses: ordinary integer addition (with carries),
 * and physical colour numbering -> matrix lists -> SHA256 -> original AES.
 * node solver/decimal_carry_color.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {baseLists,keysFromLists,open}=require('./decimal_keystream_constraints.cjs');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','decimal_keystream_2026-09-15','carry_color');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'));
const data=JSON.parse(inputBytes),sha=x=>crypto.createHash('sha256').update(x).digest();
const mod=(x,m)=>((x%m)+m)%m;
const bytesOf=n=>Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length/2)*2,'0'),'hex');
const powers=[1n];for(let i=1;i<=600;i++)powers.push(powers[i-1]*10n);
function sourceDomain(source) {
  const low=BigInt([...source].map(c=>c==='g'?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c==='g'?[7n*powers[source.length-i-1]]:[]);
  const tails=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  return {low,weights,tails,modulus:powers[source.length],length:source.length};
}
function keyNumber(key,length) {return BigInt(Array.from({length},(_,i)=>key[i%key.length]).join(''));}
function intervals(lo,hi,key,mode,modulus) {
  const start=mod(mode==='subtract'?lo-key:mode==='add'?lo+key:key-hi,modulus);
  const end=start+(hi-lo);
  return end<modulus?[[start,end]]:[[start,modulus-1n],[0n,end-modulus]];
}
function search(source,key,mode,{maxNodes=200000,maxMs=1000}={}) {
  assert(['subtract','add','beaufort'].includes(mode));assert(key.length>0);
  const domain=typeof source==='string'?sourceDomain(source):source;
  const {low,weights,tails,modulus,length}=domain,K=keyNumber(key,length);
  const certificates=[],hits=[],pending=[];let nodes=0,covered=0n;const start=Date.now();
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}
    nodes++;
    const ranges=intervals(lo,lo+tails[i],K,mode,modulus);
    if(ranges.every(([a,b])=>nextAscii(a,true)>b)) {certificates.push(mask);covered+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length){const n=ranges[0][0],bytes=bytesOf(n);assert([...bytes].every(b=>b<128));hits.push({mask,decimal:n.toString(),hex:bytes.toString('hex')});return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,low,'');
  const unvisited=pending.reduce((s,m)=>s+(1n<<BigInt(weights.length-m.length)),0n);
  assert.equal(covered+BigInt(hits.length)+unvisited,1n<<BigInt(weights.length));
  return {ambiguous:weights.length,nodes,complete:pending.length===0,certificates,hits,pending,elapsedMs:Date.now()-start};
}
function colorLists() {
  const cells=new Map(data.colored.map(([,co,r,c])=>[`${r},${c}`,co]));
  const definitions=[
    {name:'spectrum-ranks',blue:5,yellow:3,black:1,white:0,reason:'1-based red/orange/yellow/green/blue/indigo/violet ranks for colours; original bits elsewhere.'},
    {name:'spectrum-rank-primes',blue:11,yellow:5,black:1,white:0,reason:'Replace the above colour ranks by the corresponding 5th and 3rd primes; original bits elsewhere.'},
    {name:'resistor-code',blue:6,yellow:4,black:0,white:9,reason:'Standard resistor digit values for all four colours.'},
    {name:'resistor-code-primes',blue:13,yellow:7,black:0,white:23,reason:'Replace nonzero resistor digits by the corresponding primes; leave zero zero.'},
  ];
  const lists=[],matrices=[];
  for(const def of definitions)for(const background of ['specified','zero']) {
    const matrix=data.matrix.map((row,r)=>row.map((v,c)=>cells.get(`${r},${c}`)==='B'?def.blue:cells.get(`${r},${c}`)==='Y'?def.yellow:background==='zero'?0:v?def.black:def.white));
    const name=`${def.name}/${background}`;matrices.push({name,definition:def,background,matrix});
    for(const dir of ['rows','columns'])lists.push({name:`${name}/${dir}`,reason:def.reason,
      values:Array.from({length:14},(_,i)=>Array.from({length:14},(_,j)=>dir==='rows'?matrix[i][j]:matrix[j][i]).reduce((a,b)=>a+b,0))});
  }
  return {matrices,lists};
}
function encode(text,key,mode) {
  const p=BigInt('0x'+Buffer.from(text).toString('hex')),length=p.toString().length,K=keyNumber(key,length),m=powers[length];
  const c=mod(mode==='subtract'?p+K:mode==='add'?p-K:K-p,m);
  return [...c.toString().padStart(length,'0')].map(d=>String.fromCharCode(96+(Number(d)||7))).join('');
}
function controls() {
  let planted=0,bruteForce=0;
  for(const key of [[9,9,8,7,0,1],[6,1,0,8,7,6,6,5,4,9,9,7,8,7,9],[0]])for(const mode of ['subtract','add','beaufort']) {
    for(const text of ['matrixsumlist','lastwordsbeforearchichoice','thispassword',data.phase32_text.slice(0,237)]) {
      const s=encode(text,key,mode),r=search(s,key,mode,{maxMs:5000});assert(r.complete);
      assert(r.hits.some(x=>x.hex===Buffer.from(text).toString('hex')));planted++;
    }
    for(const source of ['ggbg','abcgg','gggggg','faedgg']) {
      const expected=[],count=[...source].filter(c=>c==='g').length,m=powers[source.length],K=keyNumber(key,source.length);
      for(let mask=0;mask<2**count;mask++) {
        let j=0;const n=BigInt([...source].map(c=>c==='g'?((mask>>j++)&1?7:0):c.charCodeAt(0)-96).join(''));
        const p=mod(mode==='subtract'?n-K:mode==='add'?n+K:K-n,m);
        if([...bytesOf(p)].every(b=>b<128))expected.push(p.toString());
      }
      const r=search(source,key,mode);assert(r.complete);assert.deepEqual(r.hits.map(x=>x.decimal).sort(),expected.sort());bruteForce++;
    }
  }
  return {planted,bruteForce};
}
function passwords(color,candidates) {
  const texts=data.phase32_text.replace(/[^A-Za-z]/g,'').toLowerCase();
  const start=texts.indexOf('reinsertingtheprimebasics'),end=texts.indexOf('select',start);
  assert(start>=0&&end>start);
  const lastwords=[texts.slice(start,end),'sheisgoingtodieandthereisnothingyoucandotostopit'];
  const result=new Map();
  function add(label,preimage) {
    const hash=sha(preimage),password=hash.toString('hex');
    if(!result.has(password))result.set(password,{label,preimageHex:Buffer.from(preimage).toString('hex'),password});
  }
  const serialized=[];
  for(const matrix of color.matrices) {
    const row=color.lists.find(x=>x.name===`${matrix.name}/rows`).values,col=color.lists.find(x=>x.name===`${matrix.name}/columns`).values;
    for(const [order,values] of [['rows',row],['columns',col],['rows-columns',[...row,...col]],['columns-rows',[...col,...row]],['interleaved',row.flatMap((v,i)=>[v,col[i]])]])for(const reverse of [false,true])for(const sep of ['',',',' ','\n']) {
      const v=reverse?[...values].reverse():values,text=v.join(sep),id=[matrix.name,order,reverse,JSON.stringify(sep)].join('/');
      serialized.push({id,text});add(id,text);
      for(const word of lastwords) {
        add(`${id}+lastwords/${word}`,text+word);
        add(`dbbi+${id}+faed+lastwords/${word}`,data.dbbi+text+data.faed+word);
      }
    }
  }
  for(const candidate of candidates)add(`decoded/${candidate.field}/${candidate.key}/${candidate.mode}`,Buffer.from(candidate.hex,'hex'));
  return {lastwords,serialized,passwords:[...result.values()]};
}
function runAES(pass) {
  const raw=Buffer.from(data.phase32_control_b64,'base64');
  const ctrl={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
  assert(open(Buffer.from(data.phase32_control_password),ctrl,'sha256').toString().startsWith("I've been waiting for you."));
  const padding=[],keyHits=[];let attempts=0,keysChecked=0;const seenKeys=new Set();
  function checkKey(key,label) {
    if(key.length!==32||seenKeys.has(key.toString('hex')))return;
    seenKeys.add(key.toString('hex'));keysChecked++;
    const ec=crypto.createECDH('secp256k1');try{ec.setPrivateKey(key);}catch{return;}
    const pub=ec.getPublicKey('hex','uncompressed');
    if(pub===data.target_pubkey)keyHits.push({label,keyHex:key.toString('hex')});
  }
  for(const p of pass) {
    assert.equal(sha(Buffer.from(p.preimageHex,'hex')).toString('hex'),p.password);
    checkKey(Buffer.from(p.password,'hex'),`SHA256(${p.label})`);
    for(const [name,blob] of Object.entries(data.blobs))for(const digest of ['sha256','md5']) {
      attempts++;const body=open(Buffer.from(p.password),blob,digest);if(!body)continue;
      padding.push({password:p.password,blob:name,kdf:digest,plaintextHex:body.toString('hex'),printable:[...body].filter(b=>(b>=32&&b<127)||[9,10,13].includes(b)).length/body.length});
      for(let i=0;i+32<=body.length;i++)checkKey(body.subarray(i,i+32),`${name}/${p.password}/${digest}/offset-${i}`);
      for(const m of body.toString('latin1').matchAll(/[0-9a-fA-F]{64}/g))checkKey(Buffer.from(m[0],'hex'),`${name}/hex-key`);
    }
  }
  return {attempts,padding,keysChecked,keyHits};
}
function main() {
  const checked=controls(),color=colorLists(),lists=[...baseLists(),...color.lists],keys=keysFromLists(lists);
  fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify({hypothesis:'Full-integer mod 10^L addition/subtraction/reflection by the repeated decimal key; all g=0/7 masks. Also colour-number matrix sums as SHA256 password inputs.',
    caveat:'Finite conditional models. Spectrum/resistor number assignments and their use here are not instructions confirmed by the puzzle creator.',
    sourceURLs:['https://cosmicopia.gsfc.nasa.gov/qa_gp_b.html','https://www.vishay.com/docs/49411/resistor_color_code_calculator.pdf'],
    sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),inputSHA256:sha(inputBytes).toString('hex'),controls:checked,lists,keys,colorMatrices:color.matrices},null,2)+'\n');
  const logfile=path.join(out,'cases.jsonl');fs.writeFileSync(logfile,'');
  let cases=0,nodes=0,certificates=0;const candidates=[],partial=[];
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    const s=reverse?[...data[field]].reverse().join(''):data[field],domain=sourceDomain(s);
    for(const key of keys)for(const mode of ['subtract','add','beaufort']) {
      const r=search(domain,key.values,mode);cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      fs.appendFileSync(logfile,JSON.stringify({field,reverse,key:key.id,mode,...r})+'\n');
      if(!r.complete)partial.push({field,reverse,key:key.id,mode,nodes:r.nodes});
      for(const h of r.hits)candidates.push({field,reverse,key:key.id,mode,...h});
    }
    console.log(JSON.stringify({field,reverse,cases,nodes,candidates:candidates.length,partial:partial.length}));
  }
  const pass=passwords(color,candidates);
  fs.writeFileSync(path.join(out,'passwords.json'),JSON.stringify(pass,null,2)+'\n');
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');
  console.log(JSON.stringify({testingPasswords:pass.passwords.length}));
  const aes=runAES(pass.passwords);fs.writeFileSync(path.join(out,'aes.json'),JSON.stringify(aes,null,2)+'\n');
  const summary={lists:lists.length,distinctKeys:keys.length,cases,complete:cases-partial.length,nodes,certificates,candidates:candidates.length,partial,passwords:pass.passwords.length,
    aesAttempts:aes.attempts,padding:aes.padding.length,maxPrintable:Math.max(0,...aes.padding.map(x=>x.printable)),keysChecked:aes.keysChecked,keyHits:aes.keyHits,controls:checked};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={sourceDomain,intervals,search,colorLists,encode};
