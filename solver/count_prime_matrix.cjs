/* Bounded clue hypothesis: 9 yellow / 15 blue cells -> primes 23 / 47,
 * then matrix row/column sums. Fixed geometry, no fitted prime values.
 * node solver/count_prime_matrix.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextUtf8,bytesOf}=require('./utf8_decimal_constraints.cjs');
const {domains,keysFromLists,open,baseLists}=require('./decimal_keystream_constraints.cjs');
const {colorLists}=require('./decimal_carry_color.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','count_prime_matrix_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex'),mod=(x,m)=>((x%m)+m)%m;
const pow=[1n];for(let i=1;i<=600;i++)pow.push(pow[i-1]*10n);
function build() {
  const counts={B:0,Y:0};for(const [,c]of input.colored)counts[c]++;
  const primes=[];for(let n=2;primes.length<Math.max(...Object.values(counts));n++)if(!primes.some(p=>p*p<=n&&n%p===0))primes.push(n);
  const values={B:primes[counts.B-1],Y:primes[counts.Y-1]},cells=new Map(input.colored.map(([,color,r,c])=>[r+','+c,color]));
  const matrices=[],lists=[];
  for(const background of ['bits','zero']) {
    const matrix=input.matrix.map((row,r)=>row.map((v,c)=>cells.has(r+','+c)?values[cells.get(r+','+c)]:background==='bits'?v:0));
    matrices.push({background,matrix});
    for(const direction of ['rows','columns'])lists.push({name:background+'/'+direction,values:Array.from({length:14},(_,i)=>Array.from({length:14},(_,j)=>direction==='rows'?matrix[i][j]:matrix[j][i]).reduce((a,b)=>a+b,0))});
  }
  return {counts,values,matrices,lists};
}
function prepare(source,key,mode,family) {
  const ds=family==='digits'?domains(source,key,mode):[...source].map(c=>c==='g'?[0,7]:[c.charCodeAt(0)-96]);
  const low=BigInt(ds.map(x=>x[0]).join('')),weights=ds.flatMap((v,i)=>v.length===2?[BigInt(v[1]-v[0])*pow[source.length-i-1]]:[]);
  const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  const K=BigInt(Array.from({length:source.length},(_,i)=>key[i%key.length]).join('')),M=pow[source.length];
  function ranges(lo,hi) {
    if(family==='digits')return [[lo,hi]];
    const a=mod(mode==='subtract'?lo-K:mode==='add'?lo+K:K-hi,M),b=a+hi-lo;
    return b<M?[[a,b]]:[[a,M-1n],[0n,b-M]];
  }
  return {low,weights,tails,ranges};
}
function search(source,key,mode,family,order,{maxNodes=200000,maxMs=1500}={}) {
  const d=prepare(source,key,mode,family),certificates=[],hits=[],pending=[];
  let nodes=0,excluded=0n;const started=Date.now();
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-started>=maxMs){pending.push(mask);return;}nodes++;
    const rs=d.ranges(lo,lo+d.tails[i]);
    if(rs.every(([a,b])=>nextUtf8(a,order)>b)){certificates.push(mask);excluded+=1n<<BigInt(d.weights.length-i);return;}
    if(i===d.weights.length){assert.equal(rs.length,1);const n=rs[0][0],bytes=bytesOf(n);if(order==='little')bytes.reverse();const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);hits.push({mask,decimal:n.toString(),hex:bytes.toString('hex'),text});return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+d.weights[i],mask+'1');
  }
  visit(0,d.low,'');const unvisited=pending.reduce((s,p)=>s+(1n<<BigInt(d.weights.length-p.length)),0n);
  assert.equal(excluded+BigInt(hits.length)+unvisited,1n<<BigInt(d.weights.length));
  return {ambiguous:d.weights.length,nodes,complete:!pending.length,certificates,hits,pending,elapsedMs:Date.now()-started};
}
function controls() {
  let brute=0,planted=0;
  for(const family of ['digits','carry'])for(const mode of ['subtract','add','beaufort'])for(const order of ['big','little'])for(const key of [[4,7,2,3],[9,0,9]]) {
    for(const source of ['ggbg','gggggg','faegdg','igggib']) {
      const expected=[],d=prepare(source,key,mode,family);
      for(let mask=0;mask<2**d.weights.length;mask++) {
        let n=d.low;d.weights.forEach((w,i)=>{if(mask&(1<<i))n+=w;});n=d.ranges(n,n)[0][0];
        const b=bytesOf(n);if(order==='little')b.reverse();try{new TextDecoder('utf-8',{fatal:true}).decode(b);expected.push(n.toString());}catch{}
      }
      const r=search(source,key,mode,family,order);assert(r.complete);assert.deepEqual(r.hits.map(h=>h.decimal).sort(),expected.sort());brute++;
    }
    const b=Buffer.from('Olá, “matrix” 🔑');if(order==='little')b.reverse();const plain=BigInt('0x'+b.toString('hex')),decimal=plain.toString();
    let cipher;
    if(family==='digits')cipher=[...decimal].map((ch,i)=>mod(mode==='subtract'?Number(ch)+key[i%key.length]:mode==='add'?Number(ch)-key[i%key.length]:key[i%key.length]-Number(ch),10)).join('');
    else {const K=BigInt(Array.from({length:decimal.length},(_,i)=>key[i%key.length]).join(''));cipher=mod(mode==='subtract'?plain+K:mode==='add'?plain-K:K-plain,pow[decimal.length]).toString().padStart(decimal.length,'0');}
    const source=[...cipher].map(d=>String.fromCharCode(96+(Number(d)||7))).join(''),r=search(source,key,mode,family,order);
    assert(r.complete&&r.hits.some(h=>h.decimal===plain.toString()));planted++;
  }
  return {brute,planted};
}
function preimages(geometry,candidates) {
  const texts=new Map();function add(label,bytes){const b=Buffer.isBuffer(bytes)?bytes:Buffer.from(bytes),hex=b.toString('hex');if(!texts.has(hex))texts.set(hex,{hex,label});}
  const normalized=input.phase32_text.replace(/[^a-z]/gi,'').toLowerCase(),a=normalized.indexOf('reinsertingtheprimebasics'),b=normalized.indexOf('select',a);
  assert(a>=0&&b>a);const lastwords=[normalized.slice(a,b),'sheisgoingtodieandthereisnothingyoucandotostopit'];
  for(const {background}of geometry.matrices){const row=geometry.lists.find(l=>l.name===background+'/rows').values,col=geometry.lists.find(l=>l.name===background+'/columns').values;
    for(const [name,list]of [['rows',row],['columns',col],['rows-columns',[...row,...col]],['columns-rows',[...col,...row]],['interleaved',row.flatMap((v,i)=>[v,col[i]])]])for(const reverse of [false,true]) {
      const v=reverse?[...list].reverse():list;
      for(const form of ['digits','comma','space','newline','raw-bytes']) {
        const sep={digits:'',comma:',',space:' ',newline:'\n'}[form],bytes=form==='raw-bytes'?Buffer.from(v):Buffer.from(v.join(sep)),label=[background,name,reverse,form].join('/');
        add(label,bytes);
        for(const words of lastwords) {
          add(label+'/lastwords/'+words,Buffer.concat([bytes,Buffer.from(words)]));
          add('dbbi/'+label+'/faed/lastwords/'+words,Buffer.concat([Buffer.from(input.dbbi),bytes,Buffer.from(input.faed+words)]));
        }
      }
    }
  }
  for(const c of candidates)add('decoded/'+[c.field,c.reverse,c.family,c.mode,c.order,c.key,c.mask].join('/'),Buffer.from(c.hex,'hex'));
  return {lastwords,values:[...texts.values()]};
}
function oracles(pre) {
  const raw=Buffer.from(input.phase32_control_b64,'base64'),ctrl=open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256');
  assert.equal(sha(ctrl),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const passwords=new Map(),padding=[],pubHits=[],scalars=new Set(),ec=crypto.createECDH('secp256k1');
  ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  const order=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');let aesAttempts=0;
  for(const [index,p]of pre.values.entries()) {
    const bytes=Buffer.from(p.hex,'hex'),h=sha(bytes),n=BigInt('0x'+h);
    if(n>0n&&n<order&&!scalars.has(h)){scalars.add(h);ec.setPrivateKey(Buffer.from(h,'hex'));const pub=ec.getPublicKey('hex','uncompressed');if(pub.slice(2,66)===input.target_pubkey.slice(2,66))pubHits.push({index,hash:h,relation:pub===input.target_pubkey?'target':'negation'});}
    for(const [form,pw]of [['direct',bytes],['sha256-hex',Buffer.from(h)]]){const hex=pw.toString('hex');if(passwords.has(hex))continue;passwords.set(hex,{preimage:index,form,hex});
      for(const [blob,value]of Object.entries(input.blobs))for(const digest of ['sha256','md5']){aesAttempts++;const body=open(pw,value,digest);if(!body)continue;padding.push({preimage:index,form,blob,digest,hex:body.toString('hex'),printable:[...body].filter(v=>v>=32&&v<127||[9,10,13].includes(v)).length/body.length});}
    }
  }
  return {passwords:[...passwords.values()],padding,pubHits,aesAttempts,scalarChecks:scalars.size,controls:{phase32:sha(ctrl),ecGenerator:true}};
}
function main() {
  fs.mkdirSync(out,{recursive:true});const checked=controls(),geometry=build(),keys=keysFromLists(geometry.lists);
  const oldLists=[...baseLists(),...colorLists().lists],oldKeys=new Set(keysFromLists(oldLists).map(k=>k.id));
  const spec={hypothesis:'Global counts of yellow and blue cells select the 9th and 15th primes (23,47). Assign those values to each coloured cell and sum rows/columns. Other cells keep original bits or become zero.',geometry,keys,
    models:'Cyclic decimal keys: concatenated list digits or values modulo 10, both directions and all cyclic alignments. Inverse add/subtract/Beaufort, digitwise mod10 or full integer mod10^L. Every g independently 0/7, original/reversed complete fields, big/little endian bytes, strict UTF8.',
    priorKeyOverlap:keys.filter(k=>oldKeys.has(k.id)).map(k=>k.id),limits:{maxNodes:200000,maxMs:1500},controls:checked,inputSHA256:sha(inputBytes),sourceSHA256:sha(fs.readFileSync(__filename)),dependencies:Object.fromEntries(['utf8_decimal_constraints.cjs','decimal_keystream_constraints.cjs','decimal_carry_color.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(root,'solver',f)))]))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');fs.writeFileSync(path.join(out,'cases.jsonl'),'');
  const candidates=[],partial=[];let cases=0,nodes=0,certificates=0;
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    const source=reverse?[...input[field]].reverse().join(''):input[field];
    for(const key of keys)for(const family of ['digits','carry'])for(const mode of ['subtract','add','beaufort'])for(const order of ['big','little']) {
      const r={field,reverse,key:key.id,family,mode,order,...search(source,key.values,mode,family,order)};cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      fs.appendFileSync(path.join(out,'cases.jsonl'),JSON.stringify(r)+'\n');if(!r.complete)partial.push({field,reverse,key:key.id,family,mode,order,nodes:r.nodes});
      for(const h of r.hits)candidates.push({field,reverse,key:key.id,family,mode,order,...h});
    }
    console.log(JSON.stringify({field,reverse,cases,nodes,candidates:candidates.length,partial:partial.length}));
  }
  const pre=preimages(geometry,candidates),aes=oracles(pre);
  fs.writeFileSync(path.join(out,'preimages.json'),JSON.stringify(pre,null,2)+'\n');fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(aes,null,2)+'\n');
  const summary={cases,complete:cases-partial.length,nodes,certificates,candidates,partial,keys:keys.length,priorKeyOverlap:spec.priorKeyOverlap.length,preimages:pre.values.length,passwords:aes.passwords.length,aesAttempts:aes.aesAttempts,paddings:aes.padding.length,maxPrintable:Math.max(0,...aes.padding.map(x=>x.printable)),scalarChecks:aes.scalarChecks,pubHits:aes.pubHits,casesSHA256:sha(fs.readFileSync(path.join(out,'cases.jsonl')))};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({...summary,candidates:candidates.length}));
}
if(require.main===module)main();
