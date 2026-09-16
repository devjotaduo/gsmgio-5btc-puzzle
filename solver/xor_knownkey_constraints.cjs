/* DBBI with ANY single zero alias and the exact 14,042 matrix-derived
 * SHA256 keys preserved by xor_dbbi_followup.cjs. All zero assignments,
 * constrained by the key's byte MSBs; no new password vocabulary.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','xor_period_2026-09-15','known_keys');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),keyFile=fs.readFileSync(path.join(root,'_work','xor_period_2026-09-15','dbbi_followup.json')),keyData=JSON.parse(keyFile).keys;
const sha=b=>crypto.createHash('sha256').update(b).digest('hex'),ten=[1n];for(let i=1;i<=600;i++)ten.push(ten[i-1]*10n);
function bytes(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
function nextPattern(n,bits) {
  const b=bytes(n),p=bits.length;
  for(let i=0;i<b.length;i++) {
    if((b[i]>>7)===bits[i%p])continue;let at=i;
    if(bits[i%p]===1)b[i]=128;
    else {
      for(at=i-1;at>=0;at--)if(b[at]<(bits[at%p]?255:127)){b[at]++;break;}
      if(at<0) {
        const longer=Buffer.from(Array.from({length:b.length+1},(_,j)=>bits[j%p]*128));if(longer[0]===0)longer[0]=1;
        return BigInt('0x'+longer.toString('hex'));
      }
    }
    for(let j=at+1;j<b.length;j++)b[j]=bits[j%p]*128;
    return BigInt('0x'+b.toString('hex'));
  }
  return n;
}
function domain(source,alias) {
  const low=BigInt([...source].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*ten[source.length-i-1]]:[]),tails=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];return {low,weights,tails};
}
function search(d,bits,{maxNodes=50000,maxMs=500}={}) {
  const {low,weights,tails}=d,certificates=[],pending=[],hits=[];const start=Date.now();let nodes=0,covered=0n;
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}
    nodes++;
    if(nextPattern(lo,bits)>lo+tails[i]){certificates.push(mask);covered+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length){hits.push({mask,decimal:lo.toString(),hex:bytes(lo).toString('hex')});return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,low,'');const unvisited=pending.reduce((sum,m)=>sum+(1n<<BigInt(weights.length-m.length)),0n);assert.equal(covered+BigInt(hits.length)+unvisited,1n<<BigInt(weights.length));
  return {nodes,complete:pending.length===0,ambiguous:weights.length,certificates,pending,hits};
}
function controls() {
  let successors=0,planted=0;
  for(const bits of [[0],[1],[0,1],[1,0],[0,1,1]]) {
    const good=n=>[...bytes(n)].every((b,i)=>(b>>7)===bits[i%bits.length]);let next=65536n;while(!good(next))next++;
    for(let n=65535n;n>=0n;n--){if(good(n))next=n;assert.equal(nextPattern(n,bits),next);successors++;}
  }
  const key=Buffer.from(sha('matrixsumlist'),'hex'),text=Buffer.from('matrixsumlistlastwordsbeforearchichoice!'),cipher=Buffer.from(text.map((b,i)=>b^key[i%32])),decimal=BigInt('0x'+cipher.toString('hex')).toString();
  for(const alias of 'abcdefghi') {
    const source=[...decimal].map(d=>d==='0'?alias:String.fromCharCode(96+Number(d))).join(''),r=search(domain(source,alias),[...key].map(b=>b>>7),{maxNodes:1000000,maxMs:5000});
    assert(r.complete);assert(r.hits.some(h=>h.hex===cipher.toString('hex')));planted++;
  }
  const raw=Buffer.from(input.phase32_control_b64,'base64');assert.equal(sha(open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256')),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  return {successors,planted,phase32Control:true};
}
function main() {
  const checked=controls();fs.mkdirSync(out,{recursive:true});
  const keys=keyData.map(k=>{assert.equal(sha(Buffer.from(k.preimageHex,'hex')),k.keyHex);return Buffer.from(k.keyHex,'hex');});
  const spec={hypothesis:'DBBI a=1..i=9, any ONE symbol independently zero, both original and reversed symbol order, whole decimal integer -> bytes XOR repeated raw SHA256 of exactly the previously saved matrix candidates; all output bytes <128.',
    keyFileSHA256:sha(keyFile),keyCount:keys.length,sourceSHA256:sha(fs.readFileSync(__filename)),controls:checked,limits:{maxNodes:50000,maxMs:500}};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  const logfile=path.join(out,'cases.jsonl');fs.writeFileSync(logfile,'');let cases=0,nodes=0,certificates=0;const partial=[],candidates=[];
  for(const reverse of [false,true])for(const alias of 'abcdefghi') {
    const source=reverse?[...input.dbbi].reverse().join(''):input.dbbi,d=domain(source,alias);
    for(let index=0;index<keys.length;index++) {
      const key=keys[index],r=search(d,[...key].map(b=>b>>7),spec.limits),id={reverse,alias,keyIndex:index};cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      fs.appendFileSync(logfile,JSON.stringify({...id,...r})+'\n');if(!r.complete)partial.push(id);
      for(const h of r.hits) {
        const cipher=Buffer.from(h.hex,'hex'),plain=Buffer.from(cipher.map((b,i)=>b^key[i%32]));assert(plain.every(b=>b<128));
        candidates.push({...id,...h,plaintextHex:plain.toString('hex'),fullyPrintable:plain.every(b=>b>=32&&b<=126||[9,10,13].includes(b))});
      }
    }
    console.log(JSON.stringify({reverse,alias,cases,nodes,candidates:candidates.length,partial:partial.length}));
  }
  const passwords=new Map(),padding=[];let aesAttempts=0;
  for(const c of candidates)for(const form of ['direct','sha256-hex']){const b=Buffer.from(c.plaintextHex,'hex'),pw=form==='direct'?b:Buffer.from(sha(b)),hex=pw.toString('hex');if(!passwords.has(hex))passwords.set(hex,{passwordHex:hex,form,preimageHex:b.toString('hex')});}
  for(const p of passwords.values())for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    aesAttempts++;const plain=open(Buffer.from(p.passwordHex,'hex'),blob,digest);if(plain)padding.push({passwordHex:p.passwordHex,blob:name,digest,plaintextHex:plain.toString('hex')});
  }
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');fs.writeFileSync(path.join(out,'aes.json'),JSON.stringify({passwords:[...passwords.values()],attempts:aesAttempts,padding},null,2)+'\n');
  const summary={cases,nodes,certificates,partial,candidates:candidates.length,fullyPrintable:candidates.filter(c=>c.fullyPrintable).length,passwords:passwords.size,aesAttempts,padding:padding.length,controls:checked};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={nextPattern,search,domain};
