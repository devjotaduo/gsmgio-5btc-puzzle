/* Independent count for fixed MSB patterns, full known-key model audit,
 * CBC with manual PKCS#7, and candidate scalar/public-key comparison.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','xor_period_2026-09-15','known_keys'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),keyFile=fs.readFileSync(path.join(root,'_work','xor_period_2026-09-15','dbbi_followup.json'));
const keyRecords=JSON.parse(keyFile).keys,keys=keyRecords.map(r=>Buffer.from(r.keyHex,'hex')),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
assert.equal(sha(keyFile),spec.keyFileSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','xor_knownkey_constraints.cjs'))),spec.sourceSHA256);assert.equal(keys.length,spec.keyCount);
const p128=[1n],ten=[1n];for(let i=1;i<=600;i++){p128.push(p128[i-1]*128n);ten.push(ten[i-1]*10n);}
function bytes(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
function count(n,key) {
  if(n<0n)return 0n;const zero=(key[0]>>7)===0?1n:0n;if(n===0n)return zero;
  const b=bytes(n),firstCount=(key[0]>>7)===0?127n:128n;let total=zero+firstCount*(p128[b.length-1]-1n)/127n;
  for(let i=0;i<b.length;i++) {
    const high=key[i%key.length]>>7,lower=Math.max(0,Math.min(128,b[i]-128*high))-(i===0&&high===0?1:0);
    assert(lower>=0);total+=BigInt(lower)*p128[b.length-i-1];if((b[i]>>7)!==high)return total;
  }
  return total+1n;
}
let controls=0;
for(const key of [[0],[128],[0,128],[128,0],[0,128,128]]) {
  let expected=0n;
  for(let n=0;n<65536;n++){if([...bytes(BigInt(n))].every((b,i)=>((b^key[i%key.length])&128)===0))expected++;assert.equal(count(BigInt(n),key),expected);controls++;}
  for(let l=1;l<=300;l++)assert.equal(count(256n**BigInt(l)-1n,key),(key[0]===0?1n:0n)+(key[0]===0?127n:128n)*(p128[l]-1n)/127n);
}
const domains=new Map();
for(const reverse of [false,true])for(const alias of 'abcdefghi') {
  const s=reverse?[...input.dbbi].reverse().join(''):input.dbbi,lo=BigInt([...s].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const w=[...s].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*ten[s.length-i-1]]:[]),tail=Array(w.length+1).fill(0n);for(let i=w.length-1;i>=0;i--)tail[i]=tail[i+1]+w[i];domains.set(`${reverse}/${alias}`,{lo,w,tail});
}
const data=fs.readFileSync(path.join(out,'cases.jsonl')),records=data.toString('utf8').trim().split('\n').map(JSON.parse),ids=new Set(),found=[];let certificates=0,nodes=0;
for(const r of records) {
  assert.equal(typeof r.reverse,'boolean');assert.match(r.alias,/^[a-i]$/);assert(Number.isInteger(r.keyIndex)&&r.keyIndex>=0&&r.keyIndex<keys.length);assert(r.complete&&r.pending.length===0);
  const id=`${r.reverse}/${r.alias}/${r.keyIndex}`;assert(!ids.has(id));ids.add(id);const d=domains.get(`${r.reverse}/${r.alias}`),key=keys[r.keyIndex];assert.equal(r.ambiguous,d.w.length);
  const masks=[...r.certificates,...r.hits.map(h=>h.mask)].sort();for(let i=1;i<masks.length;i++)assert(!masks[i].startsWith(masks[i-1]));let coverage=0n;
  for(const mask of r.certificates) {
    assert.match(mask,/^[01]*$/);assert(mask.length<=d.w.length);let lo=d.lo;for(let i=0;i<mask.length;i++)if(mask[i]==='1')lo+=d.w[i];
    assert.equal(count(lo+d.tail[mask.length],key)-count(lo-1n,key),0n,`${id}/${mask}`);coverage+=1n<<BigInt(d.w.length-mask.length);certificates++;
  }
  for(const h of r.hits) {
    assert.match(h.mask,/^[01]*$/);assert.equal(h.mask.length,d.w.length);let n=d.lo;for(let i=0;i<h.mask.length;i++)if(h.mask[i]==='1')n+=d.w[i];assert.equal(n.toString(),h.decimal);assert.equal(bytes(n).toString('hex'),h.hex);
    const cipher=bytes(n),plain=Buffer.from(cipher.map((b,i)=>b^key[i%32]));assert(plain.every(v=>v<128));coverage++;
    found.push({reverse:r.reverse,alias:r.alias,keyIndex:r.keyIndex,...h,plaintextHex:plain.toString('hex'),fullyPrintable:plain.every(v=>v>=32&&v<=126||[9,10,13].includes(v))});
  }
  assert.equal(coverage,1n<<BigInt(d.w.length));nodes+=r.nodes;
}
assert.equal(ids.size,18*keys.length);assert.equal(ids.size,saved.cases);assert.equal(nodes,saved.nodes);assert.equal(certificates,saved.certificates);assert.equal(saved.partial.length,0);
assert.deepEqual(found,JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))));assert.equal(found.length,saved.candidates);
function decrypt(pw,blob,digest) {
  const salt=Buffer.from(blob.salt,'hex');let previous=Buffer.alloc(0),material=Buffer.alloc(0);
  while(material.length<48){previous=crypto.createHash(digest).update(Buffer.concat([previous,pw,salt])).digest();material=Buffer.concat([material,previous]);}
  const d=crypto.createDecipheriv('aes-256-cbc',material.subarray(0,32),material.subarray(32,48));d.setAutoPadding(false);
  const body=Buffer.concat([d.update(Buffer.from(blob.ciphertext,'hex')),d.final()]),pad=body.at(-1);
  return pad>=1&&pad<=16&&body.subarray(-pad).every(v=>v===pad)?body.subarray(0,body.length-pad):null;
}
const raw=Buffer.from(input.phase32_control_b64,'base64');assert.equal(sha(decrypt(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256')),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const aes=JSON.parse(fs.readFileSync(path.join(out,'aes.json'))),expected=new Map(aes.padding.map(r=>[[r.passwordHex,r.blob,r.digest].join('/'),r.plaintextHex])),seenScalars=new Set(),keyHits=[];let attempts=0,paddings=0,scalarChecks=0;
function checkScalar(b,label) {
  const hex=b.toString('hex');if(b.length!==32||seenScalars.has(hex))return;seenScalars.add(hex);const ec=crypto.createECDH('secp256k1');try{ec.setPrivateKey(b);}catch{return;}scalarChecks++;
  if(ec.getPublicKey('hex','compressed').slice(2)===input.target_pubkey.slice(2,66))keyHits.push({hex,label});
}
function scan(b,label){checkScalar(Buffer.from(sha(b),'hex'),`${label}/sha256`);for(let i=0;i+32<=b.length;i++)checkScalar(b.subarray(i,i+32),`${label}/offset-${i}`);}
const generated=new Set();for(const c of found){const body=Buffer.from(c.plaintextHex,'hex');generated.add(body.toString('hex'));generated.add(Buffer.from(sha(body)).toString('hex'));scan(body,'xor-plaintext');}
assert.equal(generated.size,aes.passwords.length);
for(const p of aes.passwords) {
  const body=Buffer.from(p.preimageHex,'hex');assert(['direct','sha256-hex'].includes(p.form));const pw=p.form==='direct'?body:Buffer.from(sha(body));assert.equal(pw.toString('hex'),p.passwordHex);assert(generated.has(p.passwordHex));
  for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    const b=decrypt(pw,blob,digest);assert.equal(b?.toString('hex')??null,expected.get([p.passwordHex,name,digest].join('/'))??null);attempts++;if(b){paddings++;scan(b,'aes-plaintext');}
  }
}
assert.equal(attempts,aes.attempts);assert.equal(attempts,saved.aesAttempts);assert.equal(paddings,aes.padding.length);
const result={cases:ids.size,nodes,certificates,candidates:found.length,fullyPrintable:found.filter(c=>c.fullyPrintable).length,allModelsCompleteAndMatched:true,controls:{smallIntegers:controls,largeWidths:1500,phase32:true},aesAttempts:attempts,paddings,scalarChecks,keyHits,
  keyScope:'Candidate plaintext SHA256 and every contiguous big-endian 32-byte plaintext window; compare public-key x to also include negation. Other derivations not tested.',
  casesSHA256:sha(data),verifierSHA256:sha(fs.readFileSync(__filename))};fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
