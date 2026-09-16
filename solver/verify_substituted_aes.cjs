'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),dir=path.join(root,'_work','substituted_decimal_2026-09-15');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function decrypt(password,blob,digest) {
  let previous=Buffer.alloc(0),material=Buffer.alloc(0);const salt=Buffer.from(blob.salt,'hex');
  while(material.length<48){previous=crypto.createHash(digest).update(Buffer.concat([previous,password,salt])).digest();material=Buffer.concat([material,previous]);}
  const aes=crypto.createDecipheriv('aes-256-cbc',material.subarray(0,32),material.subarray(32,48));aes.setAutoPadding(false);
  const plain=Buffer.concat([aes.update(Buffer.from(blob.ciphertext,'hex')),aes.final()]),pad=plain.at(-1);
  if(pad<1||pad>16||!plain.subarray(-pad).every(b=>b===pad))return null;
  return plain.subarray(0,plain.length-pad);
}
const raw=Buffer.from(input.phase32_control_b64,'base64');assert.equal(sha(decrypt(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256')),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const target=input.target_pubkey.slice(2,66),hits=[],seenKeys=new Set();let keyChecks=0,attempts=0,paddings=0,passwords=0,candidates=0,fullyPrintableCandidates=0;
function check(key,label) {
  if(key.length!==32)return;const hex=key.toString('hex');if(seenKeys.has(hex))return;seenKeys.add(hex);
  const ec=crypto.createECDH('secp256k1');try{ec.setPrivateKey(key);}catch{return;}
  keyChecks++;const pub=ec.getPublicKey('hex','compressed');if(pub.slice(2)===target)hits.push({key:hex,label,pub});
}
function scan(bytes,label) {
  for(let i=0;i+32<=bytes.length;i++)check(bytes.subarray(i,i+32),`${label}/offset-${i}`);
  for(const m of bytes.toString('latin1').matchAll(/[0-9a-fA-F]{64}/g))check(Buffer.from(m[0],'hex'),`${label}/hex`);
}
const one=crypto.createECDH('secp256k1');one.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(one.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
for(const alias of 'abcdefghi') {
  const saved=JSON.parse(fs.readFileSync(path.join(dir,`aes-${alias}.json`))),result=JSON.parse(fs.readFileSync(path.join(dir,`alias-${alias}.json`)));
  assert.equal(result.partial.length,0);assert.equal(result.groups.length,4);candidates+=result.candidates.length;
  for(const c of result.candidates){const b=Buffer.from(c.hex,'hex');if([...b].every(x=>(x>=32&&x<=126)||[9,10,13].includes(x)))fullyPrintableCandidates++;scan(b,`${alias}/${c.mapping}/${c.reverse}`);check(Buffer.from(sha(b),'hex'),'candidate-sha256');}
  const expected=new Map(saved.padding.map(p=>[[p.passwordHex,p.blob,p.kdf].join('/'),p.plaintextHex]));assert.equal(expected.size,saved.padding.length);
  for(const p of saved.passwords) {
    const bytes=Buffer.from(p.preimageHex,'hex'),pw=p.form==='direct'?bytes:Buffer.from(sha(bytes));assert.equal(pw.toString('hex'),p.passwordHex);passwords++;
    for(const [name,blob]of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
      attempts++;const plain=decrypt(pw,blob,digest),id=[p.passwordHex,name,digest].join('/');assert.equal(plain?.toString('hex')??null,expected.get(id)??null);
      if(plain){paddings++;scan(plain,`aes/${id}`);}
    }
  }
}
const result={candidates,fullyPrintableCandidates,passwords,attempts,paddings,keyChecks,keyHits:hits,allDecryptionResultsMatched:true,phase32Control:true,scalarOneControl:true,scope:'Keys: candidate SHA256, raw 32-byte big-endian windows in candidates and padded AES outputs, 64-hex runs. Public-key x-coordinate compared to include negation. No other derivations claimed.',verifierSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(dir,'aes_verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
