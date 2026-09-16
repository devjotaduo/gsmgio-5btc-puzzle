/* Authenticate ranked checkerboard candidates against the three AES blobs
 * and the published secp256k1 key. PKCS#7 alone is only a padding hit.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),readline=require('node:readline');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),base=path.join(root,'_work','ambiguous_checkerboard_2026-09-15'),general=process.env.GSMG_CHECKERBOARD_PROFILE==='general',out=general?path.join(base,'general_english'):base,input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const sha=b=>crypto.createHash('sha256').update(b).digest(),N=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const raw=Buffer.from(input.phase32_control_b64,'base64'),control=open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256');
assert.equal(sha(control).toString('hex'),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const ec=crypto.createECDH('secp256k1');ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
const aesFile=path.join(out,'padding.jsonl');fs.writeFileSync(aesFile,'');
const passwords=new Set(),scalars=new Set(),pubHits=[],printableBodies=[],datasetHashes={};let records=0,aesAttempts=0,paddings=0,scalarChecks=0,maxPrintable=0;
function forms(text) {
  const m=new Map();for(const [shape,s] of [['dots',text],['no-dots',text.replace(/\./g,'')],['spaces',text.replace(/\./g,' ')]])for(const [letterCase,t] of [['upper',s],['lower',s.toLowerCase()]])if(!m.has(t))m.set(t,{shape,letterCase});return [...m].map(([text,info])=>({text,...info}));
}
function checkScalar(bytes,source) {
  const hex=bytes.toString('hex');if(scalars.has(hex))return;scalars.add(hex);const n=BigInt('0x'+hex);if(n===0n||n>=N)return;
  ec.setPrivateKey(bytes);const pub=ec.getPublicKey('hex','uncompressed');scalarChecks++;
  if(pub.slice(2,66)===input.target_pubkey.slice(2,66)) {
    const secret=pub===input.target_pubkey?hex:(N-n).toString(16).padStart(64,'0');ec.setPrivateKey(Buffer.from(secret,'hex'));assert.equal(ec.getPublicKey('hex','uncompressed'),input.target_pubkey);pubHits.push({...source,secretHex:secret});
  }
}
async function main() {
  let priorPasswords=0,priorScalars=0,priorOracleSHA256=null;
  if(general) {
    const oldBytes=fs.readFileSync(path.join(base,'oracles.json')),old=JSON.parse(oldBytes);assert.equal(old.pubHits.length,0);assert.equal(old.printableBodies.length,0);priorOracleSHA256=sha(oldBytes).toString('hex');
    for(const dataset of ['direct','matrix_keys']) {
      const file=path.join(base,dataset==='direct'?'':dataset,'ranked.jsonl');assert.equal(sha(fs.readFileSync(file)).toString('hex'),old.datasetHashes[dataset]);
      for await(const line of readline.createInterface({input:fs.createReadStream(file),crlfDelay:Infinity}))for(const f of forms(JSON.parse(line).text)) {
        const p=Buffer.from(f.text),h=sha(p).toString('hex');passwords.add(p.toString('hex'));passwords.add(Buffer.from(h).toString('hex'));scalars.add(h);
      }
    }
    priorPasswords=passwords.size;priorScalars=scalars.size;assert.equal(priorPasswords,old.passwords);assert.equal(priorScalars,old.scalarChecks);
    console.log(JSON.stringify({reusedPriorPasswords:priorPasswords,reusedPriorScalars:priorScalars}));
  }
  for(const dataset of ['direct','matrix_keys']) {
    const folder=dataset==='direct'?out:path.join(out,dataset),file=path.join(folder,'ranked.jsonl');datasetHashes[dataset]=sha(fs.readFileSync(file)).toString('hex');let lineNumber=0;
    for await(const line of readline.createInterface({input:fs.createReadStream(file),crlfDelay:Infinity})) {
      lineNumber++;const r=JSON.parse(line);records++;
      for(const f of forms(r.text)) {
        const p=Buffer.from(f.text),hash=sha(p),source={dataset,line:lineNumber,shape:f.shape,letterCase:f.letterCase};checkScalar(hash,{...source,derivation:'sha256(candidate)'});
        for(const [form,password] of [['direct',p],['sha256-hex',Buffer.from(hash.toString('hex'))]]) {
          const id=password.toString('hex');if(passwords.has(id))continue;passwords.add(id);
          for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
            aesAttempts++;const b=open(password,blob,digest);if(!b)continue;paddings++;
            const printable=[...b].filter(v=>v>=32&&v<127||[9,10,13].includes(v)).length/b.length;maxPrintable=Math.max(maxPrintable,printable);
            const rec={...source,form,blob:name,digest,printable,plaintextHex:b.toString('hex')};fs.appendFileSync(aesFile,JSON.stringify(rec)+'\n');
            if(printable>0.9)printableBodies.push(rec);
            if(b.length===32)checkScalar(b,{...source,form,blob:name,digest,derivation:'AES-32-byte-body'});
            if(/^[0-9a-fA-F]{64}$/.test(b.toString()))checkScalar(Buffer.from(b.toString(),'hex'),{...source,form,blob:name,digest,derivation:'AES-hex-body'});
          }
        }
      }
      if(records%5000===0)console.log(JSON.stringify({records,passwords:passwords.size,aesAttempts,paddings,scalarChecks,pubHits:pubHits.length,maxPrintable}));
    }
  }
  const result={records,passwords:passwords.size-priorPasswords,priorPasswords,priorScalars,priorOracleSHA256,aesAttempts,paddings,scalarChecks,pubHits,printableBodies,maxPrintable,
    controls:{phase32PlaintextSHA256:sha(control).toString('hex'),secp256k1Generator:true},datasetHashes,sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),
    caveat:'Padding is unauthenticated. No claim that every possible zero mask or lower-scoring plaintext was tried as a password.'};
  fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}
main().catch(e=>{console.error(e);process.exitCode=1;});
