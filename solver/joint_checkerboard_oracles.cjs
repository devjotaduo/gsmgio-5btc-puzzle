'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','joint_checkerboard_2026-09-16'),input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),sha=b=>crypto.createHash('sha256').update(b).digest();
const lines=fs.readFileSync(path.join(out,'cases.jsonl'),'utf8').split('\n').slice(0,90),cases=lines.map(l=>JSON.parse(l));assert.equal(cases.length,90);assert(cases.every(c=>c.dataset==='real'));assert.equal(new Set(cases.map(c=>[c.reverse,...c.esc].join('/'))).size,90);
fs.writeFileSync(path.join(out,'real_cases.jsonl'),lines.join('\n')+'\n');
const candidates=new Map();for(let c=0;c<cases.length;c++)for(const group of ['improvements','restartBests'])for(const [index,b] of (cases[c][group]||[]).entries())if(!candidates.has(b.text))candidates.set(b.text,{text:b.text,score:b.score,case:c,group,index});
const raw=Buffer.from(input.phase32_control_b64,'base64'),control=open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256');assert.equal(sha(control).toString('hex'),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const ec=crypto.createECDH('secp256k1'),order=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),scalarSet=new Set(),passwords=new Set(),padding=[],pubHits=[];let aesAttempts=0,scalarChecks=0,maxPrintable=0;
ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
for(const [candidate,c] of [...candidates.values()].entries())for(const letterCase of ['upper','lower']) {
  const text=letterCase==='lower'?c.text.toLowerCase():c.text,p=Buffer.from(text),hash=sha(p),h=hash.toString('hex'),n=BigInt('0x'+h);
  if(!scalarSet.has(h)&&n>0n&&n<order) {
    scalarSet.add(h);scalarChecks++;ec.setPrivateKey(hash);const pub=ec.getPublicKey('hex','uncompressed');
    if(pub.slice(2,66)===input.target_pubkey.slice(2,66)){const secretHex=pub===input.target_pubkey?h:(order-n).toString(16).padStart(64,'0');ec.setPrivateKey(Buffer.from(secretHex,'hex'));assert.equal(ec.getPublicKey('hex','uncompressed'),input.target_pubkey);pubHits.push({candidate,letterCase,secretHex});}
  }
  for(const [form,password] of [['direct',p],['sha256-hex',Buffer.from(h)]]) {
    const id=password.toString('hex');if(passwords.has(id))continue;passwords.add(id);
    for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
      aesAttempts++;const b=open(password,blob,digest);if(!b)continue;
      const printable=[...b].filter(v=>v>=32&&v<127||[9,10,13].includes(v)).length/b.length;maxPrintable=Math.max(maxPrintable,printable);padding.push({candidate,letterCase,form,blob:name,digest,printable,plaintextHex:b.toString('hex')});
    }
  }
}
fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify([...candidates.values()])+'\n');fs.writeFileSync(path.join(out,'padding.json'),JSON.stringify(padding)+'\n');
const result={cases:90,uniqueCandidateTexts:candidates.size,passwords:passwords.size,aesAttempts,paddings:padding.length,scalarChecks,pubHits,maxPrintable,mostlyPrintable:padding.filter(p=>p.printable>.9),
  controls:{phase32SHA256:sha(control).toString('hex'),ecGenerator:true},realCasesSHA256:sha(fs.readFileSync(path.join(out,'real_cases.jsonl'))).toString('hex'),candidatesSHA256:sha(fs.readFileSync(path.join(out,'candidates.json'))).toString('hex'),sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),
  caveat:'Only saved global improvements and restart bests tested; null/shuffled inputs are not password candidates. Padding alone is not authentication.'};
fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
