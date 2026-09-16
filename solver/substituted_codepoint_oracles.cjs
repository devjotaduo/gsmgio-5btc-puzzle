'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_codepoints_2026-09-16'),input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const sha=b=>crypto.createHash('sha256').update(b).digest(),hashFile=p=>sha(fs.readFileSync(p)).toString('hex');
const accepted=JSON.parse(fs.readFileSync(path.join(out,'accepted.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),verification=JSON.parse(fs.readFileSync(path.join(out,'verification.json')));
assert(verification.allPassed);assert.equal(verification.hashes.accepted,summary.acceptedSHA256);assert.equal(summary.acceptedSHA256,hashFile(path.join(out,'accepted.json')));assert.equal(summary.partialModels.length,0);
const unique=new Map();let paths=0;
for(const [model,c]of accepted.entries()){assert(c.complete);for(const hex of c.texts){paths++;if(!unique.has(hex))unique.set(hex,{hex,model});}}
assert.equal(paths,summary.savedTexts);assert.equal(String(paths),summary.totalControlFreePaths);
const candidates=[...unique.values()],passwords=new Map(),scalars=new Map(),padding=[],pubHits=[];
const raw=Buffer.from(input.phase32_control_b64,'base64'),control=open(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256');
assert.equal(sha(control).toString('hex'),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const ec=crypto.createECDH('secp256k1'),order=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
let attempts=0;
for(const [candidate,c]of candidates.entries()) {
  const bytes=Buffer.from(c.hex,'hex'),hash=sha(bytes);assert([...bytes].every(b=>b>=32&&b<=126));
  for(const [form,b]of [['sha256',hash],...(bytes.length===32?[['raw',bytes]]:[])]){
    const hex=b.toString('hex'),n=BigInt('0x'+hex);if(n===0n||n>=order||scalars.has(hex))continue;scalars.set(hex,{candidate,form,hex});ec.setPrivateKey(b);const pub=ec.getPublicKey('hex','uncompressed');if(pub.slice(2,66)===input.target_pubkey.slice(2,66))pubHits.push({candidate,form,hex,relation:pub===input.target_pubkey?'target':'negation'});
  }
  for(const [form,pw]of [['direct',bytes],['sha256-hex',Buffer.from(hash.toString('hex'))]]) {
    const id=pw.toString('hex');if(passwords.has(id))continue;passwords.set(id,{candidate,form,hex:id});
    for(const [blob,b]of Object.entries(input.blobs))for(const digest of ['sha256','md5']){attempts++;const plain=open(pw,b,digest);if(!plain)continue;padding.push({candidate,form,blob,digest,hex:plain.toString('hex'),printable:[...plain].filter(v=>v>=32&&v<127||[9,10,13].includes(v)).length/plain.length});}
  }
}
fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates)+'\n');fs.writeFileSync(path.join(out,'padding.json'),JSON.stringify(padding)+'\n');
const result={paths,uniqueCandidates:candidates.length,passwords:[...passwords.values()],scalars:[...scalars.values()],aesAttempts:attempts,paddings:padding.length,maxPrintable:Math.max(0,...padding.map(p=>p.printable)),pubHits,controls:{phase32SHA256:sha(control).toString('hex'),ecGenerator:true},hashes:{accepted:summary.acceptedSHA256,candidates:hashFile(path.join(out,'candidates.json')),padding:hashFile(path.join(out,'padding.json')),source:hashFile(__filename)},limits:'Only all control-free ASCII paths tested, as exact bytes and SHA256 hex passwords. Paths containing TAB/LF/CR were counted but not password-tested; the entire cipher family is not excluded by these AES results.'};
fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({...result,passwords:passwords.size,scalars:scalars.size}));
