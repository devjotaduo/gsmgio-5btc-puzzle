'use strict';
// Cryptographic checks for every saved real-data text in this campaign.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','checkerboard_exact_mask_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest();
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw);
function main(){
  const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json')));assert.equal(spec.inputSHA256,sha(inputRaw).toString('hex'));
  // The writer appends records. Ignore any not-yet-terminated final line and
  // freeze the completed real-data subset while shuffle controls may continue.
  const snapshot=fs.readFileSync(path.join(out,'cases.jsonl'),'utf8'),lines=snapshot.slice(0,snapshot.lastIndexOf('\n')+1).trim().split(/\r?\n/),realLines=lines.filter(l=>JSON.parse(l).dataset==='real');
  const cases=realLines.map(JSON.parse);assert.equal(cases.length,90);
  assert.equal(new Set(cases.map(c=>[c.reverse,...c.esc].join('/'))).size,90);
  for(const c of cases)assert.equal(c.source,c.reverse?[...input.faed].reverse().join(''):input.faed);
  const raw=Buffer.from(realLines.join('\n')+'\n');fs.writeFileSync(path.join(out,'real_cases.jsonl'),raw);
  const texts=new Map();function add(text,source){assert.match(text,/^[A-Z ]+$/);if(!texts.has(text))texts.set(text,{text,source});}
  for(const [index,c]of cases.entries()){
    for(const group of ['improvements','restartBests'])for(const [j,r]of (c.quad[group]||[]).entries())add(r.text,{case:index,kind:'quadgram',group,index:j});
    for(const [start,r]of c.refinements.entries())for(const [j,v]of r.improvements.entries()){
      add(v.text,{case:index,kind:'word',start,index:j,spacing:'none'});add(v.words.join(' '),{case:index,kind:'word',start,index:j,spacing:'inferred'});
    }
  }
  const candidates=[...texts.values()],passwords=new Map(),scalarSet=new Set(),pubHits=[],padding=[];
  const ec=crypto.createECDH('secp256k1'),order=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');let scalarChecks=0,aesAttempts=0,maxPrintable=0;
  function keyCheck(bytes,source){const h=bytes.toString('hex');if(scalarSet.has(h))return;scalarSet.add(h);const n=BigInt('0x'+h);if(n===0n||n>=order)return;scalarChecks++;ec.setPrivateKey(bytes);const pub=ec.getPublicKey('hex','uncompressed');if(pub.slice(2,66)===input.target_pubkey.slice(2,66))pubHits.push({source,scalarHex:h,relation:pub===input.target_pubkey?'target':'negation'});}
  function scan(bytes,source){keyCheck(sha(bytes),source+'/sha256');for(let i=0;i+32<=bytes.length;i++){const b=bytes.subarray(i,i+32);keyCheck(b,source+'/BE/'+i);keyCheck(Buffer.from(b).reverse(),source+'/LE/'+i);}}
  const ctrl=Buffer.from(input.phase32_control_b64,'base64'),plain=open(Buffer.from(input.phase32_control_password),{salt:ctrl.subarray(8,16).toString('hex'),ciphertext:ctrl.subarray(16).toString('hex')},'sha256');assert.equal(sha(plain).toString('hex'),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  ec.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));assert.equal(ec.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  for(const [candidate,c]of candidates.entries())for(const letterCase of ['upper','lower']){
    const bytes=Buffer.from(letterCase==='lower'?c.text.toLowerCase():c.text),hash=sha(bytes);keyCheck(hash,`candidate/${candidate}/${letterCase}`);
    for(const [form,password]of [['direct',bytes],['sha256-hex',Buffer.from(hash.toString('hex'))]]){const id=password.toString('hex');if(passwords.has(id))continue;passwords.set(id,{candidate,letterCase,form,passwordHex:id});
      for(const [blob,value]of Object.entries(input.blobs))for(const digest of ['sha256','md5']){
        aesAttempts++;const body=open(password,value,digest);if(!body)continue;const printable=[...body].filter(v=>v>=32&&v<=126||[9,10,13].includes(v)).length/body.length;maxPrintable=Math.max(maxPrintable,printable);const index=padding.length;padding.push({candidate,letterCase,form,blob,digest,plaintextHex:body.toString('hex'),printable});scan(body,`padding/${index}`);
      }
    }
  }
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates)+'\n');fs.writeFileSync(path.join(out,'passwords.json'),JSON.stringify([...passwords.values()])+'\n');fs.writeFileSync(path.join(out,'padding.json'),JSON.stringify(padding)+'\n');fs.writeFileSync(path.join(out,'scalars.bin'),Buffer.concat([...scalarSet].map(h=>Buffer.from(h,'hex'))));
  const result={complete:true,realCases:cases.length,candidateTexts:candidates.length,passwords:passwords.size,aesAttempts,paddings:padding.length,maxPrintable,scalarRecords:scalarSet.size,scalarChecks,pubHits,mostlyPrintable:padding.filter(r=>r.printable>.9),controls:{phase32SHA256:sha(plain).toString('hex'),ecGenerator:true},sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),inputSHA256:sha(inputRaw).toString('hex'),helperSHA256:sha(fs.readFileSync(path.join(__dirname,'decimal_keystream_constraints.cjs'))).toString('hex'),realCasesSHA256:sha(raw).toString('hex'),artifacts:Object.fromEntries(['real_cases.jsonl','candidates.json','passwords.json','padding.json','scalars.bin'].map(f=>[f,sha(fs.readFileSync(path.join(out,f))).toString('hex')])),scope:'All 90 completed real cases; shuffle controls may still be running. All saved real quadgram improvements/restart bests and word-refinement improvements. Upper/lower text with and without inferred word spaces, direct or SHA256 hex. Three blobs, EVP-SHA256/MD5. Scalars: candidate SHA256 and padding SHA256 plus every 32-byte padding window in both orders. No shuffled/control texts are passwords.'};
  fs.writeFileSync(path.join(out,'oracles.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();
