'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_joined_words_2026-09-16'));
const sha=b=>crypto.createHash('sha256').update(b).digest();
const candidates=JSON.parse(fs.readFileSync(path.join(folder,'candidates.json'))),input=JSON.parse(fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')));
assert(!fs.existsSync(path.join(folder,'oracles.json')),'Preserve existing oracle evidence');
const control=Buffer.from(input.phase32_control_b64,'base64');
assert.equal(sha(open(Buffer.from(input.phase32_control_password),{salt:control.subarray(8,16).toString('hex'),ciphertext:control.subarray(16).toString('hex')},'sha256')).toString('hex'),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
const materials=new Map();
for(const candidate of candidates)for(const [form,text] of [['raw',candidate.text],['upper',candidate.text.toUpperCase()],['joined',candidate.text.replace(/\s/g,'')],['joined-upper',candidate.text.replace(/\s/g,'').toUpperCase()]]) {
  if(!materials.has(text))materials.set(text,{id:materials.size,candidate:candidate.id,form,text});
}
const list=[...materials.values()],padding=[],decision=crypto.createHash('sha256');let attempts=0,maxPrintable=0;
fs.writeFileSync(path.join(folder,'materials.json'),JSON.stringify(list)+'\n',{flag:'wx'});
for(const m of list)for(const form of ['direct','sha256-hex']) {
  const raw=Buffer.from(m.text),password=form==='direct'?raw:Buffer.from(sha(raw).toString('hex'));
  for(const [blob,b]of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    const body=open(password,b,digest),hex=body?body.toString('hex'):'-';attempts++;
    decision.update([m.id,form,blob,digest,hex].join('|')+'\n');
    if(body) {
      const printable=[...body].filter(x=>x>=32&&x<=126||[9,10,13].includes(x)).length/body.length;
      maxPrintable=Math.max(maxPrintable,printable);padding.push({material:m.id,form,blob,digest,hex,printable});
    }
  }
}
const result={candidates:candidates.length,materials:list.length,passwordCases:list.length*2,attempts,padding:padding.length,maxPrintable,
  decisionsSHA256:decision.digest('hex'),paddingRecords:padding,sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),
  inputsSHA256:Object.fromEntries(['candidates.json','materials.json','spec.json','summary.json'].map(n=>[n,sha(fs.readFileSync(path.join(folder,n))).toString('hex')])),
  caveat:'Padding and dictionary membership are not authentication; partial searches do not exclude unseen candidates.'};
fs.writeFileSync(path.join(folder,'oracles.json'),JSON.stringify(result)+'\n',{flag:'wx'});
console.log(JSON.stringify({...result,paddingRecords:padding.length},null,2));
