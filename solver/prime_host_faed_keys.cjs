'use strict';
// Continue the new prime-host interpretation: use its sum lists to transform FAED.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {domains,search,encrypt,open,baseLists,keysFromLists}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),source=path.resolve(process.argv[2]||path.join(root,'_work/prime_host_delta_2026-09-17/run1'));
const out=path.resolve(process.argv[3]||path.join(root,'_work/prime_host_delta_2026-09-17/faed_keys'));
assert(!fs.existsSync(out),'Use a fresh destination');fs.mkdirSync(out,{recursive:true});
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const save=(name,x)=>fs.writeFileSync(path.join(out,name),JSON.stringify(x,null,2)+'\n',{flag:'wx'});
const data=JSON.parse(fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')));
const materialsRaw=fs.readFileSync(path.join(source,'materials.json')),materials=JSON.parse(materialsRaw);
const lists=materials.filter(m=>m.provenance.endsWith('/json')).map(m=>({name:m.provenance,values:JSON.parse(Buffer.from(m.hex,'hex').toString())}));
// No rotations added: zero phase, original and reversed lists as already generated.
const keys=new Map();
for(const list of lists)for(const format of ['decimal-concat','mod10']){
  const values=format==='decimal-concat'?[...list.values.join('')].map(Number):list.values.map(v=>v%10);
  const id=values.join('');if(!keys.has(id))keys.set(id,{id:keys.size,values,origin:list.name,format});
}
// The older repeated-key family is omitted when exactly the same key already exists there.
const previous=new Set(keysFromLists(baseLists()).map(k=>k.values.join('')));
let excludedOld=0;for(const [s,k]of keys)if(previous.has(s)){keys.delete(s);excludedOld++;}
const modes=['subtract','add','beaufort'],controls=[];
for(const key of [[2,3,5,7],[1,0,1,6,7]])for(const mode of modes){
  const text='matrixsumlistlastwordsbeforearchichoice';
  const encoded=encrypt(text,key,mode),r=search(domains(encoded,key,mode),{maxMs:5000,maxNodes:500000});
  assert(r.complete);assert(r.hits.some(h=>h.hex===Buffer.from(text).toString('hex')));controls.push({key,mode,recovered:true});
}
save('spec.json',{sourceMaterialsSHA256:sha(materialsRaw),sourceSHA256:sha(fs.readFileSync(__filename)),
  hypothesis:'Prime-host logical matrices and picture-coordinate witnesses yield a decimal key for FAED, following the already tested decimal-keystream model but using newly derived keys.',
  scope:'All JSON list materials from the stated source. Literal decimal digits or each element modulo 10, original/reversed lists, no extra rotations. FAED forward/reversed, P=C-K, C+K, or K-C modulo10, all g choices 0/7, whole decimal integer to minimal big-endian seven-bit bytes. No other symbol renaming or chaining.',
  exclusion:'Exact keys from historical baseLists()/keysFromLists() omitted; this does not audit every historical corpus.',limits:{maxNodes:200000,maxMs:1000},lists:lists.length,excludedOld,distinctKeys:keys.size});
save('keys.json',[...keys.values()]);save('controls.json',controls);
const runs=[],hits=[];let nodes=0,certificates=0,models=0;
for(const k of keys.values())for(const reverse of [false,true])for(const mode of modes){
  const sourceText=reverse?[...data.faed].reverse().join(''):data.faed;
  const r=search(domains(sourceText,k.values,mode),{maxNodes:200000,maxMs:1000});
  runs.push({key:k.id,reverse,mode,...r});models++;nodes+=r.nodes;certificates+=r.certificates.length;
  for(const h of r.hits)hits.push({key:k.id,reverse,mode,...h});
  if(models%1000===0)console.log(JSON.stringify({models,hits:hits.length,partial:runs.filter(r=>!r.complete).length}));
}
save('runs.json',runs);save('hits.json',hits);
const passwords=new Map();for(const h of hits){const b=Buffer.from(h.hex,'hex');for(const p of [b,Buffer.from(sha(b))])passwords.set(p.toString('hex'),p);}
const padding=[];let attempts=0;
for(const [passwordHex,p]of passwords)for(const [blob,b]of Object.entries(data.blobs))for(const digest of ['sha256','md5']){
  const pt=open(p,b,digest);attempts++;if(pt)padding.push({passwordHex,blob,digest,hex:pt.toString('hex')});
}
save('padding.json',padding);
const summary={lists:lists.length,excludedOld,keys:keys.size,models,complete:runs.filter(r=>r.complete).length,partial:runs.filter(r=>!r.complete).length,nodes,certificates,
  hits:hits.length,passwords:passwords.size,AESAttempts:attempts,paddings:padding.length};save('summary.json',summary);console.log(JSON.stringify(summary,null,2));
