/* The surviving DBBI period32 MSB models: test exact SHA256 key material
 * already derived from matrices, and exact alphabet compatibility.
 * No arbitrary new vocabulary. A feasible alphabet is not a plaintext.
 * node solver/xor_dbbi_followup.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {baseLists,open}=require('./decimal_keystream_constraints.cjs');
const {colorLists}=require('./decimal_carry_color.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','xor_period_2026-09-15');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),witnessBytes=fs.readFileSync(path.join(out,'witnesses.json')),witnesses=JSON.parse(witnessBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest(),printable=b=>(b>=32&&b<=126)||[9,10,13].includes(b);
const xor=(cipher,key)=>Buffer.from(cipher.map((v,i)=>v^key[i%key.length]));
function domains(cipher,alphabet) {
  const allowed=new Set(alphabet),result=[];
  for(let offset=0;offset<32;offset++)result.push(Array.from({length:256},(_,k)=>k).filter(k=>[...cipher].every((b,i)=>i%32!==offset||allowed.has(b^k))));
  return result;
}
const keySources=new Map(),sourceFiles={};
function add(preimage,label) {
  const raw=Buffer.from(preimage),key=sha(raw),id=key.toString('hex');
  if(!keySources.has(id))keySources.set(id,{keyHex:id,preimageHex:raw.toString('hex'),labels:[]});keySources.get(id).labels.push(label);
}
const oldPath='_work/prime_geometry_2026-09-11/candidates.jsonl',oldBytes=fs.readFileSync(path.join(root,oldPath));sourceFiles[oldPath]=sha(oldBytes).toString('hex');
for(const c of oldBytes.toString('utf8').trim().split('\n').map(JSON.parse))add(c.text,`prime-geometry/${c.label}`);
const colorPath='_work/decimal_keystream_2026-09-15/carry_color/passwords.json',colorBytes=fs.readFileSync(path.join(root,colorPath));sourceFiles[colorPath]=sha(colorBytes).toString('hex');
for(const p of JSON.parse(colorBytes).passwords){const b=Buffer.from(p.preimageHex,'hex');assert.equal(sha(b).toString('hex'),p.password);add(b,`carry-color/${p.label}`);}
for(const l of [...baseLists(),...colorLists().lists])for(const reverse of [false,true])for(const separator of ['',',',' ','\n'])add((reverse?l.values.slice().reverse():l.values).join(separator),`list/${l.name}/${reverse}/${JSON.stringify(separator)}`);

const lowercase=[...Buffer.from('abcdefghijklmnopqrstuvwxyz')],lowerWithDigits=[...lowercase,...Buffer.from('0123456789 '),9,10,13];
const profiles={lowercase,lowercaseDigitsWhitespace:lowerWithDigits,lettersDigitsWhitespace:[...lowerWithDigits,...Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ')],printable:Array.from({length:128},(_,i)=>i).filter(printable)};
const plain=Buffer.from('matrixsumlistlastwordsbeforearchichoice!'),controlKey=sha(Buffer.from('matrixsumlist')),controlCipher=xor(plain,controlKey);
assert.deepEqual(xor(controlCipher,controlKey),plain);const d=domains(controlCipher,profiles.printable);assert(d.every((v,i)=>v.includes(controlKey[i])));
// Independently enumerate printable pairs for all possible pair XOR values.
for(let delta=0;delta<256;delta++) {
  const expected=profiles.printable.filter(p=>printable(p^delta)).length;
  assert.equal(domains(Buffer.from([0,...Array(31).fill(0),delta]),profiles.printable)[0].length,expected);
}
const alphabetResults=[],candidates=[];let attempts=0,sevenBit=0,fullyPrintable=0;
for(const witness of witnesses) {
  assert.equal(witness.period,32);const cipher=Buffer.from(witness.hex,'hex');assert.equal(cipher.length,38);
  const alphabet={};
  for(const [name,allowed] of Object.entries(profiles)) {
    const ds=domains(cipher,allowed);alphabet[name]={possible:ds.every(v=>v.length>0),emptyOffsets:ds.flatMap((v,i)=>v.length?[]:[i]),domainSizes:ds.map(v=>v.length)};
  }
  alphabetResults.push({reverse:witness.reverse,mask:witness.mask,alphabet});
  for(const record of keySources.values()) {
    attempts++;const key=Buffer.from(record.keyHex,'hex');
    if(![...cipher].every((v,i)=>(v>>7)===(key[i%32]>>7)))continue;
    const body=xor(cipher,key);assert([...body].every(v=>v<128));sevenBit++;if([...body].every(printable))fullyPrintable++;
    candidates.push({witness,key:record,plaintextHex:body.toString('hex'),fullyPrintable:[...body].every(printable)});
  }
}
const pass=new Map(),padding=[];
for(const c of candidates)for(const [form,b] of [['direct',Buffer.from(c.plaintextHex,'hex')],['sha256-hex',Buffer.from(sha(Buffer.from(c.plaintextHex,'hex')).toString('hex'))]])if(!pass.has(b.toString('hex')))pass.set(b.toString('hex'),{form,passwordHex:b.toString('hex')});
let aesAttempts=0;
for(const p of pass.values())for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
  aesAttempts++;const body=open(Buffer.from(p.passwordHex,'hex'),blob,digest);if(body)padding.push({passwordHex:p.passwordHex,blob:name,digest,plaintextHex:body.toString('hex')});
}
const summary={hypothesis:'Use raw SHA256 of existing matrix-derived preimages as a repeated 32-byte XOR key for surviving DBBI candidates.',
  scope:'Full 38-byte DBBI, all g=0/7 masks already restricted by exact MSB condition, original and reversed symbol order. Matrix candidate preimages reused verbatim; no arbitrary password search.',
  keys:keySources.size,witnesses:witnesses.length,keyWitnessPairs:attempts,sevenBit,fullyPrintable,aesAttempts,padding:padding.length,
  alphabetCounts:Object.fromEntries(Object.keys(profiles).map(name=>[name,alphabetResults.filter(r=>r.alphabet[name].possible).length])),
  controls:{xorRoundtrip:true,knownKeyInAllColumnDomains:true,all256PairXorValues:true},sourceFiles,witnessesSHA256:sha(witnessBytes).toString('hex'),sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex')};
fs.writeFileSync(path.join(out,'dbbi_followup.json'),JSON.stringify({summary,keys:[...keySources.values()],alphabetResults,candidates,aes:{passwords:[...pass.values()],attempts:aesAttempts,padding}},null,2)+'\n');console.log(JSON.stringify(summary,null,2));
