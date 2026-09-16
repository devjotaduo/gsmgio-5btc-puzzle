/* Reconstruct key collection; calculate every XOR body without the MSB gate.
 * Independently intersect possible key-byte sets for the alphabet conditions.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','xor_period_2026-09-15'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fileBytes=fs.readFileSync(path.join(out,'dbbi_followup.json')),saved=JSON.parse(fileBytes),witnessBytes=fs.readFileSync(path.join(out,'witnesses.json')),witnesses=JSON.parse(witnessBytes);
assert.equal(sha(witnessBytes),saved.summary.witnessesSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','xor_dbbi_followup.cjs'))),saved.summary.sourceSHA256);
const keys=new Map();function add(b){const raw=Buffer.from(b);keys.set(sha(raw),raw.toString('hex'));}
for(const [name,hash] of Object.entries(saved.summary.sourceFiles))assert.equal(sha(fs.readFileSync(path.join(root,name))),hash);
for(const c of fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','candidates.jsonl'),'utf8').trim().split('\n').map(JSON.parse))add(c.text);
const colors=JSON.parse(fs.readFileSync(path.join(root,'_work','decimal_keystream_2026-09-15','carry_color','passwords.json')));
for(const p of colors.passwords){const b=Buffer.from(p.preimageHex,'hex');assert.equal(sha(b),p.password);add(b);}
const prior=JSON.parse(fs.readFileSync(path.join(root,'_work','decimal_keystream_2026-09-15','carry_color','spec.json')));
for(const l of prior.lists)for(const reverse of [false,true])for(const separator of ['',',',' ','\n'])add((reverse?l.values.slice().reverse():l.values).join(separator));
assert.equal(keys.size,saved.keys.length);assert.equal(keys.size,saved.summary.keys);
for(const k of saved.keys){assert.equal(sha(Buffer.from(k.preimageHex,'hex')),k.keyHex);assert.equal(keys.get(k.keyHex),k.preimageHex);}
let pairs=0,sevenBit=0;
for(const w of witnesses)for(const hex of keys.keys()) {
  const c=Buffer.from(w.hex,'hex'),key=Buffer.from(hex,'hex'),body=Buffer.alloc(c.length);
  for(let i=0;i<c.length;i++)body[i]=c[i]^key[i%32];pairs++;if(body.every(v=>v<128))sevenBit++;
}
assert.equal(pairs,saved.summary.keyWitnessPairs);assert.equal(sevenBit,0);assert.equal(sevenBit,saved.summary.sevenBit);assert.deepEqual(saved.candidates,[]);assert.deepEqual(saved.aes,{passwords:[],attempts:0,padding:[]});
const low='abcdefghijklmnopqrstuvwxyz',extra='0123456789 \t\n\r';
const alphabets={lowercase:[...Buffer.from(low)],lowercaseDigitsWhitespace:[...Buffer.from(low+extra)],lettersDigitsWhitespace:[...Buffer.from(low+extra+low.toUpperCase())],printable:[9,10,13,...Array.from({length:95},(_,i)=>32+i)]},counts={};
let alphabetChecks=0;
for(const w of witnesses) {
  const c=Buffer.from(w.hex,'hex'),row=saved.alphabetResults.find(r=>r.mask===w.mask&&r.reverse===w.reverse);assert(row);
  for(const [name,alphabet] of Object.entries(alphabets)) {
    const sizes=[],empty=[];
    for(let offset=0;offset<32;offset++) {
      let possible=null;
      for(let i=offset;i<c.length;i+=32) {
        const candidates=new Set(alphabet.map(p=>c[i]^p));possible=possible===null?candidates:new Set([...possible].filter(k=>candidates.has(k)));
      }
      sizes.push(possible.size);if(possible.size===0)empty.push(offset);
    }
    assert.deepEqual(row.alphabet[name],{possible:empty.length===0,emptyOffsets:empty,domainSizes:sizes});counts[name]=(counts[name]??0)+Number(empty.length===0);alphabetChecks++;
  }
}
assert.deepEqual(counts,saved.summary.alphabetCounts);
const result={keys:keys.size,witnesses:witnesses.length,pairs,sevenBit,alphabetChecks,alphabetCounts:counts,allKeySourcesReconstructed:true,allDirectXorResultsMatched:true,allAlphabetIntersectionsMatched:true,resultSHA256:sha(fileBytes),verifierSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(out,'dbbi_followup_verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
