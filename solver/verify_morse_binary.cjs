/* Independent string-based Morse and binary verification, all AES attempts,
 * and public-key checks on hashes and all raw 32-byte plaintext windows.
 * node solver/verify_morse_binary.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const md=path.join(root,'_work','morse_2026-09-15'),bd=path.join(root,'_work','binary_partition_2026-09-15');
const read=(dir,file)=>JSON.parse(fs.readFileSync(path.join(dir,file))),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const ms=read(md,'summary.json'),morse=new Map(Object.entries(ms.codeTable).map(([letter,code])=>[code,letter]));
const expectedMorse=new Map(read(md,'candidates.json').map(c=>[[c.method,c.field,c.reverse,c.mapping.join('')].join('/'),c.text]));
const sources=[];for(const field of ['dbbi','faed'])for(const reverse of [false,true]){let s=[...input[field]].map(c=>c.charCodeAt(0)-97);if(reverse)s.reverse();sources.push({field,reverse,s});}
function splitMorse(stream) {
  if(stream.includes('xxx'))return null;
  stream=stream.replace(/^x{1,2}|x{1,2}$/g,'');if(!stream)return null;
  const words=[];
  for(const word of stream.split('xx')) {
    let text='';for(const code of word.split('x')){if(!morse.has(code))return null;text+=morse.get(code);}words.push(text);
  }
  return words.join(' ');
}
const pairs=['..','.-','.x','-.','--','-x','x.','x-','xx'];let morseChecks=0,morseHits=0;
function testMorse(map,method) {
  const table=method==='morbit'?map.map(i=>pairs[i]):map.map(i=>'.-x'[i]);
  for(const s of sources) {
    const result=splitMorse(s.s.map(c=>table[c]).join('')),id=[method,s.field,s.reverse,map.join('')].join('/');
    assert.equal(result,expectedMorse.get(id)??null);morseChecks++;if(result!==null)morseHits++;
  }
}
// Heap permutations, different from the searcher's recursive construction.
const perm=Array.from({length:9},(_,i)=>i),counters=Array(9).fill(0);testMorse(perm,'morbit');
for(let i=0;i<9;) {
  if(counters[i]<i){const j=i%2?counters[i]:0;[perm[j],perm[i]]=[perm[i],perm[j]];testMorse(perm,'morbit');counters[i]++;i=0;}
  else{counters[i]=0;i++;}
}
for(let i=0;i<3**9;i++)testMorse(Array.from({length:9},(_,j)=>Math.floor(i/(3**j))%3),'pollux');
assert.equal(morseChecks,ms.fullDecodingAttempts);assert.equal(morseHits,expectedMorse.size);
console.log(JSON.stringify({morseChecks,morseHits}));

const bs=read(bd,'summary.json'),binaryCandidates=read(bd,'candidates.json'),expectedBinary=new Set(binaryCandidates.map(c=>c.hex));
const foundBinary=new Set();let binaryChecks=0,binaryHits=0;
const alphabets={bacon26:'ABCDEFGHIJKLMNOPQRSTUVWXYZ',bacon24:'ABCDEFGHIKLMNOPQRSTUWXYZ'};
for(let n=0;n<3**9;n++) {
  const map=Array.from({length:9},(_,i)=>['0','1',''][Math.floor(n/(3**i))%3]);
  for(const s of sources) {
    const bits=s.s.map(c=>map[c]).join('');
    for(const [name,width] of [['ascii7',7],['ascii8',8],['bacon26',5],['bacon24',5]])for(const lsb of [false,true]) {
      binaryChecks++;const length=bits.length-bits.length%width;
      if(bits.slice(length).includes('1'))continue;
      const values=[];let valid=true;
      for(let i=0;i<length;i+=width) {
        let b=bits.slice(i,i+width);if(lsb)b=[...b].reverse().join('');const v=parseInt(b,2);
        if(name.startsWith('ascii')){if(!((v>=32&&v<=126)||v===9||v===10||v===13)){valid=false;break;}values.push(v);}
        else{if(v>=alphabets[name].length){valid=false;break;}values.push(alphabets[name].charCodeAt(v));}
      }
      if(valid){const h=Buffer.from(values).toString('hex');assert(expectedBinary.has(h));foundBinary.add(h);binaryHits++;}
    }
  }
}
assert.equal(binaryChecks,bs.decodings);assert.equal(binaryHits,bs.grammarAcceptances);assert.deepEqual([...foundBinary].sort(),[...expectedBinary].sort());
console.log(JSON.stringify({binaryChecks,binaryHits,distinct:foundBinary.size}));

function decrypt(password,blob,digest) {
  const salt=Buffer.from(blob.salt,'hex');let prev=Buffer.alloc(0),material=Buffer.alloc(0);
  while(material.length<48){prev=crypto.createHash(digest).update(Buffer.concat([prev,password,salt])).digest();material=Buffer.concat([material,prev]);}
  const aes=crypto.createDecipheriv('aes-256-cbc',material.subarray(0,32),material.subarray(32,48));aes.setAutoPadding(false);
  const plain=Buffer.concat([aes.update(Buffer.from(blob.ciphertext,'hex')),aes.final()]),pad=plain.at(-1);
  if(pad<1||pad>16||!plain.subarray(-pad).every(b=>b===pad))return null;
  return plain.subarray(0,plain.length-pad).toString('hex');
}
const raw=Buffer.from(input.phase32_control_b64,'base64');
assert(Buffer.from(decrypt(Buffer.from(input.phase32_control_password),{salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')},'sha256'),'hex').toString().startsWith("I've been waiting for you."));
let aesChecks=0,paddingChecks=0;const passwordKeys=new Set(),bodies=[];
for(const [dir,isMorse] of [[md,true],[bd,false]]) {
  const saved=read(dir,'padding.json'),byId=new Map(saved.map(p=>[[(isMorse?Buffer.from(p.password).toString('hex'):p.passwordHex),p.blob,p.kdf].join('/'),p.plaintextHex]));
  assert.equal(byId.size,saved.length);
  for(const p of read(dir,'passwords.json')) {
    const pw=isMorse?Buffer.from(p.password):Buffer.from(p.passwordHex,'hex');
    const preimage=isMorse?Buffer.from(p.preimage):Buffer.from(p.preimageHex,'hex');
    assert.equal(pw.toString('hex'),(p.form==='direct'?preimage:Buffer.from(sha(preimage))).toString('hex'));
    if(p.form==='sha256-hex')passwordKeys.add(pw.toString());
    if(preimage.length===32)passwordKeys.add(preimage.toString('hex'));
    for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
      const plain=decrypt(pw,blob,digest),id=[pw.toString('hex'),name,digest].join('/');
      assert.equal(plain,byId.get(id)??null);aesChecks++;
      if(plain!==null){paddingChecks++;bodies.push({label:id,hex:plain});}
    }
  }
}
console.log(JSON.stringify({aesChecks,paddingChecks,passwordKeyCandidates:passwordKeys.size}));
const target=Buffer.from(input.target_pubkey,'hex').subarray(1,33).toString('hex'),keyHits=[];
let keyChecks=0;
function checkKey(key,label) {
  if(key.length!==32)return;
  const ec=crypto.createECDH('secp256k1');try{ec.setPrivateKey(key);}catch{return;}
  keyChecks++;const pub=ec.getPublicKey('hex','compressed');
  if(pub.slice(2)===target)keyHits.push({label,keyHex:key.toString('hex'),compressedPublicKey:pub});
}
const one=crypto.createECDH('secp256k1');one.setPrivateKey(Buffer.from('1'.padStart(64,'0'),'hex'));
assert.equal(one.getPublicKey('hex','compressed'),'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
for(const hex of passwordKeys)checkKey(Buffer.from(hex,'hex'),'candidate-hash-or-raw');
for(let j=0;j<bodies.length;j++) {
  const body=Buffer.from(bodies[j].hex,'hex');
  for(let i=0;i+32<=body.length;i++)checkKey(body.subarray(i,i+32),`${bodies[j].label}/${i}`);
  for(const m of body.toString('latin1').matchAll(/[0-9a-fA-F]{64}/g))checkKey(Buffer.from(m[0],'hex'),`${bodies[j].label}/hex`);
  if(j%400===0)console.log(JSON.stringify({checkedBodies:j,keyChecks,keyHits:keyHits.length}));
}
const result={morseChecks,morseHits,binaryChecks,binaryHits,distinctBinaryCandidates:foundBinary.size,aesChecks,paddingChecks,keyChecks,keyHits,
  scope:'Full independent re-enumeration and decryption. Key scan: SHA256 candidate preimages, raw 32-byte candidate preimages, every 32-byte big-endian padded-output window, and 64-hex runs; compares target x-coordinate to include the negated key. No other key derivations claimed.',
  verifierSHA256:sha(fs.readFileSync(__filename)),allPassed:true};
fs.writeFileSync(path.join(bd,'independent_verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
