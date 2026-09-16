/* All assignments of a..i to bit 0, bit 1, or deletion (3^9).
 * Decode full retained streams as 7/8-bit text or 5-bit Bacon alphabets.
 * Only zero trailing padding shorter than one code unit is permitted.
 * node solver/binary_partition_endgame.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','binary_partition_2026-09-15');
const data=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const alphabets={bacon26:'ABCDEFGHIJKLMNOPQRSTUVWXYZ',bacon24:'ABCDEFGHIKLMNOPQRSTUWXYZ'};
assert.equal(alphabets.bacon24.length,24);
const formats=[{name:'ascii7',width:7},{name:'ascii8',width:8},{name:'bacon26',width:5},{name:'bacon24',width:5}];
function decode(bits,format,lsb=false) {
  const tail=bits.length%format.width;
  if(tail&&bits.slice(bits.length-tail).some(b=>b!==0))return null;
  const values=[];
  for(let i=0;i+format.width<=bits.length;i+=format.width) {
    let n=0;for(let j=0;j<format.width;j++)n=n*2+bits[i+(lsb?format.width-j-1:j)];
    if(format.name.startsWith('ascii')){if(!((n>=32&&n<=126)||[9,10,13].includes(n)))return null;values.push(n);}
    else{if(n>=alphabets[format.name].length)return null;values.push(alphabets[format.name].charCodeAt(n));}
  }
  return {hex:Buffer.from(values).toString('hex'),paddingBits:tail};
}
function control() {
  let checks=0;
  for(const f of formats)for(const lsb of [false,true]) {
    const text='THISPASSWORD',bits=[...text].flatMap(c=>{
      const n=f.name.startsWith('ascii')?c.charCodeAt(0):alphabets[f.name].indexOf(c);
      const b=[...n.toString(2).padStart(f.width,'0')].map(Number);return lsb?b.reverse():b;
    });
    assert.equal(Buffer.from(decode(bits,f,lsb).hex,'hex').toString(),text);
    const map=[0,0,0,1,1,1,2,2,2],encoded=[];
    bits.forEach((b,i)=>{encoded.push(b*3+(i%3));if(i%4===0)encoded.push(6+i%3);});
    assert.deepEqual(encoded.map(x=>map[x]).filter(x=>x!==2),bits);
    assert.equal(Buffer.from(decode([...bits,0],f,lsb).hex,'hex').toString(),text);
    assert.equal(decode([...bits,1],f,lsb),null);checks++;
  }
  return {formatAndHomophoneControls:checks};
}
function main() {
  const controls=control(),candidates=new Map(),countByMode={};let tests=0,grammatical=0;
  const sources=[];for(const field of ['dbbi','faed'])for(const reverse of [false,true]){let s=[...data[field]].map(c=>c.charCodeAt(0)-97);if(reverse)s.reverse();sources.push({field,reverse,s});}
  for(let n=0;n<3**9;n++) {
    let k=n;const map=[];for(let i=0;i<9;i++){map.push(k%3);k=Math.floor(k/3);}
    for(const s of sources) {
      const bits=s.s.map(i=>map[i]).filter(b=>b!==2);
      for(const f of formats)for(const lsb of [false,true]) {
        tests++;const decoded=decode(bits,f,lsb);if(!decoded)continue;grammatical++;
        const label=`${s.field}/${s.reverse}/${f.name}/${lsb}`;countByMode[label]=(countByMode[label]||0)+1;
        if(!candidates.has(decoded.hex))candidates.set(decoded.hex,{field:s.field,reverse:s.reverse,format:f.name,lsb,mapping:map,paddingBits:decoded.paddingBits,hex:decoded.hex});
      }
    }
  }
  fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify([...candidates.values()],null,2)+'\n');
  const passwords=new Map();
  for(const c of candidates.values()) {
    const raw=Buffer.from(c.hex,'hex');
    for(const material of [raw,Buffer.from(raw.toString('ascii').toLowerCase())])for(const [form,pw] of [['direct',material],['sha256-hex',Buffer.from(sha(material))]]) {
      const h=pw.toString('hex');if(!passwords.has(h))passwords.set(h,{passwordHex:h,form,preimageHex:material.toString('hex'),candidate:c});
    }
  }
  const raw=Buffer.from(data.phase32_control_b64,'base64'),controlBlob={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
  assert(open(Buffer.from(data.phase32_control_password),controlBlob,'sha256').toString().startsWith("I've been waiting for you."));
  const padding=[];let attempts=0;
  for(const p of passwords.values())for(const [name,blob] of Object.entries(data.blobs))for(const digest of ['sha256','md5']) {
    attempts++;const body=open(Buffer.from(p.passwordHex,'hex'),blob,digest);if(!body)continue;
    padding.push({passwordHex:p.passwordHex,blob:name,kdf:digest,plaintextHex:body.toString('hex'),printable:[...body].filter(b=>(b>=32&&b<127)||[9,10,13].includes(b)).length/body.length});
  }
  fs.writeFileSync(path.join(out,'passwords.json'),JSON.stringify([...passwords.values()],null,2)+'\n');
  fs.writeFileSync(path.join(out,'padding.json'),JSON.stringify(padding,null,2)+'\n');
  const summary={hypothesis:'Every symbol has one fixed label 0,1,or deletion. Entire retained sequence, both directions, both bit endiannesses, 7/8-bit printable ASCII+TAB/LF/CR or specified 5-bit Bacon alphabet. Optional zero tail shorter than one code unit.',
    maps:3**9,decodings:tests,grammarAcceptances:grammatical,distinctCandidates:candidates.size,passwords:passwords.size,aesAttempts:attempts,padding:padding.length,maxPrintable:Math.max(0,...padding.map(x=>x.printable)),controls,countByMode,sourceSHA256:sha(fs.readFileSync(__filename)),fieldHashes:{dbbi:sha(data.dbbi),faed:sha(data.faed)}};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');
  console.log(JSON.stringify({...summary,previews:[...candidates.values()].slice(0,8).map(c=>({field:c.field,format:c.format,text:Buffer.from(c.hex,'hex').toString()}))},null,2));
}
if(require.main===module)main();
module.exports={decode,formats,alphabets};
