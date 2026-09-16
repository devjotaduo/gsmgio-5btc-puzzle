/* Exhaustive direct Morbit (9!) and Pollux (3^9) maps for DBBI and FAED.
 * node solver/morse_endgame.cjs
 * Morse grammar only filters candidates; only subsequent evidence can solve.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','morse_2026-09-15');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const codes={A:'.-',B:'-...',C:'-.-.',D:'-..',E:'.',F:'..-.',G:'--.',H:'....',I:'..',J:'.---',K:'-.-',L:'.-..',M:'--',N:'-.',O:'---',P:'.--.',Q:'--.-',R:'.-.',S:'...',T:'-',U:'..-',V:'...-',W:'.--',X:'-..-',Y:'-.--',Z:'--..',
  '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
  '.':'.-.-.-',',':'--..--','?':'..--..',"'":'.----.','!':'-.-.--','/':'-..-.','(':'-.--.',')':'-.--.-','&':'.-...',':':'---...',';':'-.-.-','=':'-...-','+':'.-.-.','-':'-....-','_':'..--.-','"':'.-..-.','$':'...-..-','@':'.--.-.'};
const prefix=new Set([1]),letters=new Map();
for(const [letter,code] of Object.entries(codes)) {
  let n=1;for(const ch of code){n=n*2+(ch==='-'?1:0);prefix.add(n);}assert(!letters.has(n));letters.set(n,letter);
}
const pairs=Array.from({length:9},(_,i)=>[Math.floor(i/3),i%3]);
function decode(source,map,morbit) {
  let current=1,separators=0,text='',leading=0;
  for(const index of source) {
    const symbols=morbit?pairs[map[index]]:[map[index]];
    for(const bit of symbols) {
      if(bit===2) {
        if(current!==1) {
          const letter=letters.get(current);if(letter===undefined)return null;
          text+=letter;current=1;separators=1;
        } else {
          separators++;if(separators>2)return null;
          if(text.length===0)leading++;else if(separators===2)text+=' ';
        }
      } else {
        current=current*2+bit;separators=0;if(!prefix.has(current))return null;
      }
    }
  }
  if(current!==1){const letter=letters.get(current);if(letter===undefined)return null;text+=letter;}
  if(!text.trim())return null;
  return {text:text.trim(),leadingSeparators:leading};
}
function morbitEncode(text,map) {
  let stream=text.toUpperCase().split(' ').map(word=>[...word].map(c=>codes[c]).join('x')).join('xx');
  if(stream.length%2)stream+='x';
  const inverse=Array(9);map.forEach((v,i)=>{inverse[v]=i;});
  const digits=[...stream].map(c=>c==='.'?0:c==='-'?1:2),result=[];
  for(let i=0;i<digits.length;i+=2)result.push(inverse[digits[i]*3+digits[i+1]]);
  return result;
}
function controls() {
  const rank=[9,5,8,4,2,7,1,3,6],map=Array(9);rank.forEach((r,i)=>{map[r-1]=i;});
  assert.equal(decode([...'27435881512827465679378'].map(c=>Number(c)-1),map,true).text,'ONCE UPON A TIME');
  const pm=[0,2,1,0,0,2,0,1,1,2];
  assert.equal(decode([...'086393425702417685963041456234908745360'].map(Number),pm,false).text,'LUCK HELPS');
  let roundTrips=0;
  const plain='MATRIX SUMLIST 127 BLUE YELLOW THE PASSWORD IS IN FRONT OF YOUR EYES';
  for(let rotation=0;rotation<9;rotation++)for(const reversed of [false,true]) {
    let m=Array.from({length:9},(_,i)=>(i+rotation)%9);if(reversed)m.reverse();
    assert.equal(decode(morbitEncode(plain,m),m,true).text,plain);roundTrips++;
  }
  assert.equal(decode([0,0,0],[2],false),null);
  assert.equal(decode(Array(8).fill(0),[0],false),null);
  return {acaMorbit:true,acaPollux:true,morbitRoundTrips:roundTrips,invalidSeparatorsAndLongRunRejected:true};
}
function main() {
  const checked=controls(),sources=[];
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    let s=[...input[field]].map(c=>c.charCodeAt(0)-97);if(reverse)s.reverse();sources.push({field,reverse,s});
  }
  const candidates=[],counts={morbit:0,pollux:0};
  function trial(map,morbit) {
    const method=morbit?'morbit':'pollux';counts[method]++;
    for(const source of sources) {
      const result=decode(source.s,map,morbit);
      if(result)candidates.push({method,field:source.field,reverse:source.reverse,mapping:[...map],...result});
    }
  }
  function permutations(map,used){if(map.length===9){trial(map,true);return;}for(let n=0;n<9;n++)if(!(used&(1<<n)))permutations([...map,n],used|(1<<n));}
  permutations([],0);
  for(let n=0;n<3**9;n++){let k=n;const map=[];for(let i=0;i<9;i++){map.push(k%3);k=Math.floor(k/3);}trial(map,false);}
  assert.equal(counts.morbit,362880);assert.equal(counts.pollux,19683);
  fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');
  const passwords=new Map();
  for(const c of candidates)for(const text of new Set([c.text,c.text.toLowerCase(),c.text.replaceAll(' ',''),c.text.replaceAll(' ','').toLowerCase()]))for(const [form,pw] of [['direct',text],['sha256-hex',sha(text)]]) {
    if(!passwords.has(pw))passwords.set(pw,{password:pw,form,preimage:text,source:c});
  }
  const raw=Buffer.from(input.phase32_control_b64,'base64'),control={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
  assert(open(Buffer.from(input.phase32_control_password),control,'sha256').toString().startsWith("I've been waiting for you."));
  const padding=[];let attempts=0;
  for(const p of passwords.values())for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    attempts++;const body=open(Buffer.from(p.password),blob,digest);if(!body)continue;
    padding.push({password:p.password,blob:name,kdf:digest,plaintextHex:body.toString('hex'),printable:[...body].filter(b=>(b>=32&&b<127)||[9,10,13].includes(b)).length/body.length});
  }
  fs.writeFileSync(path.join(out,'passwords.json'),JSON.stringify([...passwords.values()],null,2)+'\n');
  fs.writeFileSync(path.join(out,'padding.json'),JSON.stringify(padding,null,2)+'\n');
  const summary={hypothesis:'Direct Morbit or Pollux over a..i, no extra transposition or keystream. Entire source, original or reversed. Standard single/double separators, optional <=2 leading/trailing separators; A-Z, 0-9 and declared punctuation.',
    sourceURLs:['https://www.cryptogram.org/downloads/aca.info/ciphers/Morbit.pdf','https://www.cryptogram.org/downloads/aca.info/ciphers/Pollux.pdf'],
    controls:checked,sourceSHA256:sha(fs.readFileSync(__filename)),fieldHashes:{dbbi:sha(input.dbbi),faed:sha(input.faed)},codeTable:codes,
    maps:counts,fullDecodingAttempts:(counts.morbit+counts.pollux)*4,candidates:candidates.length,passwords:passwords.size,aesAttempts:attempts,paddings:padding.length,maxPrintable:Math.max(0,...padding.map(x=>x.printable)),
    candidateCounts:Object.fromEntries(sources.flatMap(s=>['morbit','pollux'].map(method=>[`${method}/${s.field}/${s.reverse}`,candidates.filter(c=>c.method===method&&c.field===s.field&&c.reverse===s.reverse).length])))};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');
  console.log(JSON.stringify({...summary,codeTable:undefined,previews:candidates.slice(0,8)},null,2));
}
if(require.main===module)main();
module.exports={decode,morbitEncode,codes};
