/* Independently verify complete interval certificates using a counting
 * formula, then recheck ALL AES attempts using an independent CBC path.
 * node solver/verify_decimal_keystream.cjs
 * Does not import any search or decryption code from the experiments.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','decimal_keystream_2026-09-15');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const powers128=[1n],powers10=[1n];for(let i=1;i<=600;i++){powers128.push(powers128[i-1]*128n);powers10.push(powers10[i-1]*10n);}
function count(n) {
  if(n<0n)return 0n;
  const h=n.toString(16),digits=Buffer.from(h.length%2?'0'+h:h,'hex');let total=0n;
  for(let i=0;i<digits.length;i++){total+=BigInt(Math.min(digits[i],128))*powers128[digits.length-i-1];if(digits[i]>127)return total;}
  return total+1n;
}
let expected=0n;for(let n=0;n<65536;n++){if((n&255)<128&&(n>>8)<128)expected++;assert.equal(count(BigInt(n)),expected);}
for(let i=1;i<=300;i++)assert.equal(count(256n**BigInt(i)-1n),128n**BigInt(i));
const mod=(x,n)=>((x%n)+n)%n;
const summary={controls:{integerCounts:65536,largeWidths:300},families:{}};
for(const family of ['digits','carry_color']) {
  const dir=family==='digits'?out:path.join(out,family),spec=JSON.parse(fs.readFileSync(path.join(dir,'spec.json')));
  const keys=new Map(spec.keys.map(k=>[k.id,k.values]));assert.equal(keys.size,spec.keys.length);
  const casesBytes=fs.readFileSync(path.join(dir,'cases.jsonl')),records=casesBytes.toString('utf8').trim().split('\n').map(JSON.parse);
  const ids=new Set();let certificates=0;
  for(const r of records) {
    assert(r.complete&&r.hits.length===0&&r.pending.length===0);
    assert(['dbbi','faed'].includes(r.field)&&typeof r.reverse==='boolean');
    assert(['subtract','add','beaufort'].includes(r.mode));
    const key=keys.get(r.key);assert(key&&key.join('')===r.key);
    const id=[r.field,r.reverse,r.key,r.mode].join('/');assert(!ids.has(id));ids.add(id);
    const s=r.reverse?[...input[r.field]].reverse().join(''):input[r.field],length=s.length;
    const sets=[...s].map((c,i)=>{
      const values=c==='g'?[0,7]:[c.charCodeAt(0)-96];if(family!=='digits')return values;
      return values.map(v=>Number(mod(BigInt(r.mode==='subtract'?v-key[i%key.length]:r.mode==='add'?v+key[i%key.length]:key[i%key.length]-v),10n))).sort((a,b)=>a-b);
    });
    const low=BigInt(sets.map(x=>x[0]).join('')),weights=sets.flatMap((v,i)=>v.length===2?[BigInt(v[1]-v[0])*powers10[length-i-1]]:[]);
    const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
    assert.equal(r.ambiguous,weights.length);
    const m=powers10[length],K=BigInt(Array.from({length},(_,i)=>key[i%key.length]).join(''));
    let coverage=0n;const prefixes=[];
    for(const mask of r.certificates) {
      assert.match(mask,/^[01]*$/);assert(mask.length<=weights.length);
      assert(!prefixes.some(p=>p.startsWith(mask)||mask.startsWith(p)));prefixes.push(mask);
      let a=low;for(let i=0;i<mask.length;i++)if(mask[i]==='1')a+=weights[i];const b=a+tails[mask.length];
      if(family==='digits')assert.equal(count(b)-count(a-1n),0n);
      else {
        const lower=r.mode==='subtract'?a-K:r.mode==='add'?a+K:K-b;
        const upper=r.mode==='subtract'?b-K:r.mode==='add'?b+K:K-a;
        // Split at multiples of the modulus, using floor division even for
        // negative endpoints, not the searcher's cyclic-interval function.
        const qlo=(lower-mod(lower,m))/m,qhi=(upper-mod(upper,m))/m;
        for(let q=qlo;q<=qhi;q++) {
          const l=lower>q*m?lower:q*m,u=upper<(q+1n)*m-1n?upper:(q+1n)*m-1n;
          assert.equal(count(u-q*m)-count(l-q*m-1n),0n);
        }
      }
      coverage+=1n<<BigInt(weights.length-mask.length);certificates++;
    }
    assert.equal(coverage,1n<<BigInt(weights.length));
  }
  assert.equal(ids.size,keys.size*2*2*3);
  summary.families[family]={cases:ids.size,certificates,allExcluded:true,casesSHA256:sha(casesBytes)};
  console.log(JSON.stringify({family,...summary.families[family]}));
}
function decrypt(pw,blob,digest) {
  const salt=Buffer.from(blob.salt,'hex');let previous=Buffer.alloc(0),material=Buffer.alloc(0);
  while(material.length<48){previous=crypto.createHash(digest).update(Buffer.concat([previous,pw,salt])).digest();material=Buffer.concat([material,previous]);}
  const dec=crypto.createDecipheriv('aes-256-cbc',material.subarray(0,32),material.subarray(32,48));dec.setAutoPadding(false);
  const p=Buffer.concat([dec.update(Buffer.from(blob.ciphertext,'hex')),dec.final()]),pad=p.at(-1);
  if(pad<1||pad>16||!p.subarray(p.length-pad).every(b=>b===pad))return null;
  return p.subarray(0,p.length-pad).toString('hex');
}
const raw=Buffer.from(input.phase32_control_b64,'base64'),control={salt:raw.subarray(8,16).toString('hex'),ciphertext:raw.subarray(16).toString('hex')};
assert(Buffer.from(decrypt(Buffer.from(input.phase32_control_password),control,'sha256'),'hex').toString().startsWith("I've been waiting for you."));
const pass=JSON.parse(fs.readFileSync(path.join(out,'carry_color','passwords.json'))).passwords;
const aes=JSON.parse(fs.readFileSync(path.join(out,'carry_color','aes.json')));
const byId=new Map(aes.padding.map(p=>[[p.password,p.blob,p.kdf].join('/'),p.plaintextHex]));assert.equal(byId.size,aes.padding.length);
let attempts=0,paddings=0;
for(const p of pass) {
  assert.equal(sha(Buffer.from(p.preimageHex,'hex')),p.password);
  for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    const plain=decrypt(Buffer.from(p.password),blob,digest),id=[p.password,name,digest].join('/');
    assert.equal(plain,byId.get(id)??null);attempts++;if(plain!==null)paddings++;
  }
}
assert.equal(attempts,aes.attempts);assert.equal(paddings,aes.padding.length);
summary.aes={attempts,paddings,allSuccessesAndFailuresMatched:true,phase32Control:true};
summary.verifierSHA256=sha(fs.readFileSync(__filename));
fs.writeFileSync(path.join(out,'independent_verification.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
