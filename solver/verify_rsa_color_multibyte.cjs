'use strict';
// Independent right-to-left numeric parsing and BigInt modular exponentiation.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','rsa_color_multibyte_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const allowed=new Set([9,10,13,...Array.from({length:95},(_,i)=>i+32)]);
function gcd(a,b){while(b)[a,b]=[b,a%b];return a;}
function modpow(a,e,n){let r=1n,b=BigInt(a),k=BigInt(e),m=BigInt(n);while(k){if(k&1n)r=r*b%m;b=b*b%m;k>>=1n;}return Number(r);}
function inverse(a,m){let [r,s,x,y]=[m,a,0,1];while(s){const q=Math.floor(r/s);[r,s]=[s,r-q*s];[x,y]=[y,x-q*y];}assert.equal(r,1);return (x%m+m)%m;}
function bytesOf(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
function properties(n){const b=bytesOf(n),all=[...b].every(v=>allowed.has(v));return {size:b.length,mask:all?1+2*Number([...b].every(v=>v>=32))+4*Number([...b].every(v=>v===32||v>=65&&v<=90||v>=97&&v<=122)):0};}
function parse(source,aliases,n,format,lookup){
  const length=source.length,width=String(n-1).length;if(format==='padded'&&length%width)return {all:0n,print:0n,letter:0n};
  const all=Array(length+1).fill(0n),print=all.slice(),letter=all.slice(),low=new Uint16Array(length+1),high=new Uint16Array(length+1);all[length]=print[length]=letter[length]=1n;let earliest=length;
  for(let end=length;end>=earliest;end--)if(all[end]){
    let states=[0],power=1;
    for(let size=1;size<=width&&end-size>=0;size++,power*=10){
      const symbol=source[end-size],digits=[symbol.charCodeAt(0)-96];if(aliases.includes(symbol))digits.push(0);const next=[];
      for(const tail of states)for(const digit of digits){const c=tail+power*digit;if(c>=n)continue;next.push(c);if(c===0||format==='minimal'&&size>1&&digit===0||format==='padded'&&size!==width)continue;const value=lookup(c);if(!(value.mask&1))continue;const at=end-size;
        if(!all[at]){low[at]=low[end]+value.size;high[at]=high[end]+value.size;}else{low[at]=Math.min(low[at],low[end]+value.size);high[at]=Math.max(high[at],high[end]+value.size);}all[at]+=all[end];if(value.mask&2)print[at]+=print[end];if(value.mask&4)letter[at]+=letter[end];earliest=Math.min(earliest,at);
      }
      states=next;if(!states.length)break;
    }
  }
  return {all:all[0],print:print[0],letter:letter[0],min:low[0],max:high[0]};
}
function witness(source,aliases,format,text,n,e){
  assert([...text].every(v=>allowed.has(v)));const width=String(n-1).length,stack=[[0,0]],seen=new Set();
  while(stack.length){const [at,p]=stack.pop(),id=at+'/'+p;if(seen.has(id))continue;seen.add(id);if(at===source.length&&p===text.length)return true;let m=0;
    for(let size=1;size<=3&&p+size<=text.length;size++){m=256*m+text[p+size-1];if(m>=n)break;const c=modpow(m,e,n),word=format==='padded'?String(c).padStart(width,'0'):String(c);if(at+word.length>source.length)continue;let okay=true;for(let j=0;j<word.length;j++)if(word[j]==='0'?!aliases.includes(source[at+j]):+word[j]!==source.charCodeAt(at+j)-96){okay=false;break;}if(okay)stack.push([at+word.length,p+size]);}
  }
  return false;
}
function main(){
  const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),flags=fs.readFileSync(path.join(out,'flags.bin')),raw=fs.readFileSync(path.join(out,'valid.jsonl')),records=raw.toString().trim().split(/\r?\n/).map(JSON.parse),valid=new Map(records.map(r=>[[r.keyIndex,r.modelIndex].join('/'),r]));
  assert(summary.complete);assert.equal(spec.inputSHA256,sha(inputRaw));assert.equal(summary.flagsSHA256,sha(flags));assert.equal(summary.validSHA256,sha(raw));assert.equal(valid.size,records.length);for(const [file,h]of Object.entries(spec.sources))assert.equal(sha(fs.readFileSync(path.join(__dirname,file))),h);
  const previousRaw=fs.readFileSync(path.join(root,'_work','rsa_color_blocks_2026-09-16','spec.json')),previous=JSON.parse(previousRaw),previousV=JSON.parse(fs.readFileSync(path.join(root,'_work','rsa_color_blocks_2026-09-16','verification.json')));assert(previousV.complete);assert.equal(spec.previousSpecSHA256,sha(previousRaw));assert.deepEqual(spec.models,previous.models);assert.deepEqual(spec.allowed,previous.allowed);
  const counts={B:0,Y:0};for(const [,color]of input.colored)counts[color]++;assert.deepEqual(spec.colourCounts,counts);const primes=[];for(let n=2;primes.length<Math.max(counts.B,counts.Y);n++){let yes=true;for(let k=2;k*k<=n;k++)if(n%k===0){yes=false;break;}if(yes)primes.push(n);}assert.deepEqual(spec.countPrimePair,{B:primes[counts.B-1],Y:primes[counts.Y-1]});assert.equal(spec.moduli.length,previous.moduli.length+1);
  for(let i=0;i<previous.moduli.length;i++){const {family,...m}=spec.moduli[i];assert.deepEqual(m,previous.moduli[i]);}const last=spec.moduli.at(-1);assert.equal(last.p,spec.countPrimePair.B);assert.equal(last.q,spec.countPrimePair.Y);assert(Math.max(...spec.moduli.map(m=>m.n))<9*256**3);
  let offset=0,keyIndex=0,found=0,printable=0,letters=0,checkedWitnesses=0,decryptions=0;const start=Date.now(),groups=[];
  for(const mod of spec.moduli){
    const {n,p,q}=mod,lambda=(p-1)/gcd(p-1,q-1)*(q-1);assert.equal(n,p*q);assert.equal(lambda,mod.lambda);const stamp=new Uint32Array(n),mask=new Uint8Array(n),size=new Uint8Array(n);let keys=0,positives=0;
    for(let d=1;d<lambda;d++)if(gcd(d,lambda)===1){
      const tag=d+1,e=inverse(d,lambda);function lookup(c){if(stamp[c]!==tag){const r=properties(modpow(c,d,n));mask[c]=r.mask;size[c]=r.size;stamp[c]=tag;decryptions++;}return {mask:mask[c],size:size[c]};}
      for(const [modelIndex,model]of spec.models.entries()){
        const source=model.reverse?[...input[model.field]].reverse().join(''):input[model.field],r=parse(source,model.aliases,n,model.format,lookup),flag=Number(r.all>0n)+2*Number(r.print>0n)+4*Number(r.letter>0n);assert.equal(flag,flags[offset],'Decision mismatch '+keyIndex+'/'+modelIndex);offset++;
        if(flag){const id=[keyIndex,modelIndex].join('/'),w=valid.get(id);assert(w);valid.delete(id);assert.equal(w.n,n);assert.equal(w.d,d);for(const [f,value]of [['pathsAscii',r.all],['pathsPrintable',r.print],['pathsLettersSpace',r.letter]])assert.equal(w[f],String(value));assert.equal(w.minBytes,r.min);assert.equal(w.maxBytes,r.max);assert(witness(source,model.aliases,model.format,Buffer.from(w.witnessHex,'hex'),n,e));checkedWitnesses++;if(w.letterWitnessHex){assert(witness(source,model.aliases,model.format,Buffer.from(w.letterWitnessHex,'hex'),n,e));checkedWitnesses++;}found++;positives++;printable+=Number(r.print>0n);letters+=Number(r.letter>0n);}
      }
      keys++;keyIndex++;
    }
    assert.equal(keys,mod.exponentClasses);groups.push({n,keys,valid:positives});console.log(JSON.stringify({n,keys,modelsVerified:offset,valid:positives,elapsedMs:Date.now()-start}));
  }
  assert.equal(valid.size,0);assert.equal(offset,flags.length);assert.equal(keyIndex,summary.keys);assert.equal(found,summary.valid);assert.equal(printable,summary.printable);assert.equal(letters,summary.lettersSpace);
  const result={complete:true,keys:keyIndex,models:offset,valid:found,printable,lettersSpace:letters,checkedWitnesses,decryptions,groups,flagsSHA256:sha(flags),validSHA256:sha(raw),verifierSHA256:sha(fs.readFileSync(__filename)),elapsedMs:Date.now()-start,scope:'Every grammar decision, positive path count, min/max length and saved witness independently verified by reverse numeric construction, BigInt modular exponentiation, and witness re-encryption. Does not authenticate any password or claim all compatible plaintexts were tested as passwords.'};fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();
