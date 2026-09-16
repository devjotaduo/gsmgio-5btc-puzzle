'use strict';
// Independent suffix-trie parser and modular exponentiation. No producer imports.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','rsa_color_blocks_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function gcd(a,b){return b?gcd(b,a%b):a;}
function modpow(m,e,n){let a=BigInt(m),r=1n,k=BigInt(e),mod=BigInt(n);while(k){if(k&1n)r=r*a%mod;a=a*a%mod;k>>=1n;}return Number(r);}
function prime(n){if(n<2)return false;for(let d=2;d*d<=n;d++)if(n%d===0)return false;return true;}
function trie(codes,width,padded){
  const next=[Array(10).fill(0)],byte=[0];
  for(const [m,c]of codes){let word=String(c);if(padded)word=word.padStart(width,'0');let node=0;for(let i=word.length-1;i>=0;i--){const digit=+word[i];if(!next[node][digit]){next[node][digit]=next.length;next.push(Array(10).fill(0));byte.push(0);}node=next[node][digit];}assert.equal(byte[node],0);byte[node]=m;}
  return {next,byte};
}
function parse(source,aliases,t,width){
  const count=Array(source.length+1).fill(0n),print=count.slice(),letters=count.slice();count[source.length]=print[source.length]=letters[source.length]=1n;let earliest=source.length;
  for(let end=source.length;end>=earliest;end--)if(count[end]){
    let states=[0];
    for(let len=1;len<=width&&end-len>=0;len++){
      const symbol=source[end-len],ds=[symbol.charCodeAt(0)-96];if(aliases.includes(symbol))ds.push(0);const after=[];
      for(const node of states)for(const digit of ds){const child=t.next[node][digit];if(!child)continue;after.push(child);const m=t.byte[child];if(m){const at=end-len;count[at]+=count[end];if(m>=32)print[at]+=print[end];if(m===32||m>=65&&m<=90||m>=97&&m<=122)letters[at]+=letters[end];earliest=Math.min(earliest,at);}}
      states=after;if(!states.length)break;
    }
  }
  return {all:count[0],print:print[0],letter:letters[0]};
}
function controls(){
  const allowed=[9,10,13,...Array.from({length:95},(_,i)=>i+32)];let count=0;
  for(const [p,q]of [[3,181],[37,181],[9341,181]])for(const aliases of ['g','di'])for(const padded of [false,true]){
    const n=p*q,e=65537,width=String(n-1).length,codes=allowed.map(m=>[m,modpow(m,e,n)]),text='THE MATRIX HAS YOU',digits=[...Buffer.from(text)].map(m=>{const c=modpow(m,e,n);return padded?String(c).padStart(width,'0'):String(c);}).join('');let zeros=0;const source=[...digits].map(d=>d==='0'?aliases[zeros++%aliases.length]:String.fromCharCode(96+Number(d))).join(''),r=parse(source,aliases,trie(codes,width,padded),width);assert(r.all>0n&&r.print>0n&&r.letter>0n);count++;
  }
  return count;
}
function main(){
  const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),flags=fs.readFileSync(path.join(out,'flags.bin')),validRaw=fs.readFileSync(path.join(out,'valid.jsonl')),valid=validRaw.toString().trim()?validRaw.toString().trim().split(/\r?\n/).map(JSON.parse):[];
  assert(summary.complete);assert.equal(spec.inputSHA256,sha(inputRaw));assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(__dirname,'rsa_color_blocks.cjs'))));assert.equal(summary.flagsSHA256,sha(flags));assert.equal(summary.validSHA256,sha(validRaw));
  for(const color of [spec.blue,spec.yellow]){assert.equal(parseInt(color.hex,16),color.value);assert(color.factors.every(prime));assert.equal(color.factors.reduce((a,b)=>a*b,1),color.value);}
  const expected=new Set();for(const p of new Set(spec.blue.factors))for(const q of new Set(spec.yellow.factors))if(p!==q)expected.add(p+'/'+q);assert.equal(spec.moduli.length,expected.size);
  const aliases=['',...'abcdefghi'];for(let a=0;a<9;a++)for(let b=a+1;b<9;b++)aliases.push(String.fromCharCode(97+a,97+b));const models=[];for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of aliases)for(const format of ['minimal','padded'])models.push({field,reverse,aliases:alias,format});assert.deepEqual(spec.models,models);assert.deepEqual(spec.allowed,[9,10,13,...Array.from({length:95},(_,i)=>i+32)]);
  const witnesses=new Map(valid.map(r=>[[r.keyIndex,r.modelIndex].join('/'),r])),codeHash=crypto.createHash('sha256'),calibration=controls();let offset=0,keyIndex=0,positives=0,printables=0,letterModels=0;const start=Date.now();
  for(const modulus of spec.moduli){
    assert(expected.delete(modulus.p+'/'+modulus.q));const n=modulus.p*modulus.q,lambda=(modulus.p-1)/gcd(modulus.p-1,modulus.q-1)*(modulus.q-1),width=String(n-1).length;assert.equal(n,modulus.n);assert.equal(lambda,modulus.lambda);let keys=0;
    for(let e=1;e<lambda;e++)if(gcd(e,lambda)===1){
      const codes=spec.allowed.filter(m=>m<n).map(m=>[m,modpow(m,e,n)]),raw=Buffer.alloc(8+codes.length*5);raw.writeUInt32LE(n,0);raw.writeUInt32LE(e,4);codes.forEach(([m,c],i)=>{raw[8+5*i]=m;raw.writeUInt32LE(c,9+5*i);});codeHash.update(raw);const tries={minimal:trie(codes,width,false),padded:trie(codes,width,true)};
      for(const [modelIndex,model]of models.entries()){
        const source=model.reverse?[...input[model.field]].reverse().join(''):input[model.field],r=model.format==='padded'&&source.length%width?{all:0n,print:0n,letter:0n}:parse(source,model.aliases,tries[model.format],width),flag=Number(r.all>0n)+2*Number(r.print>0n)+4*Number(r.letter>0n);assert.equal(flags[offset],flag,'Grammar decision mismatch at '+[keyIndex,modelIndex]);offset++;
        if(flag){positives++;printables+=Number(r.print>0n);letterModels+=Number(r.letter>0n);const key=[keyIndex,modelIndex].join('/'),w=witnesses.get(key);assert(w);assert.equal(w.n,n);assert.equal(w.e,e);assert.equal(w.pathsAscii,String(r.all));assert.equal(w.pathsPrintable,String(r.print));assert.equal(w.pathsLettersSpace,String(r.letter));witnesses.delete(key);}
      }
      keyIndex++;keys++;
    }
    assert.equal(keys,modulus.exponentClasses);console.log(JSON.stringify({n,keys,modelsVerified:offset,elapsedMs:Date.now()-start}));
  }
  assert.equal(expected.size,0);assert.equal(witnesses.size,0);assert.equal(offset,flags.length);assert.equal(keyIndex,summary.keys);assert.equal(positives,summary.valid);assert.equal(printables,summary.printable);assert.equal(letterModels,summary.lettersSpace);const hash=codeHash.digest('hex');assert.equal(hash,summary.codebooksSHA256);
  const result={complete:true,keys:keyIndex,models:offset,valid:positives,printable:printables,lettersSpace:letterModels,codebooksSHA256:hash,flagsSHA256:sha(flags),controls:calibration,verifierSHA256:sha(fs.readFileSync(__filename)),elapsedMs:Date.now()-start,scope:'All per-character modular-power codebooks independently recomputed with BigInt exponentiation. Every segmentation decision and positive path count checked by a reverse decimal-word trie, with independent prime-factor/domain coverage and planted messages.'};fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();
