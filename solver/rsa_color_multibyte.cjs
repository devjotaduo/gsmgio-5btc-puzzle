'use strict';
// Necessary plaintext grammar for modular-power blocks of variable byte lengths.
// A relaxation of fixed byte blocks and a shorter final block; no plaintext NULs.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {graphs,pow,allowed}=require('./rsa_color_blocks.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','rsa_color_multibyte_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex'),allowedSet=new Set(allowed);
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),previousSpec=JSON.parse(fs.readFileSync(path.join(root,'_work','rsa_color_blocks_2026-09-16','spec.json')));
function gcd(a,b){while(b)[a,b]=[b,a%b];return a;}
function minBytes(n){const b=[];do{b.push(n%256);n=Math.floor(n/256);}while(n);return Buffer.from(b.reverse());}
function classify(n){const b=minBytes(n);if(![...b].every(v=>allowedSet.has(v)))return 0;return 1+2*Number([...b].every(v=>v>=32))+4*Number([...b].every(v=>v===32||v>=65&&v<=90||v>=97&&v<=122));}
function workspace(length){return {all:Array(length+1).fill(0n),print:Array(length+1).fill(0n),letter:Array(length+1).fill(0n),min:new Uint16Array(length+1),max:new Uint16Array(length+1),parent:new Uint16Array(length+1),value:new Uint32Array(length+1),parentLetter:new Uint16Array(length+1),valueLetter:new Uint32Array(length+1)};}
function parse(graph,length,decrypt,w){
  const touched=[0];w.all[0]=w.print[0]=w.letter[0]=1n;w.min[0]=w.max[0]=0;let furthest=0;
  for(let at=0;at<=furthest&&at<length;at++)if(w.all[at])for(let k=graph.heads[at];k<graph.heads[at+1];k+=2){
    const end=graph.edges[k],c=graph.edges[k+1],{mask,m}=decrypt(c);if(!(mask&1))continue;const lengthBytes=m<256?1:m<65536?2:3;
    if(!w.all[end]){touched.push(end);w.min[end]=w.min[at]+lengthBytes;w.max[end]=w.max[at]+lengthBytes;w.parent[end]=at;w.value[end]=m;}else {w.min[end]=Math.min(w.min[end],w.min[at]+lengthBytes);w.max[end]=Math.max(w.max[end],w.max[at]+lengthBytes);}
    w.all[end]+=w.all[at];if(mask&2)w.print[end]+=w.print[at];if(mask&4&&w.letter[at]){if(!w.letter[end]){w.parentLetter[end]=at;w.valueLetter[end]=m;}w.letter[end]+=w.letter[at];}furthest=Math.max(furthest,end);
  }
  let r=null;if(w.all[length]){
    function witness(letter){let at=length;const words=[];while(at){words.push(minBytes(letter?w.valueLetter[at]:w.value[at]));at=letter?w.parentLetter[at]:w.parent[at];}return Buffer.concat(words.reverse()).toString('hex');}
    r={pathsAscii:String(w.all[length]),pathsPrintable:String(w.print[length]),pathsLettersSpace:String(w.letter[length]),minBytes:w.min[length],maxBytes:w.max[length],witnessHex:witness(false),letterWitnessHex:w.letter[length]?witness(true):null};
  }
  for(const at of touched)w.all[at]=w.print[at]=w.letter[at]=0n;return r;
}
function inverses(e,n){for(let k=1;k<n;k++)if(e*k%n===1)return k;throw Error('Not invertible');}
function controls(){let count=0;for(const size of [1,2,3])for(const format of ['minimal','padded'])for(const aliases of ['g','be']){
  const p=9341,q=181,n=p*q,lambda=84060,e=65537,d=inverses(e,lambda),text=Buffer.from(size===3?'\tAB\nCD\rEF':'THE MATRIX HAS YOU'),width=String(n-1).length,cipher=[];
  for(let i=0;i<text.length;i+=size){const word=text.subarray(i,i+size);let m=0;for(const v of word)m=256*m+v;assert(m<n);cipher.push(pow(m,e,n));}
  const digits=cipher.map(v=>format==='padded'?String(v).padStart(width,'0'):String(v)).join('');let zero=0;const source=[...digits].map(v=>v==='0'?aliases[zero++%aliases.length]:String.fromCharCode(96+Number(v))).join(''),g=graphs(source,aliases,n),r=parse(g[format],source.length,c=>{const m=pow(c,d,n);return {m,mask:classify(m)};},workspace(source.length));assert(r);for(let i=0;i<cipher.length;i++)assert.equal(minBytes(pow(cipher[i],d,n)).toString('hex'),text.subarray(i*size,(i+1)*size).toString('hex'));count++;
  }return count;
}
function main(){
  fs.mkdirSync(out,{recursive:true});assert(!fs.existsSync(path.join(out,'flags.bin'))&&!fs.existsSync(path.join(out,'valid.jsonl')),'Existing results: inspect before restarting');const counts={B:0,Y:0};for(const [,color]of input.colored)counts[color]++;const primes=[];for(let v=2;primes.length<Math.max(counts.B,counts.Y);v++)if(!primes.some(p=>p*p<=v&&v%p===0))primes.push(v);
  const moduli=previousSpec.moduli.map(m=>({...m,family:'RGB prime factors'})),p=primes[counts.B-1],q=primes[counts.Y-1],lambda=(p-1)*(q-1)/gcd(p-1,q-1);moduli.push({p,q,n:p*q,lambda,exponentClasses:Array.from({length:lambda-1},(_,i)=>i+1).filter(e=>gcd(e,lambda)===1).length,family:'Prime ordinals of colour counts'});
  const models=previousSpec.models,checked=controls(),spec={scope:'Each modular-power plaintext integer becomes its MINIMAL bytes, all in TAB/LF/CR/ASCII 32..126. Block sizes may vary freely. Thus this includes any fixed 1/2/3-byte plaintext blocks and a shorter final block that fit the modulus. The selected moduli cannot hold a 4-byte integer whose first byte is in this repertoire. Byte-order feasibility is unchanged by reversal of each block. Same source/cipher-decimal/zero-alias models as the previous one-character campaign. Includes even-prime moduli and identity exponent classes as relaxations; not PKCS#1/OAEP, NUL padding, arbitrary moduli or different digit alphabets.',moduli,colourCounts:counts,countPrimePair:{B:p,Y:q},models,allowed,controls:checked,inputSHA256:sha(inputRaw),previousSpecSHA256:sha(fs.readFileSync(path.join(root,'_work','rsa_color_blocks_2026-09-16','spec.json'))),sources:Object.fromEntries(['rsa_color_multibyte.cjs','rsa_color_blocks.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))])),flags:'Ascending decryption exponents d coprime to lambda, modulus order as listed, then models as listed. Bits 0/1/2 indicate any ASCII/printable/letters-space path.'};fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');fs.writeFileSync(path.join(out,'valid.jsonl'),'');
  const totalKeys=moduli.reduce((s,m)=>s+m.exponentClasses,0),flags=Buffer.alloc(totalKeys*models.length),work=new Map(),groups=[];let offset=0,keyIndex=0,valid=0,printable=0,letter=0,decryptions=0;const start=Date.now();
  for(const mod of moduli){
    const {n,lambda}=mod,width=String(n-1).length,stamp=new Uint32Array(n),values=new Uint32Array(n),classes=new Uint8Array(n),cache=new Map(),prepared=models.map(model=>{const id=[model.field,model.reverse,model.aliases].join('/'),source=model.reverse?[...input[model.field]].reverse().join(''):input[model.field];if(!cache.has(id))cache.set(id,graphs(source,model.aliases,n));if(!work.has(source.length))work.set(source.length,workspace(source.length));return {source,graph:cache.get(id)[model.format]};});let groupValid=0,groupPrint=0,groupLetter=0,keys=0;
    for(let d=1;d<lambda;d++)if(gcd(d,lambda)===1){
      const tag=d+1;function decrypt(c){if(stamp[c]!==tag){const m=pow(c,d,n);values[c]=m;classes[c]=classify(m);stamp[c]=tag;decryptions++;}return {m:values[c],mask:classes[c]};}
      for(const [modelIndex,model]of models.entries()){
        const {source,graph}=prepared[modelIndex],r=model.format==='padded'&&source.length%width?null:parse(graph,source.length,decrypt,work.get(source.length));
        if(r){const fp=BigInt(r.pathsPrintable)>0n,fl=BigInt(r.pathsLettersSpace)>0n;flags[offset]=1+2*Number(fp)+4*Number(fl);valid++;groupValid++;printable+=Number(fp);groupPrint+=Number(fp);letter+=Number(fl);groupLetter+=Number(fl);fs.appendFileSync(path.join(out,'valid.jsonl'),JSON.stringify({keyIndex,modelIndex,p:mod.p,q:mod.q,n,lambda,d,family:mod.family,...model,...r})+'\n');}offset++;
      }
      keyIndex++;keys++;
    }
    const group={n,p:mod.p,q:mod.q,family:mod.family,keys,models:keys*models.length,valid:groupValid,printable:groupPrint,lettersSpace:groupLetter};groups.push(group);console.log(JSON.stringify({...group,elapsedMs:Date.now()-start}));
  }
  assert.equal(keyIndex,totalKeys);assert.equal(offset,flags.length);fs.writeFileSync(path.join(out,'flags.bin'),flags);const summary={complete:true,keys:keyIndex,models:offset,valid,printable,lettersSpace:letter,decryptions,groups,elapsedMs:Date.now()-start,flagsSHA256:sha(flags),validSHA256:sha(fs.readFileSync(path.join(out,'valid.jsonl')))};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}
if(require.main===module)main();module.exports={parse,workspace,classify,minBytes};
