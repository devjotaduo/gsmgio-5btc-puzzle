'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextUtf8,bytesOf}=require('./utf8_decimal_constraints.cjs');
const {domains,keysFromLists}=require('./decimal_keystream_constraints.cjs');
const folder=path.resolve(__dirname,'../_work/zero_cells_prime_sums_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const mod=(a,m)=>(a%m+m)%m;
const pow=Array.from({length:601},(_,i)=>10n**BigInt(i));
function prepare(source,key,mode,family){
  const ds=family==='digits'?domains(source,key,mode):[...source].map(ch=>ch==='g'?[0,7]:[ch.charCodeAt(0)-96]);
  const low=BigInt(ds.map(d=>d[0]).join('')),weights=ds.flatMap((d,i)=>d.length===2?[BigInt(d[1]-d[0])*pow[source.length-1-i]]:[]);
  const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  const K=BigInt(Array.from({length:source.length},(_,i)=>key[i%key.length]).join('')),M=pow[source.length];
  function ranges(lo,hi){
    if(family==='digits')return [[lo,hi]];
    const a=mod(mode==='subtract'?lo-K:mode==='add'?lo+K:K-hi,M),b=a+hi-lo;
    return b<M?[[a,b]]:[[a,M-1n],[0n,b-M]];
  }
  return {low,weights,tails,ranges};
}
function search(source,key,mode,family,order,{maxNodes=200000,maxMs=1500}={}){
  const d=prepare(source,key,mode,family),certificates=[],hits=[],pending=[];let nodes=0,excluded=0n;const start=Date.now();
  function visit(i,lo,mask){
    if(nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}nodes++;
    const ranges=d.ranges(lo,lo+d.tails[i]);
    if(ranges.every(([a,b])=>nextUtf8(a,order)>b)){certificates.push(mask);excluded+=1n<<BigInt(d.weights.length-i);return;}
    if(i===d.weights.length){assert.equal(ranges.length,1);const n=ranges[0][0],bytes=bytesOf(n);if(order==='little')bytes.reverse();const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);hits.push({mask,decimal:String(n),hex:bytes.toString('hex'),text});return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+d.weights[i],mask+'1');
  }
  visit(0,d.low,'');const remain=pending.reduce((s,m)=>s+(1n<<BigInt(d.weights.length-m.length)),0n);
  assert.equal(excluded+BigInt(hits.length)+remain,1n<<BigInt(d.weights.length));
  return {ambiguous:d.weights.length,nodes,complete:pending.length===0,certificates,hits,pending};
}
function controls(){
  let brute=0,planted=0;
  for(const family of ['digits','carry'])for(const mode of ['subtract','add','beaufort'])for(const order of ['big','little']){
    const key=[7,4,0,9];
    for(const source of ['ggbg','faegdg','gggggg']){
      const d=prepare(source,key,mode,family),expected=[];
      for(let mask=0;mask<2**d.weights.length;mask++){
        let n=d.low;d.weights.forEach((w,j)=>{if(mask&(1<<j))n+=w;});n=d.ranges(n,n)[0][0];const b=bytesOf(n);if(order==='little')b.reverse();
        try{new TextDecoder('utf-8',{fatal:true}).decode(b);expected.push(String(n));}catch{}
      }
      const r=search(source,key,mode,family,order);assert(r.complete);assert.deepEqual(r.hits.map(h=>h.decimal).sort(),expected.sort());brute++;
    }
    const b=Buffer.from('Olá, matrix 🔑');if(order==='little')b.reverse();const n=BigInt('0x'+b.toString('hex')),decimal=String(n),M=pow[decimal.length];let cipher;
    if(family==='digits')cipher=[...decimal].map((d,i)=>mod(BigInt(mode==='subtract'?Number(d)+key[i%key.length]:mode==='add'?Number(d)-key[i%key.length]:key[i%key.length]-Number(d)),10n).toString()).join('');
    else{const K=BigInt(Array.from({length:decimal.length},(_,i)=>key[i%key.length]).join(''));cipher=String(mod(mode==='subtract'?n+K:mode==='add'?n-K:K-n,M)).padStart(decimal.length,'0');}
    const source=[...cipher].map(d=>String.fromCharCode(96+(Number(d)||7))).join(''),r=search(source,key,mode,family,order);
    assert(r.complete&&r.hits.some(h=>h.decimal===decimal));planted++;
  }
  return {brute,planted};
}
function main(){
  assert(!fs.existsSync(path.join(folder,'stream_spec.json')),'Inspect existing stream search before rerunning');
  const sourceRaw=fs.readFileSync(path.resolve(__dirname,'../_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(sourceRaw),raw=fs.readFileSync(path.join(folder,'matrices.json')),matrices=JSON.parse(raw);
  const lists=matrices.flatMap(m=>['rows','columns'].map(axis=>({name:m.id+'/'+axis,values:m[axis]}))),keys=keysFromLists(lists),checked=controls();
  const spec={hypothesis:'Use each complete14-value row/column sum list from the56 DBBI-filled matrices as a repeated decimal key for FAED. Residues modulo10 or concatenated decimal digits, either direction, every cyclic alignment. Invert addition/subtraction/Beaufort digitwise modulo10 or whole-integer modulo10^L. Every FAED g independently0/7, all other letters1..9. Complete original/reversed FAED; minimal bytes BE/LE must be strict UTF8, controls allowed. No language classifier, dropped bytes or arbitrary key fitting.',lists,keys,controls:checked,limits:{maxNodes:200000,maxMs:1500},matricesSHA256:sha(raw),inputSHA256:sha(sourceRaw),sourceSHA256:sha(fs.readFileSync(__filename)),dependencies:Object.fromEntries(['utf8_decimal_constraints.cjs','decimal_keystream_constraints.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))]))};
  fs.writeFileSync(path.join(folder,'stream_spec.json'),JSON.stringify(spec,null,2)+'\n');
  const fd=fs.openSync(path.join(folder,'stream_cases.jsonl'),'wx'),partial=[],candidates=[];let count=0,nodes=0,certificates=0;
  console.log(JSON.stringify({keys:keys.length,expectedCases:keys.length*24,controls:checked}));
  for(const reverse of [false,true]){
    const source=reverse?[...input.faed].reverse().join(''):input.faed;
    for(const [key,k]of keys.entries())for(const family of ['digits','carry'])for(const mode of ['subtract','add','beaufort'])for(const order of ['big','little']){
      const r={id:count,reverse,key,family,mode,order,...search(source,k.values,mode,family,order)};count++;nodes+=r.nodes;certificates+=r.certificates.length;
      fs.writeSync(fd,JSON.stringify(r)+'\n');if(!r.complete)partial.push(r.id);for(const h of r.hits)candidates.push({case:r.id,...h});
      if(count%10000===0)console.log(JSON.stringify({cases:count,nodes,candidates:candidates.length,partial:partial.length}));
    }
  }
  fs.closeSync(fd);
  const summary={complete:partial.length===0,cases:count,keys:keys.length,nodes,certificates,candidates,partial,casesSHA256:sha(fs.readFileSync(path.join(folder,'stream_cases.jsonl'))),specSHA256:sha(fs.readFileSync(path.join(folder,'stream_spec.json')))};
  fs.writeFileSync(path.join(folder,'stream_summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({...summary,candidates:candidates.length}));
}
if(require.main===module)main();module.exports={prepare,search,controls};
