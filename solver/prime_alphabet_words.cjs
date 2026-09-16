'use strict';
// Whole decimal integer -> prime-radix alphabet -> explicit word grammar.
// Dictionary compatibility is not evidence of an authenticated decryption.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {vocabulary}=require('./unbounded_integer_words.cjs');
const root=path.resolve(__dirname,'..'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const alphabets=[' abcdefghijklmnopqrstuvwxyz.,','abcdefghijklmnopqrstuvwxyz .,',
  " abcdefghijklmnopqrstuvwxyz.,-'","abcdefghijklmnopqrstuvwxyz .,-'",
  ' abcdefghijklmnopqrstuvwxyz0123456789','0123456789abcdefghijklmnopqrstuvwxyz '];
function digits(n,base) {
  const b=BigInt(base),result=[];
  do {result.push(Number(n%b));n/=b;}while(n);
  return result.reverse();
}
function integer(ds,base) {return ds.reduce((n,d)=>n*BigInt(base)+BigInt(d),0n);}
function adapter(v,alphabet) {
  assert([29,31,37].includes(alphabet.length));assert.equal(new Set(alphabet).size,alphabet.length);
  return {base:alphabet.length,alphabet,distance:v.distance,terminal:v.terminal,
    step:(s,d)=>v.step(s,alphabet.charCodeAt(d)),
    accept:ds=>v.accept(Buffer.from(ds.map(d=>alphabet[d]).join('')))};
}
function successor(n,a) {
  const ds=digits(n,a.base),states=[0],length=ds.length;let failed=length;
  for(let i=0;i<length;i++) {
    const state=a.step(states[i],ds[i]);
    if(state<0||a.distance[state]>length-i-1){failed=i;break;}
    states.push(state);
  }
  if(failed===length)return n;
  function fill(prefix,state,wanted) {
    const out=prefix.slice();
    while(out.length<wanted) {
      const pos=out.length;let chosen=false;
      for(let d=pos===0&&wanted>1?1:0;d<a.base;d++) {
        const next=a.step(state,d);
        if(next<0||a.distance[next]>wanted-pos-1)continue;
        out.push(d);state=next;chosen=true;break;
      }
      assert(chosen);
    }
    assert(a.terminal[state]);return integer(out,a.base);
  }
  for(let i=failed;i>=0;i--)for(let d=ds[i]+1;d<a.base;d++) {
    const state=a.step(states[i],d);
    if(state<0||a.distance[state]>length-i-1)continue;
    return fill([...ds.slice(0,i),d],state,length);
  }
  return fill([],0,length+1);
}
function shape(source) {
  const base=BigInt([...source].map(c=>c==='g'?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c==='g'?[7n*10n**BigInt(source.length-1-i)]:[]);
  const tail=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tail[i]=tail[i+1]+weights[i];
  return {base,weights,tail};
}
function search(source,a,limits={maxNodes:500000,maxMs:15000}) {
  const {base,weights,tail}=shape(source),terminal=[],hits=[];
  let nodes=0,excluded=0n,pending=0n;const start=Date.now();
  function walk(lo,mask) {
    const amount=1n<<BigInt(weights.length-mask.length);
    if(nodes>=limits.maxNodes||Date.now()-start>=limits.maxMs) {
      terminal.push({mask,status:'pending'});pending+=amount;return;
    }
    nodes++;
    if(successor(lo,a)>lo+tail[mask.length]) {
      terminal.push({mask,status:'excluded'});excluded+=amount;return;
    }
    if(mask.length===weights.length) {
      const ds=digits(lo,a.base);assert(a.accept(ds));
      terminal.push({mask,status:'hit'});hits.push({mask,decimal:String(lo),text:ds.map(d=>a.alphabet[d]).join('')});return;
    }
    walk(lo,mask+'0');walk(lo+weights[mask.length],mask+'1');
  }
  walk(base,'');const total=1n<<BigInt(weights.length);
  assert.equal(excluded+pending+BigInt(hits.length),total);
  return {complete:pending===0n,nodes,total:String(total),excluded:String(excluded),pending:String(pending),terminal,hits,elapsedMs:Date.now()-start};
}
function controls(v) {
  let successors=0,planted=0,bruteCases=0;
  for(const alphabet of alphabets) {
    const a=adapter(v,alphabet),limit=a.base**3,accepted=[];
    for(let n=0;n<=limit*2;n++)if(a.accept(digits(BigInt(n),a.base)))accepted.push(BigInt(n));
    let at=0;
    for(let n=0;n<limit;n+=17) {
      while(accepted[at]<BigInt(n))at++;
      assert.equal(successor(BigInt(n),a),accepted[at]);successors++;
    }
    for(const text of ['the matrix has you','follow the white rabbit','the answer is here']) {
      const n=integer([...text].map(c=>alphabet.indexOf(c)),a.base),decimal=String(n);
      const source=[...decimal].map(d=>String.fromCharCode(96+(+d||7))).join('');
      const result=search(source,a,{maxNodes:200000,maxMs:5000});
      assert(result.complete);assert(result.hits.some(h=>h.text===text));planted++;
    }
    for(const src of ['ggbg','abcgg','ggggg','faedgg']) {
      const {base,weights}=shape(src),wanted=[];
      for(let mask=0;mask<2**weights.length;mask++) {
        const n=weights.reduce((n,w,i)=>n+((mask>>i)&1?w:0n),base);
        if(a.accept(digits(n,a.base)))wanted.push(String(n));
      }
      const actual=search(src,a);assert(actual.complete);
      assert.deepEqual(actual.hits.map(h=>h.decimal).sort(),wanted.sort());bruteCases++;
    }
  }
  return {successors,planted,bruteCases};
}
function main() {
  const folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_alphabet_words_2026-09-16'));
  assert(!fs.existsSync(folder),'Choose a fresh destination');
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw),v=vocabulary(0);
  const checked=controls(v),limits={maxNodes:500000,maxMs:15000};
  fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,'spec.json'),JSON.stringify({inputSHA256:sha(raw),corpusSHA256:v.corpusSHA256,words:v.words.size,
    alphabets,limits,controls:checked,sourceSHA256:sha(fs.readFileSync(__filename)),vocabularyLoaderSHA256:sha(fs.readFileSync(path.join(__dirname,'unbounded_integer_words.cjs'))),
    hypothesis:'a1..i9, each g independently 0/7. Full decimal integer represented in prime base29/31/37; digits index one of six stated alphabets. Both fields, both source directions. Each maximal run of letters must be a corpus word of length<=32; single letters only A/I. Nonletters separate words; strings containing only nonletters are admitted.',
    limitations:'A language-filtered conditional model, not confirmed by creator. Does not cover other zero aliases, alphabets, omitted leading radix-zero characters, joined words, missing words/names, typos, other languages or further ciphers. Pending states are explicitly incomplete.'},null,2)+'\n');
  const cases=[],candidates=new Map();
  for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const [alphabetId,alphabet]of alphabets.entries()) {
    const source=reverse?[...input[field]].reverse().join(''):input[field],result=search(source,adapter(v,alphabet),limits);
    const name=`${field}_${reverse?'reverse':'forward'}_${alphabetId}.json`,record={field,reverse,alphabetId,...result};
    fs.writeFileSync(path.join(folder,name),JSON.stringify(record)+'\n');
    for(const h of result.hits)if(!candidates.has(h.text))candidates.set(h.text,{id:candidates.size,...h,provenance:name});
    const row={...record,file:name,terminal:result.terminal.length,hits:result.hits.length,sha256:sha(fs.readFileSync(path.join(folder,name)))};
    cases.push(row);console.log(JSON.stringify(row));
  }
  fs.writeFileSync(path.join(folder,'candidates.json'),JSON.stringify([...candidates.values()],null,2)+'\n');
  const summary={complete:cases.every(c=>c.complete),cases,candidates:candidates.size,finalPasswordFound:false};
  fs.writeFileSync(path.join(folder,'summary.json'),JSON.stringify(summary,null,2)+'\n');
  console.log(JSON.stringify({complete:summary.complete,cases:cases.length,candidates:candidates.size}));
}
if(require.main===module)main();
module.exports={alphabets,digits,integer,adapter,successor,shape,search};
