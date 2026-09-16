'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {vocabulary}=require('./unbounded_integer_words.cjs');
const {alphabets,digits,integer,successor,shape,search}=require('./prime_alphabet_words.cjs');
const root=path.resolve(__dirname,'..'),folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_joined_words_2026-09-16'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function machine(v) {
  const subsets=[[0]],ids=new Map([['0',0]]),distance=[0],terminal=[1],cache=new Map();
  function step(s,c) {
    const k=s*128+c;if(cache.has(k))return cache.get(k);
    const children=new Set();
    for(const node of subsets[s]){const next=v.step(node,c);if(next>=0)children.add(next);}
    if(!children.size){cache.set(k,-1);return -1;}
    if([...children].some(n=>v.terminal[n]))children.add(0);
    const row=[...children].sort((a,b)=>a-b),key=row.join(',');
    let id=ids.get(key);
    if(id===undefined){id=subsets.length;ids.set(key,id);subsets.push(row);distance.push(Math.min(...row.map(n=>v.distance[n])));terminal.push(Number(children.has(0)));}
    cache.set(k,id);return id;
  }
  function adapted(alphabet) {
    return {base:alphabet.length,alphabet,distance,terminal,step:(s,d)=>step(s,alphabet.charCodeAt(d)),
      accept:ds=>{let s=0;for(const d of ds){s=step(s,alphabet.charCodeAt(d));if(s<0)return false;}return Boolean(terminal[s]);}};
  }
  return {adapted,states:()=>subsets.length};
}
function main() {
  assert(!fs.existsSync(folder),'Choose a new destination');
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw);
  const threshold=1000000,v=vocabulary(threshold),m=machine(v);let controls=0;
  for(const alphabet of alphabets) {
    const a=m.adapted(alphabet);
    for(const text of ['matrixsumlist','lastwordsbeforearchichoice','theprimeisblue','followthewhiterabbit']) {
      // The special puzzle spelling "archichoice" is not a dictionary requirement.
      if(text.includes('archichoice'))continue;
      const n=integer([...text].map(c=>alphabet.indexOf(c)),a.base),source=[...String(n)].map(d=>String.fromCharCode(96+(+d||7))).join('');
      assert(a.accept(digits(n,a.base)));assert.equal(successor(n,a),n);
      const r=search(source,a,{maxNodes:100000,maxMs:5000});assert(r.complete);assert(r.hits.some(h=>h.text===text));controls++;
    }
  }
  const limits={maxNodes:200000,maxMs:15000};fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,'spec.json'),JSON.stringify({inputSHA256:sha(raw),corpusSHA256:v.corpusSHA256,threshold,words:v.words.size,alphabets,controls,limits,
    sourceSHA256:sha(fs.readFileSync(__filename)),searchSHA256:sha(fs.readFileSync(path.join(__dirname,'prime_alphabet_words.cjs'))),
    hypothesis:'Same whole-integer prime-radix alphabets and g=0/7 masks as prime_alphabet_words; maximal letter runs may now be concatenations of corpus words with count>=1000000, length<=32, single letters A/I. Separators/digits permitted. No unknown-name or complete natural-language claim.'},null,2)+'\n');
  const cases=[],candidates=new Map();
  for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const [alphabetId,alphabet]of alphabets.entries()) {
    const source=reverse?[...input[field]].reverse().join(''):input[field],a=m.adapted(alphabet);
    let result;
    if(field==='dbbi') {
      const {base,weights}=shape(source),hits=[];
      for(let mask=0;mask<2**weights.length;mask++) {
        const n=weights.reduce((n,w,i)=>n+((mask>>i)&1?w:0n),base),ds=digits(n,a.base);
        if(a.accept(ds))hits.push({mask:weights.map((_,i)=>(mask>>i)&1).join(''),decimal:String(n),text:ds.map(d=>alphabet[d]).join('')});
      }
      result={complete:true,method:'brute-force',assignments:2**weights.length,hits};
    }else result={...search(source,a,limits),method:'interval-successor'};
    const file=`${field}_${reverse?'reverse':'forward'}_${alphabetId}.json`,record={field,reverse,alphabetId,...result};
    fs.writeFileSync(path.join(folder,file),JSON.stringify(record)+'\n');
    for(const h of result.hits)if(!candidates.has(h.text))candidates.set(h.text,{id:candidates.size,...h,provenance:file});
    const row={...record,file,hits:result.hits.length,terminal:result.terminal?.length,sha256:sha(fs.readFileSync(path.join(folder,file)))};
    cases.push(row);console.log(JSON.stringify(row));
  }
  fs.writeFileSync(path.join(folder,'candidates.json'),JSON.stringify([...candidates.values()],null,2)+'\n');
  fs.writeFileSync(path.join(folder,'summary.json'),JSON.stringify({complete:cases.every(c=>c.complete),cases,candidates:candidates.size,dfaStates:m.states(),finalPasswordFound:false},null,2)+'\n');
}
if(require.main===module)main();
module.exports={machine};
