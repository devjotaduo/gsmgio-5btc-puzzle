/* Unknown a..i -> 1..9 bijection; one symbol may independently mean zero.
 * Decode a concatenation of minimal decimal ASCII codes (TAB/LF/CR/32..126).
 * Exact grammar feasibility, not a linguistic classifier.
 * node solver/substituted_codepoints.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_codepoints_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const allowed=[9,10,13,...Array.from({length:95},(_,i)=>i+32)],allowedSet=new Set(allowed);
function automaton() {
  const words=allowed.map(String),prefixes=['',...new Set(words.flatMap(w=>Array.from({length:w.length-1},(_,i)=>w.slice(0,i+1))))];
  assert(prefixes.length<16);const count=1<<prefixes.length,single=prefixes.map(p=>Array.from({length:10},(_,d)=>{
    const next=p+d,idx=prefixes.indexOf(next);return (words.includes(next)?1:0)|(idx>=0?1<<idx:0);
  }));
  const step=Array.from({length:10},()=>new Uint16Array(count));
  for(let mask=1;mask<count;mask++) {const bit=mask&-mask,index=31-Math.clz32(bit),rest=mask^bit;for(let d=0;d<10;d++)step[d][mask]=single[index][d]|step[d][rest];}
  return {prefixes,step};
}
const dfa=automaton();
function feasible(source,map,alias,record=false) {
  let mask=1;
  for(let i=0;i<source.length;i++) {
    const s=source[i],old=mask;mask=dfa.step[map[s]][old];if(s===alias)mask|=dfa.step[0][old];
    if(!mask)return record?{accept:false,deadAt:i}:false;
  }
  return record?{accept:!!(mask&1),deadAt:-1,finalMask:mask}:!!(mask&1);
}
function eachPermutation(fn) {
  const a=[1,2,3,4,5,6,7,8,9],c=Array(9).fill(0);let index=0;fn(a,index++);
  for(let i=0;i<9;){if(c[i]<i){const j=i%2?c[i]:0;[a[j],a[i]]=[a[i],a[j]];fn(a,index++);c[i]++;i=0;}else{c[i]=0;i++;}}
  assert.equal(index,362880);
}
function encode(text,map,alias) {
  const inverse=Array(10);map.forEach((v,i)=>inverse[v]=i);inverse[0]=alias;
  return [...[...Buffer.from(text)].join('')].map(d=>inverse[Number(d)]);
}
function enumerate(source,map,alias,limit=100000,keepControls=true) {
  const characters=keepControls?allowed:allowed.filter(n=>n>=32);
  const memo=new Map(),matches=(at,w)=>at+w.length<=source.length&&[...w].every((d,j)=>Number(d)===map[source[at+j]]||(d==='0'&&source[at+j]===alias));
  function edges(at){if(memo.has(at))return memo.get(at);const r=characters.filter(n=>matches(at,String(n))).map(n=>({to:at+String(n).length,byte:n}));memo.set(at,r);return r;}
  const counts=Array(source.length+1).fill(0n);counts[source.length]=1n;
  for(let i=source.length-1;i>=0;i--)for(const e of edges(i))counts[i]+=counts[e.to];
  const texts=[];
  function visit(at,bytes){if(texts.length>=limit)return;if(at===source.length){texts.push(Buffer.from(bytes).toString('hex'));return;}for(const e of edges(at))if(counts[e.to])visit(e.to,[...bytes,e.byte]);}
  visit(0,[]);return {count:counts[0].toString(),complete:BigInt(texts.length)===counts[0],texts};
}
function controls() {
  let planted=0,bruteMasks=0;
  for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]])for(let alias=0;alias<9;alias++) {
    for(const text of ['Matrix','zero','A0\n\t!']){const source=encode(text,map,alias);assert(feasible(source,map,alias));const r=enumerate(source,map,alias);assert(r.complete&&r.texts.includes(Buffer.from(text).toString('hex')));planted++;}
    for(const source of [[alias,alias,alias],[0,alias,2,alias,8],[5,0,4,3,6,6]]){
      const r=enumerate(source,map,alias);assert(r.complete);assert.equal(feasible(source,map,alias),r.texts.length>0);bruteMasks++;
    }
  }
  const seen=new Set();eachPermutation(map=>seen.add(map.join('')));assert.equal(seen.size,362880);
  return {planted,grammarComparisons:bruteMasks,distinctPermutations:seen.size};
}
function main() {
  fs.mkdirSync(out,{recursive:true});const checked=controls(),cases=[],sources=[];
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]){let s=[...input[field]].map(c=>c.charCodeAt(0)-97);if(reverse)s.reverse();sources.push({field,reverse,source:s});}
  const hashes=sources.map(()=>Array.from({length:9},()=>crypto.createHash('sha256'))),blocks=sources.map(()=>Array.from({length:9},()=>Buffer.alloc(362880)));
  let configs=0;
  eachPermutation((map,rank)=>{
    for(const [i,s]of sources.entries())for(let alias=0;alias<9;alias++) {
      const yes=feasible(s.source,map,alias);configs++;blocks[i][alias][rank]=Number(yes);
      if(yes)cases.push({field:s.field,reverse:s.reverse,alias:String.fromCharCode(97+alias),mapping:[...map],rank});
    }
  });
  console.log(JSON.stringify({configs,acceptedModels:cases.length,stage:'feasibility complete'}));
  for(const c of cases){const s=sources.find(x=>x.field===c.field&&x.reverse===c.reverse),alias=c.alias.charCodeAt(0)-97;const all=enumerate(s.source,c.mapping,alias,0),printable=enumerate(s.source,c.mapping,alias,100000,false);Object.assign(c,{allCount:all.count,...printable});}
  const groups=[];for(const [i,s]of sources.entries())for(let alias=0;alias<9;alias++)groups.push({field:s.field,reverse:s.reverse,alias:String.fromCharCode(97+alias),models:362880,accepted:blocks[i][alias].reduce((n,b)=>n+b,0),decisionsSHA256:hashes[i][alias].update(blocks[i][alias]).digest('hex')});
  const spec={hypothesis:'All 9! bijections a..i to 1..9; every occurrence of any one chosen alias independently means zero or its mapped digit. Concatenated canonical decimal codes for TAB/LF/CR and ASCII 32..126, with no separators or leading padding zero. Entire DBBI/FAED in both symbol directions.',
    limits:'No multi-symbol zero aliases, skipped symbols, transposition, Unicode or extra cipher. Feasibility and path counts include every zero mask and segmentation. Only control-free paths (ASCII 32..126) are enumerated; their individual count and complete flag are explicit. Other TAB/LF/CR paths are counted but not enumerated or tested as passwords.',allowed,controls:checked,prefixes:dfa.prefixes,inputSHA256:sha(inputBytes),sourceSHA256:sha(fs.readFileSync(__filename)),permutationOrder:'Heap algorithm as implemented; zero-based rank'};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');fs.writeFileSync(path.join(out,'accepted.json'),JSON.stringify(cases,null,2)+'\n');
  const result={configs,groups,acceptedModels:cases.length,totalParsePaths:cases.reduce((n,c)=>n+BigInt(c.allCount),0n).toString(),totalControlFreePaths:cases.reduce((n,c)=>n+BigInt(c.count),0n).toString(),savedTexts:cases.reduce((n,c)=>n+c.texts.length,0),partialModels:cases.filter(c=>!c.complete).map(c=>({field:c.field,reverse:c.reverse,alias:c.alias,rank:c.rank,count:c.count})),acceptedSHA256:sha(fs.readFileSync(path.join(out,'accepted.json')))};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({...result,groups:groups.filter(g=>g.accepted),partialModels:result.partialModels.length}));
}
if(require.main===module)main();
module.exports={feasible,enumerate,encode};
