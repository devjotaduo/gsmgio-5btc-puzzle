'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {eachPermutation}=require('./substituted_decimal_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','ebcdic_decimal_2026-09-16','codepoints'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw);
const tableRaw=fs.readFileSync(path.join(out,'..','encoding.json')),table=JSON.parse(tableRaw.toString('utf8').replace(/^\uFEFF/,''));
const allowed=table.decoded.flatMap((c,i)=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126||[9,10,13].includes(c.charCodeAt(0))?[i]:[]);
function automaton(padded){
  const words=allowed.map(n=>padded?String(n).padStart(3,'0'):String(n));
  const prefixes=['',...new Set(words.flatMap(w=>Array.from({length:w.length-1},(_,i)=>w.slice(0,i+1))))];assert(prefixes.length<31);
  const single=prefixes.map(p=>Array.from({length:10},(_,d)=>{const w=p+d,index=prefixes.indexOf(w);return (words.includes(w)?1:0)|(index>=0?1<<index:0);}));
  const cache=Array.from({length:10},()=>new Map([[0,0]]));
  function step(mask,d){if(cache[d].has(mask))return cache[d].get(mask);let value=0;for(let m=mask;m;m&=m-1)value|=single[31-Math.clz32(m&-m)][d];cache[d].set(mask,value);return value;}
  return {words,prefixes,step,cache};
}
const machines=[automaton(false),automaton(true)];
function feasible(source,map,aliasMask,padded){
  const m=machines[Number(padded)];let mask=1;
  for(const s of source){const old=mask;mask=m.step(old,map[s]);if(aliasMask&(1<<s))mask|=m.step(old,0);if(!mask)return false;}
  return !!(mask&1);
}
function enumerate(source,map,aliasMask,padded,limit=100000){
  const words=machines[Number(padded)].words,edges=Array.from({length:source.length},()=>[]),count=Array(source.length+1).fill(0n);count[source.length]=1n;
  for(let i=source.length-1;i>=0;i--)for(let j=0;j<words.length;j++){
    const w=words[j];if(i+w.length>source.length)continue;
    if([...w].every((d,k)=>Number(d)===map[source[i+k]]||d==='0'&&(aliasMask&(1<<source[i+k])))){
      edges[i].push({to:i+w.length,byte:allowed[j]});count[i]+=count[i+w.length];
    }
  }
  const texts=[];
  function visit(at,bs){if(texts.length>=limit)return;if(at===source.length){texts.push(Buffer.from(bs).toString('hex'));return;}for(const e of edges[at])if(count[e.to])visit(e.to,[...bs,e.byte]);}
  visit(0,[]);return {count:count[0].toString(),complete:BigInt(texts.length)===count[0],texts};
}
function encode(text,map,alias,padded){
  const inverse=Array(10);map.forEach((v,i)=>inverse[v]=i);inverse[0]=alias;
  return [...[...text].map(c=>{const n=table.decoded.indexOf(c);assert(n>=0);return padded?String(n).padStart(3,'0'):String(n);}).join('')].map(c=>inverse[Number(c)]);
}
function controls(){
  let planted=0,grammar=0;
  for(const padded of [false,true])for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]])for(let alias=0;alias<9;alias++){
    for(const text of ['Matrix','zero','A0\n\t!']){const source=encode(text,map,alias,padded);assert(feasible(source,map,1<<alias,padded));const r=enumerate(source,map,1<<alias,padded);const h=Buffer.from([...text].map(c=>table.decoded.indexOf(c))).toString('hex');assert(r.complete&&r.texts.includes(h));planted++;}
    for(const source of [[alias,alias,alias],[0,alias,2,alias,8],[5,0,4,3,6,6]]){const r=enumerate(source,map,1<<alias,padded);assert(r.complete);assert.equal(feasible(source,map,1<<alias,padded),r.texts.length>0);grammar++;}
  }
  return {planted,grammarComparisons:grammar};
}
function main(){
  fs.mkdirSync(out,{recursive:true});const checked=controls();console.log(JSON.stringify({controls:checked}));
  const spec={hypothesis:'Entire original/reversed DBBI and FAED encode concatenated decimal byte values of EBCDIC 1141 text. Byte codes are either canonical decimal or uniformly padded to exactly three digits. Repertoire: ASCII 32..126 plus TAB LF CR.',families:['All 9! bijections to 1..9, one letter independently zero or assigned digit','a=1..i=9, zero to two letters independently zero or assigned digit'],scope:'No other padding widths, separators, skipped symbols, transpositions, Unicode or additional cipher.',allowed,controls:checked,inputSHA256:sha(inputRaw),tableSHA256:sha(tableRaw),sourceSHA256:sha(fs.readFileSync(__filename)),permutationHelperSHA256:sha(fs.readFileSync(path.join(__dirname,'substituted_decimal_constraints.cjs')))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  const result={groups:[],cases:0,accepted:[],partial:[]},aliasSets=['',...'abcdefghi'];for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)aliasSets.push(String.fromCharCode(97+i,97+j));
  function run(family,field,reverse,aliases,padded){
    const source=[...(reverse?[...input[field]].reverse().join(''):input[field])].map(c=>c.charCodeAt(0)-97),aliasMask=[...aliases].reduce((m,c)=>m|1<<(c.charCodeAt(0)-97),0),started=Date.now();let cases=0,accepted=0;
    function one(map){cases++;if(!feasible(source,map,aliasMask,padded))return;accepted++;const r=enumerate(source,map,aliasMask,padded);const c={family,field,reverse,aliases,padded,mapping:map.join(''),...r};result.accepted.push(c);if(!r.complete)result.partial.push({...c,texts:undefined});}
    if(family==='fixed')one([1,2,3,4,5,6,7,8,9]);else eachPermutation(one);
    result.groups.push({family,field,reverse,aliases,padded,cases,accepted,elapsedMs:Date.now()-started});result.cases+=cases;
    if(family!=='fixed')console.log(JSON.stringify(result.groups.at(-1)));
    fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n');
  }
  for(const padded of [false,true])for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const aliases of aliasSets)run('fixed',field,reverse,aliases,padded);
  for(const padded of [false,true])for(const aliases of 'abcdefghi')for(const field of ['dbbi','faed'])for(const reverse of [false,true])run('substituted',field,reverse,aliases,padded);
  result.complete=result.partial.length===0;result.savedTexts=result.accepted.reduce((n,c)=>n+c.texts.length,0);result.totalPaths=result.accepted.reduce((n,c)=>n+BigInt(c.count),0n).toString();
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({complete:result.complete,cases:result.cases,accepted:result.accepted.length,texts:result.savedTexts,totalPaths:result.totalPaths}));
}
if(require.main===module)main();module.exports={feasible,enumerate,encode,allowed};
