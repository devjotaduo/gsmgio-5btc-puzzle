/* Separate hypothesis: concatenate the ordinary decimal sums 22..110,
 * retaining all three digits of 100..110, with no delimiters or padding.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/nihilist_2026-09-16/untruncated');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const coords=Array.from({length:25},(_,i)=>10*(1+Math.floor(i/5))+i%5+1);
const allowed=[...new Set(coords.flatMap(a=>coords.map(b=>a+b)))].sort((a,b)=>a-b);
const words=allowed.map(String),prefixes=['',...new Set(words.flatMap(w=>Array.from({length:w.length-1},(_,i)=>w.slice(0,i+1))))];
assert.equal(prefixes.length,12);
const single=prefixes.map(p=>Array.from({length:10},(_,d)=>{const w=p+d,i=prefixes.indexOf(w);return(words.includes(w)?1:0)|(i<0?0:1<<i);}));
const step=Array.from({length:10},()=>new Uint16Array(1<<prefixes.length));
for(let m=1;m<step[0].length;m++){
  const bit=m&-m,index=31-Math.clz32(bit),rest=m^bit;
  for(let d=0;d<10;d++)step[d][m]=single[index][d]|step[d][rest];
}
function decide(source,map,alias){
  let mask=1;
  for(let i=0;i<source.length;i++){
    const c=source[i],old=mask;mask=step[map[c]][old];if(c===alias)mask|=step[0][old];
    if(mask===0)return i;
  }
  return mask&1?-1:source.length;
}
function encode(values,map,alias){
  const inverse={};map.forEach((v,i)=>inverse[v]=i);inverse[0]=alias;
  return [...values.join('')].map(d=>inverse[d]);
}
function controls(){
  let positives=0,negatives=0;
  for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]])for(let alias=0;alias<9;alias++){
    for(const values of [allowed,[65,55,32,75,43,65,26,108,44,34,54,79],[100,102,109,110,22,30]]){
      assert.equal(decide(encode(values,map,alias),map,alias),-1);positives++;
    }
  }
  for(const values of [[21],[101],[111],[0]]){
    const map=[1,2,3,4,5,6,7,8,9];assert.notEqual(decide(encode(values,map,6),map,6),-1);negatives++;
  }
  return {positives,negatives};
}
function main(){
  fs.mkdirSync(out,{recursive:true});
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(raw),checked=controls();
  const groups=[];
  for(const field of ['dbbi','faed'])for(const reversed of [false,true]){
    let source=[...data[field]].map(c=>c.charCodeAt(0)-97);if(reversed)source.reverse();
    groups.push({field,reversed,source,models:0,accepted:0,rejectionsByOffset:Array(source.length+1).fill(0)});
  }
  const map=[1,2,3,4,5,6,7,8,9],counts=Array(9).fill(0),accepted=[];let permutations=0;
  function test(){
    permutations++;
    for(const group of groups)for(let alias=0;alias<9;alias++){
      const result=decide(group.source,map,alias);group.models++;
      if(result===-1){group.accepted++;accepted.push({field:group.field,reversed:group.reversed,mapping:[...map],alias});}
      else group.rejectionsByOffset[result]++;
    }
  }
  test();for(let i=0;i<9;){if(counts[i]<i){const j=i%2?counts[i]:0;[map[i],map[j]]=[map[j],map[i]];test();counts[i]++;i=0;}else{counts[i]=0;i++;}}
  assert.equal(permutations,362880);
  const result={createdAt:new Date().toISOString(),hypothesis:'Concatenation of canonical decimal (untruncated) sums of two 5x5 Polybius coordinates. All 9! digit bijections; each occurrence of one of nine aliases may independently be zero. All segmentations, complete DBBI/FAED, both directions.',
    scope:'Grammar feasibility alone; any per-character key allowed. No key-period or language restriction. No leading zero, delimiters, multiple zero aliases, transposition or other square dimensions.',
    inputSHA256:sha(raw),sourceSHA256:sha(fs.readFileSync(__filename)),allowed,prefixes,controls:checked,permutations,
    groups:groups.map(({source,...rest})=>rest),accepted,models:groups.reduce((n,g)=>n+g.models,0),aesTrials:0,finalPasswordFound:false};
  fs.writeFileSync(path.join(out,'results.json'),JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify({models:result.models,accepted:accepted.length,controls:checked,groups:result.groups.map(({rejectionsByOffset,...g})=>g)}));
}
if(require.main===module)main();
