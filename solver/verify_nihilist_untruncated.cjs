/* Independent boundary parser using the arithmetic condition
 * 22 <= sum <= 110 and sum % 10 != 1. No automaton/searcher import.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/nihilist_2026-09-16/untruncated');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const valid=n=>n>=22&&n<=110&&n%10!==1;
const seen=new Uint32Array(600),stack=new Uint16Array(600);let stamp=0;
function feasible(s,map,alias){
  stamp++;assert(stamp<0xffffffff);let top=1;stack[0]=0;seen[0]=stamp;
  while(top){
    const at=stack[--top],a=map[s[at]];if(at+1>=s.length)continue;
    for(const b of s[at+1]===alias?[map[s[at+1]],0]:[map[s[at+1]]]){
      if(valid(10*a+b)){
        const to=at+2;if(to===s.length)return true;
        if(seen[to]!==stamp){seen[to]=stamp;stack[top++]=to;}
      }
      if(a!==1||b>1||at+2>=s.length)continue;
      for(const c of s[at+2]===alias?[map[s[at+2]],0]:[map[s[at+2]]]){
        if(!valid(100+10*b+c))continue;
        const to=at+3;if(to===s.length)return true;
        if(seen[to]!==stamp){seen[to]=stamp;stack[top++]=to;}
      }
    }
  }
  return false;
}
function main(){
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(raw),savedBytes=fs.readFileSync(path.join(out,'results.json')),saved=JSON.parse(savedBytes);
  assert.equal(sha(raw),saved.inputSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver/nihilist_untruncated.cjs'))),saved.sourceSHA256);
  const sums=Array.from({length:111},(_,i)=>i).filter(valid);assert.deepEqual(saved.allowed,sums);
  let planted=0;
  for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1]])for(let alias=0;alias<9;alias++){
    const inv={};map.forEach((v,i)=>inv[v]=i);inv[0]=alias;
    const s=[...sums.map(String).join('')].map(d=>inv[d]);assert(feasible(s,map,alias));planted++;
  }
  const groups=[];
  for(const field of ['dbbi','faed'])for(const reversed of [false,true]){
    const s=[...data[field]].map(c=>c.charCodeAt(0)-97);if(reversed)s.reverse();groups.push({field,reversed,s,models:0,accepted:0});
  }
  const wanted=new Set(saved.accepted.map(r=>[r.field,r.reversed,r.mapping.join(''),r.alias].join('/'))),map=Array(9);let permutations=0,decisions=0;
  function visit(at,used){
    if(at<9){for(let v=1;v<=9;v++)if(!(used&(1<<v))){map[at]=v;visit(at+1,used|(1<<v));}return;}
    permutations++;const key=map.join('');
    for(const g of groups)for(let alias=0;alias<9;alias++){
      const yes=feasible(g.s,map,alias);assert.equal(yes,wanted.has([g.field,g.reversed,key,alias].join('/')));
      decisions++;g.models++;g.accepted+=Number(yes);
    }
  }
  visit(0,0);assert.equal(permutations,362880);assert.equal(decisions,saved.models);
  assert.equal(groups.length,saved.groups.length);
  for(let i=0;i<groups.length;i++){
    const {s,...got}=groups[i],{rejectionsByOffset,...expect}=saved.groups[i];assert.deepEqual(got,expect);
    assert.equal(rejectionsByOffset.reduce((a,b)=>a+b,0)+got.accepted,got.models);
  }
  const verification={verifiedAt:new Date().toISOString(),models:decisions,permutations,acceptedModels:groups.reduce((n,g)=>n+g.accepted,0),
    allDecisionsMatch:true,plantedControls:planted,inputSHA256:sha(raw),resultsSHA256:sha(savedBytes),verifierSHA256:sha(fs.readFileSync(__filename)),
    aesTrials:0,finalPasswordFound:false};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(verification,null,2)+'\n');console.log(JSON.stringify(verification));
}
if(require.main===module)main();
