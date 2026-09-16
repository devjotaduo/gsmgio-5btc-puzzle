/* Independent token-boundary decoder. Enumerates permutations lexicographically,
 * uses direct decimal code arithmetic, and never imports the NFA/searcher.
 * node solver/verify_substituted_codepoints.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_codepoints_2026-09-16'),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
function tokenEdges(s,map,alias,at,emit) {
  const a=map[s[at]];if(a===9)emit(at+1,9);
  if(at+1>=s.length)return;
  const seconds=s[at+1]===alias?[map[s[at+1]],0]:[map[s[at+1]]];
  for(const b of seconds) {
    const n=10*a+b;if(n===10||n===13||n>=32&&n<=99)emit(at+2,n);
    if(a!==1||b>2||at+2>=s.length)continue;
    const thirds=s[at+2]===alias?[map[s[at+2]],0]:[map[s[at+2]]];
    for(const c of thirds){const m=100+10*b+c;if(m<=126)emit(at+3,m);}
  }
}
const tags=new Uint32Array(600),stack=new Uint16Array(600);let stamp=0;
function canParse(s,map,alias) {
  stamp++;assert(stamp<0xffffffff);let top=1,yes=false;stack[0]=0;tags[0]=stamp;
  while(top&&!yes) {
    const at=stack[--top];
    tokenEdges(s,map,alias,at,(to)=>{if(to===s.length){yes=true;return;}if(tags[to]!==stamp){tags[to]=stamp;stack[top++]=to;}});
  }
  return yes;
}
const isLetter=c=>c>=65&&c<=90||c>=97&&c<=122;
function countShapes(s,map,alias) {
  const all=Array(s.length+1).fill(0n),noControl=[...all],letterSpace=[...all],minCost=Array(s.length+1).fill(Infinity),choice=Array(s.length);
  all[s.length]=noControl[s.length]=letterSpace[s.length]=1n;minCost[s.length]=0;
  for(let at=s.length-1;at>=0;at--)tokenEdges(s,map,alias,at,(to,c)=>{
    all[at]+=all[to];if(c>=32)noControl[at]+=noControl[to];if(isLetter(c)||c===32)letterSpace[at]+=letterSpace[to];
    const cost=minCost[to]+Number(!isLetter(c)&&c!==32);if(cost<minCost[at]){minCost[at]=cost;choice[at]={to,c};}
  });
  let at=0,bytes=[];while(at<s.length&&choice[at]){const e=choice[at];bytes.push(e.c);at=e.to;}
  return {all:all[0].toString(),noControl:noControl[0].toString(),lettersAndSpace:letterSpace[0].toString(),minimumOtherCharacters:minCost[0],leastOtherTextHex:at===s.length?Buffer.from(bytes).toString('hex'):null};
}
function permutationWalk(fn) {
  const map=Array(9);let count=0;
  function fill(at,used){if(at===9){fn(map);count++;return;}for(let v=1;v<=9;v++)if(!(used&(1<<v))){map[at]=v;fill(at+1,used|(1<<v));}}
  fill(0,0);assert.equal(count,362880);
}
function controls() {
  let positive=0;
  for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]])for(let alias=0;alias<9;alias++)for(const text of ['Matrix','A0\n\t!','last words before archichoice']) {
    const inverse={};map.forEach((v,i)=>inverse[v]=i);inverse[0]=alias;
    const source=[...[...Buffer.from(text)].map(c=>String(c)).join('')].map(d=>inverse[d]);
    assert(canParse(source,map,alias));assert(BigInt(countShapes(source,map,alias).all)>0n);positive++;
  }
  return {knownMessages:positive};
}
function main() {
  const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),acceptedBytes=fs.readFileSync(path.join(out,'accepted.json')),accepted=JSON.parse(acceptedBytes);
  assert.equal(sha(inputBytes),spec.inputSHA256);assert.equal(sha(acceptedBytes),summary.acceptedSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','substituted_codepoints.cjs'))),spec.sourceSHA256);
  const checked=controls(),sources=[];
  for(const field of ['dbbi','faed'])for(const reverse of [false,true]){const source=[...input[field]].map(c=>c.charCodeAt(0)-97);if(reverse)source.reverse();sources.push({field,reverse,source});}
  const expected=new Set(accepted.map(c=>[c.field,c.reverse,c.alias,c.mapping.join('')].join('/')));assert.equal(expected.size,accepted.length);
  let decisions=0,passing=0;
  permutationWalk(map=>{const mapping=map.join('');for(const s of sources)for(let alias=0;alias<9;alias++) {
    const yes=canParse(s.source,map,alias),id=[s.field,s.reverse,String.fromCharCode(97+alias),mapping].join('/');
    assert.equal(yes,expected.has(id));decisions++;if(yes)passing++;
  }});
  assert.equal(decisions,summary.configs);assert.equal(passing,summary.acceptedModels);
  const shapes=[];let paths=0n,saved=0,partial=0;
  for(const c of accepted) {
    const s=sources.find(s=>s.field===c.field&&s.reverse===c.reverse).source,alias=c.alias.charCodeAt(0)-97;
    const stats=countShapes(s,c.mapping,alias);assert.equal(stats.all,c.allCount);assert.equal(stats.noControl,c.count);paths+=BigInt(c.allCount);
    const seen=new Set();for(const hex of c.texts) {
      assert(!seen.has(hex));seen.add(hex);const bytes=Buffer.from(hex,'hex');assert([...bytes].every(b=>b>=32&&b<=126));
      const digits=[...bytes].map(String).join('');assert.equal(digits.length,s.length);
      for(let i=0;i<s.length;i++)assert(Number(digits[i])===c.mapping[s[i]]||(digits[i]==='0'&&s[i]===alias));saved++;
    }
    assert.equal(c.complete,BigInt(c.texts.length)===BigInt(c.count));if(!c.complete)partial++;
    shapes.push({field:c.field,reverse:c.reverse,alias:c.alias,mapping:c.mapping,rank:c.rank,...stats});
  }
  assert.equal(paths.toString(),summary.totalParsePaths);assert.equal(saved,summary.savedTexts);assert.equal(partial,summary.partialModels.length);
  assert.equal(BigInt(saved).toString(),summary.totalControlFreePaths);assert.equal(partial,0);
  fs.writeFileSync(path.join(out,'shapes.json'),JSON.stringify(shapes)+'\n');
  const stats={noControlPaths:shapes.reduce((n,s)=>n+BigInt(s.noControl),0n).toString(),letterSpacePaths:shapes.reduce((n,s)=>n+BigInt(s.lettersAndSpace),0n).toString(),minimumOtherCharacters:Math.min(...shapes.map(s=>s.minimumOtherCharacters))};
  const result={allPassed:true,method:'Independent arithmetic token decoder; all digit bijections enumerated lexicographically; every feasibility decision matched the saved model set, every path count recomputed and each saved text re-encoded.',controls:checked,decisions,passing,parsePaths:paths.toString(),savedTextsChecked:saved,partialModels:partial,shapeStatistics:stats,hashes:{accepted:sha(acceptedBytes),summary:sha(fs.readFileSync(path.join(out,'summary.json'))),shapes:sha(fs.readFileSync(path.join(out,'shapes.json'))),verifier:sha(fs.readFileSync(__filename))}};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();
module.exports={tokenEdges,countShapes,canParse};
