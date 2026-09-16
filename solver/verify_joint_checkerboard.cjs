/* Independent validation of all saved paths, reserved-slot feasibility and
 * matched budgets. Does not claim a heuristic alphabet maximum is exact.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','joint_checkerboard_2026-09-16'),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes),q=fs.readFileSync(path.join(root,'_work','ambiguous_checkerboard_2026-09-15','general_english','quadgram.f32')),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(sha(inputBytes),spec.inputSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','joint_checkerboard_search.cjs'))),spec.searchSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','run_joint_checkerboard.cjs'))),spec.runnerSHA256);assert.equal(sha(fs.readFileSync(path.join(out,'controls.json'))),spec.controlsSHA256);
const datasets=Object.fromEntries(spec.datasets.map(d=>[d.name,d.source]));assert.equal(datasets.real,input.faed);
for(const d of spec.datasets){assert.equal(d.source.length,570);assert.match(d.source,/^[a-i]+$/);assert.equal([...d.source].sort().join(''),[...input.faed].sort().join(''));}
function build(esc) {const codes=[];for(let d=0;d<10;d++)if(!esc.includes(d))codes.push(String(d));for(const e of esc)for(let d=0;d<10;d++)codes.push(String(e)+d);return codes;}
function pathText(digits,alphabet,esc,codes) {
  let i=0,text='';while(i<digits.length){const w=esc.includes(Number(digits[i]))?2:1;assert(i+w<=digits.length);const index=codes.indexOf(digits.slice(i,i+w));assert(index>=0);text+=alphabet[index];i+=w;}return text;
}
function score(text) {let total=0;for(let i=0;i+4<=text.length;i++){let k=0;for(let j=0;j<4;j++)k=k*26+text.charCodeAt(i+j)-65;total+=q.readFloatLE(4*k);}return total/(text.length-3);}
function feasibleBlanks(source,esc,codes) {
  const byCode=Object.fromEntries(codes.map((c,i)=>[c,i])),digits=[...source].map(c=>c==='g'?[0,7]:[c.charCodeAt(0)-96]);
  const transitions=digits.map((ds,i)=>ds.flatMap(d=>{
    if(esc.includes(d))return digits[i+1]?digits[i+1].map(v=>[i+2,byCode[String(d)+v]]):[];
    return [[i+1,byCode[String(d)]]];
  }));
  let count=0;for(let first=0;first<28;first++)for(let second=first+1;second<28;second++) {
    const valid=new Uint8Array(source.length+1);valid[source.length]=1;
    for(let i=source.length-1;i>=0;i--)for(const [end,slot] of transitions[i])if(slot!==first&&slot!==second&&valid[end]){valid[i]=1;break;}
    count+=valid[0];
  }return count;
}
const bytes=fs.readFileSync(path.join(out,'cases.jsonl')),records=bytes.toString().trim().split('\n').map(JSON.parse),ids=new Set(),tops={},candidates=new Map();let witnesses=0,noFeasible=0,evaluations=0,dpCalls=0;
for(const [index,r] of records.entries()) {
  assert(Object.hasOwn(datasets,r.dataset));assert.equal(typeof r.reverse,'boolean');assert.equal(r.alias,'g');assert(r.esc.length===2&&r.esc[0]>=0&&r.esc[0]<r.esc[1]&&r.esc[1]<10);
  const source=r.reverse?[...datasets[r.dataset]].reverse().join(''):datasets[r.dataset];assert.equal(r.source,source);
  const id=[r.dataset,r.reverse,...r.esc].join('/');assert(!ids.has(id));ids.add(id);
  for(const [k,v] of Object.entries(spec.options))assert.equal(r[k]??false,v);assert.equal(r.seed,314159+r.esc[0]*31+r.esc[1]*191+(r.reverse?104729:0));
  const codes=build(r.esc),allowed=feasibleBlanks(source,r.esc,codes);assert.equal(allowed,r.feasibleBlankPairs);evaluations+=r.evaluations;dpCalls+=r.dpCalls;
  if(allowed===0){assert.equal(r.best,null);assert.equal(r.evaluations,0);noFeasible++;continue;}
  assert(r.best);assert.equal(r.restartBests.length,spec.options.restarts);assert.equal(r.trace.length,spec.options.restarts);
  let prev=-Infinity;
  for(const c of r.improvements){assert(c.score>prev+1e-12);prev=c.score;}
  assert.equal(r.best.score,prev);assert.deepEqual(r.best,r.improvements.at(-1));
  for(const group of ['improvements','restartBests'])for(const [j,c] of r[group].entries()) {
    assert.equal([...c.alphabet].sort().join(''),'..ABCDEFGHIJKLMNOPQRSTUVWXYZ');assert.equal(c.digits.length,source.length);
    for(let i=0;i<source.length;i++)assert(source[i]==='g'?'07'.includes(c.digits[i]):Number(c.digits[i])===source.charCodeAt(i)-96);
    const text=pathText(c.digits,c.alphabet,r.esc,codes);assert.equal(text,c.text);assert.match(text,/^[A-Z]+$/);assert(Math.abs(score(text)-c.score)<1e-9);assert(c.score<=r.best.score+1e-9);witnesses++;
    if(r.dataset==='real'&&!candidates.has(text))candidates.set(text,{text,score:c.score,case:index,group,index:j});
  }
  const topID=[r.dataset,r.reverse].join('/');if(!tops[topID]||r.best.score>tops[topID].score)tops[topID]={esc:r.esc,...r.best};
  if((index+1)%90===0)console.log(JSON.stringify({records:index+1,witnesses,noFeasible}));
}
assert.equal(records.length,360);assert.equal(evaluations,summary.evaluations);assert.equal(dpCalls,summary.dpCalls);
for(const dataset of Object.keys(datasets))for(const reverse of [false,true])for(let a=0;a<10;a++)for(let b=a+1;b<10;b++)assert(ids.has([dataset,reverse,a,b].join('/')));
for(const g of summary.groups)assert.deepEqual(g.best,tops[[g.dataset,g.reverse].join('/')]);
assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))),[...candidates.values()]);
const realBest=Math.max(tops['real/false'].score,tops['real/true'].score),nullBests=Object.keys(datasets).filter(x=>x!=='real').map(dataset=>({dataset,score:Math.max(tops[dataset+'/false'].score,tops[dataset+'/true'].score)}));
const result={models:records.length,evaluations,dpCalls,noFeasibleAlphabet:noFeasible,savedPathsVerified:witnesses,uniqueRealCandidates:candidates.size,allPathScoresAndReservedSlotCountsMatched:true,realBest,nullBests,casesSHA256:sha(bytes),verifierSHA256:sha(fs.readFileSync(__filename)),
  caveat:'Path correctness, feasibility and effort controls verified; alphabet search is heuristic and failed difficult planted controls. No global exclusion of this cipher.'};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
