'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const J=require('./joint_checkerboard_search.cjs'),W=require('./checkerboard_word_decoder.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','checkerboard_exact_mask_2026-09-16'),oldDir=path.join(root,'_work','joint_checkerboard_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const options={restarts:4,iterations:4000,dpEvery:0,tempStart:0.04,tempEnd:0.0001,optimizeMaskEveryKey:true};
function refine(source,alias,esc,initial,maxSweeps=20){
  let alpha=initial,current=W.optimize(source,alpha,esc,alias),evaluations=1;const steps=[],improvements=[];let plateau=false;
  if(!current.found)return {initial,alphabet:alpha,evaluations,steps,improvements,found:false,plateau:false};
  improvements.push({alphabet:alpha,...current});
  for(let sweep=0;sweep<maxSweeps;sweep++){
    let best={alphabet:alpha,...current};
    for(let a=0;a<28;a++)for(let b=a+1;b<28;b++){
      if(alpha[a]===alpha[b])continue;
      const key=[...alpha];[key[a],key[b]]=[key[b],key[a]];const alphabet=key.join(''),r=W.optimize(source,alphabet,esc,alias);evaluations++;
      if(r.found&&r.sum>best.sum+1e-10){best={alphabet,...r};improvements.push({sweep,a,b,...best});}
    }
    const changed=best.alphabet!==alpha;alpha=best.alphabet;current=best;steps.push({sweep,changed,...best});if(!changed){plateau=true;break;}
  }
  return {initial,alphabet:alpha,evaluations,steps,improvements,found:true,plateau,...current};
}
function trial(source,alias,esc,seed,oldAlphabet=null){
  const start=Date.now(),quad=J.search(source,alias,esc,{...options,seed}),initials=[];
  if(quad.best)initials.push(quad.best.alphabet);if(oldAlphabet)initials.push(oldAlphabet);
  const seen=new Set(),refinements=[];for(const alpha of initials){const id=W.codes(alpha,esc,alias).join('/');if(seen.has(id))continue;seen.add(id);refinements.push(refine(source,alias,esc,alpha));}
  let best=null;for(const r of refinements)if(r.found&&(!best||r.sum>best.sum))best={alphabet:r.alphabet,text:r.text,words:r.words,sum:r.sum,mean:r.mean};
  return {source,alias,esc,seed,quad,refinements,best,elapsedMs:Date.now()-start};
}
function editDistance(a,b){let r=Array.from({length:b.length+1},(_,i)=>i);for(let i=1;i<=a.length;i++){const next=[i];for(let j=1;j<=b.length;j++)next[j]=Math.min(next[j-1]+1,r[j]+1,r[j-1]+Number(a[i-1]!==b[j-1]));r=next;}return r[b.length];}
function controlSet(){
  const old=JSON.parse(fs.readFileSync(path.join(oldDir,'controls.json'))),result=[];
  for(const c of old){
    result.push({id:`full-${c.index}`,expected:c.text,source:c.source,alias:c.alias,esc:c.esc,seed:330017+c.index,oldAlphabet:c.best.alphabet});
    const offsets=[0];for(const ch of c.text)offsets.push(offsets.at(-1)+J.crypt(ch,c.alphabet,c.esc,c.alias).length);
    let segment=null;for(let i=0;i<offsets.length&&!segment;i++){const j=offsets.indexOf(offsets[i]+570);if(j>i)segment={start:i,end:j,expected:c.text.slice(i,j)};}
    assert(segment);const source=J.crypt(segment.expected,c.alphabet,c.esc,c.alias);assert.equal(source.length,570);
    result.push({id:`length570-${c.index}`,expected:segment.expected,source,alias:c.alias,esc:c.esc,seed:940001+c.index,segment});
  }
  return result;
}
function controls(){
  const plan=controlSet();fs.writeFileSync(path.join(out,'controls_spec.json'),JSON.stringify({options,maxSweeps:20,plan,searchSHA256:sha(fs.readFileSync(__filename))},null,2)+'\n');const results=[];
  for(const c of plan){const r=trial(c.source,c.alias,c.esc,c.seed,c.oldAlphabet),distance=r.best?editDistance(c.expected,r.best.text):null;results.push({...c,...r,editDistance:distance,exact:r.best?.text===c.expected});fs.writeFileSync(path.join(out,'controls.json'),JSON.stringify(results,null,2)+'\n');console.log(JSON.stringify({control:c.id,sourceLength:c.source.length,expectedLength:c.expected.length,ms:r.elapsedMs,editDistance:distance,exact:r.best?.text===c.expected,head:r.best?.text.slice(0,90)}));}
}
function run(){
  const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),oldSpec=JSON.parse(fs.readFileSync(path.join(oldDir,'spec.json')));assert.equal(oldSpec.inputSHA256,sha(inputRaw));
  const oldCases=fs.readFileSync(path.join(oldDir,'cases.jsonl'),'utf8').trim().split(/\r?\n/).map(JSON.parse),datasets=oldSpec.datasets.filter(d=>['real','shuffle1'].includes(d.name));assert.equal(datasets.length,2);assert.equal(datasets.find(d=>d.name==='real').source,input.faed);
  const controls=JSON.parse(fs.readFileSync(path.join(out,'controls.json')));assert.equal(controls.length,6);
  const sources=['checkerboard_word_search.cjs','checkerboard_word_decoder.cjs','joint_checkerboard_search.cjs','ambiguous_checkerboard.cjs'];
  const spec={hypothesis:'Same FAED straddling-checkerboard family as the previous joint search: all 45 escape pairs, both source directions, g independently 0/7, unknown A-Z plus two reserved slots. Exact mask optimization at each new quadgram proposal; word-unigram coordinate refinement from new and historical alphabets.',
    scope:'Heuristic alphabet inference; at most 20 full swap sweeps per start. A no-word result only rejects that alphabet under this vocabulary. No cipher-family exclusion or password authentication follows from a score.',options,maxSweeps:20,datasets,inputSHA256:sha(inputRaw),priorSpecSHA256:sha(fs.readFileSync(path.join(oldDir,'spec.json'))),priorCasesSHA256:sha(fs.readFileSync(path.join(oldDir,'cases.jsonl'))),controlsSHA256:sha(fs.readFileSync(path.join(out,'controls.json'))),sources:Object.fromEntries(sources.map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))])),wordDataSHA256:W.rawSHA256,quadgramSHA256:sha(fs.readFileSync(path.join(root,'_work','ambiguous_checkerboard_2026-09-15','general_english','quadgram.f32')))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');const file=path.join(out,'cases.jsonl');assert(!fs.existsSync(file),'Do not overwrite an existing campaign.');fs.writeFileSync(file,'');
  const summary={complete:false,cases:0,quadEvaluations:0,wordEvaluations:0,groups:[]};
  for(const dataset of datasets)for(const reverse of [false,true]){
    const source=reverse?[...dataset.source].reverse().join(''):dataset.source;let best=null;
    for(let a=0;a<10;a++)for(let b=a+1;b<10;b++){
      const previous=oldCases.find(c=>c.dataset===dataset.name&&c.reverse===reverse&&c.esc[0]===a&&c.esc[1]===b);assert(previous&&previous.source===source);
      const seed=581923+a*31+b*191+(reverse?104729:0),r=trial(source,'g',[a,b],seed,previous.best?.alphabet||null),record={dataset:dataset.name,reverse,...r};
      fs.appendFileSync(file,JSON.stringify(record)+'\n');summary.cases++;summary.quadEvaluations+=r.quad.evaluations;summary.wordEvaluations+=r.refinements.reduce((n,x)=>n+x.evaluations,0);
      if(r.best&&(!best||r.best.mean>best.mean))best={esc:[a,b],...r.best};
      console.log(JSON.stringify({dataset:dataset.name,reverse,esc:[a,b],cases:summary.cases,ms:r.elapsedMs,bestMean:best?.mean,head:r.best?.text.slice(0,70)}));
      fs.writeFileSync(path.join(out,'progress.json'),JSON.stringify(summary,null,2)+'\n');
    }
    summary.groups.push({dataset:dataset.name,reverse,best});
  }
  assert.equal(summary.cases,180);summary.complete=true;summary.casesSHA256=sha(fs.readFileSync(file));fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({complete:true,cases:summary.cases,quadEvaluations:summary.quadEvaluations,wordEvaluations:summary.wordEvaluations}));
}
if(require.main===module){if(process.argv[2]==='controls')controls();else if(process.argv[2]==='run')run();else throw Error('Use controls or run');}
module.exports={refine,trial,controlSet,editDistance};
