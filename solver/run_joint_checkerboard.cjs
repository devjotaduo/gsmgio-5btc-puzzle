'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const J=require('./joint_checkerboard_search.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','joint_checkerboard_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const options={restarts:8,iterations:20000,dpEvery:500,tempStart:.09,tempEnd:.0001,optimizeMaskEveryKey:false};
function editDistance(a,b){let r=Array.from({length:b.length+1},(_,i)=>i);for(let i=1;i<=a.length;i++){const n=[i];for(let j=1;j<=b.length;j++)n[j]=Math.min(n[j-1]+1,r[j]+1,r[j-1]+Number(a[i-1]!==b[j-1]));r=n;}return r[b.length];}
if(process.argv[2]==='controls') {
  const results=J.controls(options);for(const r of results){r.editDistance=editDistance(r.text,r.best.text);r.normalizedEditDistance=r.editDistance/Math.max(r.text.length,r.best.text.length);}
  fs.writeFileSync(path.join(out,'controls.json'),JSON.stringify(results,null,2)+'\n');console.log(JSON.stringify(results.map(r=>({control:r.index,editDistance:r.editDistance,normalizedEditDistance:r.normalizedEditDistance,evaluations:r.evaluations,ms:r.elapsedMs}))));
} else if(process.argv[2]==='run') {
  const datasets=[{name:'real',source:input.faed},...Array.from({length:3},(_,i)=>({name:`shuffle${i+1}`,seed:77100+i,source:J.shuffle([...input.faed],J.random(77100+i)).join('')}))];
  const spec={hypothesis:'Unknown A-Z plus two reserved checkerboard slots; reserved slots forbidden in plaintext. FAED g independently 0/7, two escape digits and whole original/reversed symbol order. Alphabet/masks sought jointly by simulated annealing and periodic exact mask optimization.',
    caveat:'Heuristic alphabet search; full alphabet space NOT exhausted. Three matched frequency-preserving shuffle controls, not proof of impossibility. g alias is a hypothesis consistent with digit counts, not an author-confirmed mapping.',
    options,datasets,alias:'g',scorer:'Independent general-English quadgrams',inputSHA256:sha(inputBytes),searchSHA256:sha(fs.readFileSync(path.join(__dirname,'joint_checkerboard_search.cjs'))),runnerSHA256:sha(fs.readFileSync(__filename)),
    controlsSHA256:sha(fs.readFileSync(path.join(out,'controls.json')))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  const file=path.join(out,'cases.jsonl');fs.writeFileSync(file,'');let cases=0,evaluations=0,dpCalls=0;const groups=[];
  for(const dataset of datasets)for(const reverse of [false,true]) {
    const source=reverse?[...dataset.source].reverse().join(''):dataset.source;let best=null,groupCases=0;
    for(let e1=0;e1<10;e1++)for(let e2=e1+1;e2<10;e2++) {
      const seed=314159+e1*31+e2*191+(reverse?104729:0),result=J.search(source,'g',[e1,e2],{...options,seed}),rec={dataset:dataset.name,reverse,...result};
      cases++;groupCases++;evaluations+=result.evaluations;dpCalls+=result.dpCalls;fs.appendFileSync(file,JSON.stringify(rec)+'\n');
      if(result.best&&(!best||result.best.score>best.score))best={esc:[e1,e2],...result.best};
      if(groupCases%9===0)console.log(JSON.stringify({dataset:dataset.name,reverse,cases,groupCases,evaluations,score:best?.score,head:best?.text.slice(0,100)}));
    }
    groups.push({dataset:dataset.name,reverse,best});fs.writeFileSync(path.join(out,'progress.json'),JSON.stringify({cases,evaluations,dpCalls,groups},null,2)+'\n');
  }
  assert.equal(cases,360);fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify({cases,evaluations,dpCalls,groups,options,caveat:spec.caveat},null,2)+'\n');
} else throw Error('Use controls or run');
