'use strict';
// Independent word-boundary graph and backwards optimum for fixed alphabets.
// Does not import the searcher, word decoder, or quadgram optimizer.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','checkerboard_exact_mask_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const wordRaw=fs.readFileSync(path.join(out,'count_1w.txt')),words=new Map();let total=0;
for(const line of wordRaw.toString('utf8').trim().split(/\r?\n/)){const [w,s]=line.split('\t'),n=Number(s);assert(Number.isSafeInteger(n)&&n>0);total+=n;if(/^[a-z]{1,32}$/.test(w)&&(w.length>1||w==='a'||w==='i'))words.set(w.toUpperCase(),(words.get(w.toUpperCase())||0)+n);}
assert(Number.isSafeInteger(total));
const trie=[{children:{},word:null}];for(const [w,count]of words){let node=0;for(const c of w){if(trie[node].children[c]===undefined){trie[node].children[c]=trie.length;trie.push({children:{},word:null});}node=trie[node].children[c];}trie[node].word=w;trie[node].cost=Math.log10(count/total);}
function codebook(alpha,esc){assert.equal([...alpha].sort().join(''),'..ABCDEFGHIJKLMNOPQRSTUVWXYZ');let at=0;const byLetter={},byCode={};const add=code=>{const letter=alpha[at++];byCode[code]=letter;if(letter!=='.')byLetter[letter]=code;};for(let d=0;d<10;d++)if(!esc.includes(d))add(String(d));for(const e of esc)for(let d=0;d<10;d++)add(String(e)+d);return {byLetter,byCode};}
function encoded(text,alpha,esc){const {byLetter}=codebook(alpha,esc);return [...text].map(c=>byLetter[c]).join('').replace(/[0-9]/g,d=>d==='0'?'g':String.fromCharCode(96+Number(d)));}
function optimum(source,alpha,esc){
  const {byLetter}=codebook(alpha,esc),codes=Object.fromEntries(Object.entries(byLetter).map(([c,d])=>[c,d.replace(/[0-9]/g,n=>n==='0'?'g':String.fromCharCode(96+Number(n)))]));
  const best=Array(source.length+1).fill(-Infinity);best[source.length]=0;
  for(let i=source.length-1;i>=0;i--){const pending=[[0,i]];while(pending.length){const [node,at]=pending.pop();if(trie[node].word!==null)best[i]=Math.max(best[i],trie[node].cost+best[at]);for(const [c,next]of Object.entries(trie[node].children))if(source.substring(at,at+codes[c].length)===codes[c])pending.push([next,at+codes[c].length]);}}
  return best[0];
}
function staticSegment(text){const best=Array(text.length+1).fill(-Infinity);best[text.length]=0;for(let i=text.length-1;i>=0;i--)for(let n=1;n<=32&&i+n<=text.length;n++){const w=text.slice(i,i+n);if(words.has(w))best[i]=Math.max(best[i],Math.log10(words.get(w)/total)+best[i+n]);}return best[0];}
function distance(a,b){const dp=Array.from({length:a.length+1},()=>new Uint16Array(b.length+1));for(let i=0;i<=a.length;i++)dp[i][0]=i;for(let j=0;j<=b.length;j++)dp[0][j]=j;for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)dp[i][j]=Math.min(dp[i-1][j]+1,dp[i][j-1]+1,dp[i-1][j-1]+Number(a[i-1]!==b[j-1]));return dp[a.length][b.length];}
function decode(digits,alpha,esc){const {byCode}=codebook(alpha,esc);let text='';for(let i=0;i<digits.length;){const n=esc.includes(Number(digits[i]))?2:1;if(i+n>digits.length)return null;const c=byCode[digits.slice(i,i+n)];if(!c||c==='.')return null;text+=c;i+=n;}return text;}
const qraw=fs.readFileSync(path.join(root,'_work','ambiguous_checkerboard_2026-09-15','general_english','quadgram.f32'));
function qscore(text){let sum=0;for(let i=0;i+4<=text.length;i++){let n=0;for(let j=0;j<4;j++)n=n*26+text.charCodeAt(i+j)-65;sum+=qraw.readFloatLE(n*4);}return sum/(text.length-3);}
let wordWitnesses=0,quadWitnesses=0,optimalityChecks=0;
function checkWord(r,c){assert.match(r.text,/^[A-Z]+$/);assert.equal(r.words.join(''),r.text);assert.equal(encoded(r.text,r.alphabet,c.esc),c.source);let sum=0;for(const w of r.words){assert(words.has(w));sum+=Math.log10(words.get(w)/total);}assert(Math.abs(sum-r.sum)<1e-8);assert(Math.abs(sum/r.text.length-r.mean)<1e-10);wordWitnesses++;}
function checkTrial(c){
  assert.equal(c.alias,'g');const q=c.quad;
  assert.equal(q.source,c.source);assert.deepEqual(q.esc,c.esc);assert.equal(q.seed,c.seed);
  for(const r of [...(q.improvements||[]),...(q.restartBests||[])]){assert.equal(decode(r.digits,r.alphabet,c.esc),r.text);assert.equal(encoded(r.text,r.alphabet,c.esc),c.source);assert(Math.abs(qscore(r.text)-r.score)<1e-8);quadWitnesses++;}
  for(const r of c.refinements){
    assert.equal(r.evaluations,1+377*r.steps.length);
    for(const v of r.improvements)checkWord(v,c);for(const v of r.steps)checkWord(v,c);
    const initial=optimum(c.source,r.initial,c.esc);optimalityChecks++;
    if(!r.found){assert(!Number.isFinite(initial));continue;}
    assert(Math.abs(r.improvements[0].sum-initial)<1e-8);
    let previous=initial;for(const s of r.steps){assert(s.sum>=previous-1e-8);assert.equal(s.changed,s.sum>previous+1e-10);previous=s.sum;}
    assert(Math.abs(optimum(c.source,r.alphabet,c.esc)-r.sum)<1e-8);optimalityChecks++;checkWord(r,c);
    if(r.plateau){assert(r.steps.length&&r.steps.at(-1).changed===false);}else assert.equal(r.steps.length,20);
    assert.deepEqual(r.text,r.steps.at(-1)?.text||r.improvements[0].text);
  }
  const candidates=c.refinements.filter(r=>r.found);if(!candidates.length)assert.equal(c.best,null);else {const max=Math.max(...candidates.map(r=>r.sum));assert(Math.abs(c.best.sum-max)<1e-8);checkWord(c.best,c);}
}
function controls(){
  const previous=JSON.parse(fs.readFileSync(path.join(root,'_work','joint_checkerboard_2026-09-16','controls.json')));let bruteMasks=0,bruteCases=0;
  for(const c of previous)for(const text of ['THE','ZERO','MATRIX','THEONE']){
    const source=encoded(text,c.alphabet,c.esc),positions=[...source].flatMap((x,i)=>x==='g'?[i]:[]);assert(positions.length<20);let best=-Infinity;
    for(let mask=0;mask<2**positions.length;mask++){const ds=[...source].map(x=>String(x.charCodeAt(0)-96));positions.forEach((p,i)=>{ds[p]=(mask&(1<<i))?'7':'0';});const plain=decode(ds.join(''),c.alphabet,c.esc);if(plain)best=Math.max(best,staticSegment(plain));bruteMasks++;}
    const result=optimum(source,c.alphabet,c.esc);assert(result===best||Math.abs(result-best)<1e-8);bruteCases++;
  }
  const spec=JSON.parse(fs.readFileSync(path.join(out,'controls_spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'controls.json')));assert.equal(saved.length,6);assert.equal(spec.searchSHA256,sha(fs.readFileSync(path.join(__dirname,'checkerboard_word_search.cjs'))));
  for(let i=0;i<saved.length;i++){const c=saved[i],p=spec.plan[i];assert.equal(c.id,p.id);assert.equal(c.source,p.source);assert.equal(c.expected,p.expected);assert.equal(c.seed,p.seed);for(const [k,v]of Object.entries(spec.options))assert.equal(c.quad[k],v);const original=previous[Number(c.id.at(-1))];assert.equal(encoded(c.expected,original.alphabet,c.esc),c.source);if(c.id.startsWith('length570'))assert.equal(c.source.length,570);checkTrial(c);assert.equal(c.exact,c.best?.text===c.expected);assert.equal(c.editDistance,c.best?distance(c.expected,c.best.text):null);}
  return {bruteCases,bruteMasks,controls:saved.map(c=>({id:c.id,exact:c.exact,editDistance:c.editDistance,sourceLength:c.source.length}))};
}
function main(){
  const checked=controls(),result={controls:checked,complete:false,wordWitnesses,quadWitnesses,optimalityChecks,verifierSHA256:sha(fs.readFileSync(__filename))};
  if(process.argv[2]==='controls'){result.complete=true;fs.writeFileSync(path.join(out,'control_verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));return;}
  const realOnly=process.argv[2]==='real',spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=realOnly?null:JSON.parse(fs.readFileSync(path.join(out,'summary.json')));if(summary)assert(summary.complete);assert.equal(spec.wordDataSHA256,sha(wordRaw));assert.equal(spec.quadgramSHA256,sha(qraw));for(const [f,h]of Object.entries(spec.sources))assert.equal(sha(fs.readFileSync(path.join(__dirname,f))),h);
  assert.equal(spec.controlsSHA256,sha(fs.readFileSync(path.join(out,'controls.json'))));const snapshot=fs.readFileSync(path.join(out,'cases.jsonl'),'utf8'),completeLines=snapshot.slice(0,snapshot.lastIndexOf('\n')+1).trim().split(/\r?\n/),lines=realOnly?completeLines.filter(l=>JSON.parse(l).dataset==='real'):completeLines,raw=Buffer.from(lines.join('\n')+'\n'),records=lines.map(JSON.parse);if(summary)assert.equal(sha(raw),summary.casesSHA256);assert.equal(records.length,realOnly?90:180);
  const ids=new Set(),tops=new Map();let qe=0,we=0;
  for(const c of records){const d=spec.datasets.find(d=>d.name===c.dataset);assert(d);assert.equal(c.source,c.reverse?[...d.source].reverse().join(''):d.source);const id=[c.dataset,c.reverse,...c.esc].join('/');assert(!ids.has(id));ids.add(id);assert.equal(c.seed,581923+c.esc[0]*31+c.esc[1]*191+(c.reverse?104729:0));for(const [k,v]of Object.entries(spec.options)){if(k==='optimizeMaskEveryKey'&&c.quad.feasibleBlankPairs===0){assert.equal(c.quad.evaluations,0);continue;}assert.equal(c.quad[k]??false,v);}checkTrial(c);qe+=c.quad.evaluations;we+=c.refinements.reduce((n,r)=>n+r.evaluations,0);const key=c.dataset+'/'+c.reverse;if(c.best&&(!tops.has(key)||c.best.mean>tops.get(key).mean))tops.set(key,{esc:c.esc,...c.best});}
  for(const d of spec.datasets.filter(d=>!realOnly||d.name==='real'))for(const rev of [false,true])for(let a=0;a<10;a++)for(let b=a+1;b<10;b++)assert(ids.has([d.name,rev,a,b].join('/')));
  if(summary){assert.equal(qe,summary.quadEvaluations);assert.equal(we,summary.wordEvaluations);for(const g of summary.groups)assert.deepEqual(g.best,tops.get(g.dataset+'/'+g.reverse)||null);}
  Object.assign(result,{complete:true,scope:realOnly?'All 90 real cases; no claim that shuffle campaign is complete.':'Full declared campaign of 180 cases.',cases:records.length,quadEvaluations:qe,wordEvaluations:we,wordWitnesses,quadWitnesses,optimalityChecks,casesSHA256:sha(raw)});fs.writeFileSync(path.join(out,realOnly?'real_verification.json':'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();
