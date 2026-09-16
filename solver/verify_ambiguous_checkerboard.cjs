/* Independent table construction, path verification and optimality bound.
 * At the alleged optimum lambda, no valid path may have sum(q-lambda)>0.
 * Uses string contexts rather than the searcher's numbered states and does
 * not import the searcher. Floating-point comparisons allow 1e-7 total.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),readline=require('node:readline');
const root=path.resolve(__dirname,'..'),base=path.join(root,'_work','ambiguous_checkerboard_2026-09-15'),out=process.env.GSMG_CHECKERBOARD_PROFILE==='general'?path.join(base,'general_english'):base;
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes),tab=fs.readFileSync(path.join(out,'quadgram.f32')),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function tableFor(alpha,esc) {
  const codes=[];for(let d=0;d<10;d++)if(!esc.includes(d))codes.push(String(d));
  for(let r=0;r<2;r++)for(let c=0;c<10;c++)codes.push(String(esc[r])+c);
  return Object.fromEntries(codes.map((c,i)=>[c,alpha[i]]));
}
function dsFor(source,alias,key,mode) {
  return [...source].map((c,i)=>[...new Set((c===alias?[0,c.charCodeAt(0)-96]:[c.charCodeAt(0)-96]).map(d=>{
    const k=Number(key[i%key.length]);let p;if(mode==='add')p=d+k;else if(mode==='beaufort')p=k-d;else p=d-k;return(p%10+10)%10;
  }))]);
}
function choices(ds,i,table,esc) {
  const edges=[];for(const d of ds[i]) {
    if(esc.includes(d)) {if(ds[i+1])for(const e of ds[i+1])edges.push([i+2,table[String(d)+e]]);}
    else edges.push([i+1,table[d]]);
  }return edges;
}
function quad(s){let index=0;for(const c of s)index=index*26+c.charCodeAt(0)-65;return tab.readFloatLE(index*4);}
function plaintextScore(t){const s=t.replace(/[^A-Z]/g,'');let n=0;for(let i=0;i+4<=s.length;i++)n+=quad(s.slice(i,i+4));return n/(s.length-3);}
function bound(ds,table,esc,lambda) {
  const maps=Array.from({length:ds.length+1},()=>new Map());maps[0].set('',0);
  for(let i=0;i<ds.length;i++) {
    for(const [end,c] of choices(ds,i,table,esc))for(const [suffix,value] of maps[i]) {
      const s=/[A-Z]/.test(c)?suffix+c:suffix,next=s.slice(-3),v=value+(s.length===4?quad(s)-lambda:0),old=maps[end].get(next);
      if(old===undefined||v>old)maps[end].set(next,v);
    }maps[i].clear();
  }
  let max=-Infinity;for(const v of maps[ds.length].values())max=Math.max(max,v);return max;
}
function modelID(r,matrix){return(matrix?[r.field,r.reverse,r.key,r.mode,r.alias]:[r.alphabet,r.field,r.reverse,r.alias,...r.esc]).join('/');}
async function verify(folder,matrix) {
  const spec=JSON.parse(fs.readFileSync(path.join(folder,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(folder,'summary.json')));
  assert.equal(sha(inputBytes),spec.inputSHA256);assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(root,'solver',matrix?'checkerboard_matrix_keys.cjs':'ambiguous_checkerboard.cjs'))));
  if(!matrix)assert.equal(sha(tab),spec.scorerSHA256);else assert.equal(spec.optimizerSHA256,sha(fs.readFileSync(path.join(root,'solver','ambiguous_checkerboard.cjs'))));
  const alphabets=matrix?{phase32:spec.alphabet}:Object.fromEntries(spec.alphabets.map(a=>[a.name,a.alpha])),seen=new Set();let records=0,maxResidual=-Infinity;
  const file=path.join(folder,'ranked.jsonl');
  for await(const line of readline.createInterface({input:fs.createReadStream(file),crlfDelay:Infinity})) {
    const r=JSON.parse(line),id=modelID(r,matrix);assert(!seen.has(id));seen.add(id);
    const source=r.reverse?[...input[r.field]].reverse().join(''):input[r.field],ds=dsFor(source,r.alias,matrix?r.key:'0',matrix?r.mode:'subtract'),table=tableFor(alphabets[r.alphabet||'phase32'],r.esc);
    assert.equal(r.digits.length,source.length);for(let i=0;i<r.digits.length;i++)assert(ds[i].includes(Number(r.digits[i])));
    let text='';for(let i=0;i<r.digits.length;) {const w=r.esc.includes(Number(r.digits[i]))?2:1;assert(i+w<=r.digits.length);text+=table[r.digits.slice(i,i+w)];i+=w;}
    assert.equal(text,r.text);assert(Math.abs(plaintextScore(text)-r.score)<1e-10);
    const residual=bound(ds,table,r.esc,r.score);assert(Math.abs(residual)<1e-7,`${id}/${residual}`);maxResidual=Math.max(maxResidual,Math.abs(residual));records++;
    if(records%10000===0)console.log(JSON.stringify({matrix,records,maxResidual}));
  }
  let cases=0,noPath=0;const keys=matrix?spec.keys.map(k=>k.key):['0'],modes=matrix?['subtract','add','beaufort']:['subtract'];
  for(const [alphabet,alpha] of Object.entries(alphabets))for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const key of keys)for(const mode of modes)for(const alias of 'abcdefghi') {
    const escapes=matrix?[spec.esc]:Array.from({length:10},(_,a)=>Array.from({length:10},(_,b)=>[a,b])).flat().filter(([a,b])=>a!==b);
    for(const esc of escapes) {
      const id=modelID({alphabet,field,reverse,key,mode,alias,esc},matrix);cases++;if(seen.has(id))continue;
      const source=reverse?[...input[field]].reverse().join(''):input[field];assert.equal(bound(dsFor(source,alias,key,mode),tableFor(alpha,esc),esc,0),-Infinity);noPath++;
    }
  }
  assert.equal(cases,summary.cases);assert.equal(noPath,summary.noPath);assert.equal(records+noPath,cases);
  const result={cases,records,noPath,allPathsAndScoresMatched:true,allOptimaBounded:true,maxAbsoluteResidual:maxResidual,rankedSHA256:sha(fs.readFileSync(file)),verifierSHA256:sha(fs.readFileSync(__filename)),
    caveat:'This verifies optimality under the quadgram score, not English meaning, passwords, or uniqueness of the underlying cipher.'};
  fs.writeFileSync(path.join(folder,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
async function main(){await verify(out,false);await verify(path.join(out,'matrix_keys'),true);}
main().catch(e=>{console.error(e);process.exitCode=1;});
