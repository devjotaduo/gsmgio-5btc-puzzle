/* Straddling checkerboard with independent zero/nonzero choices at every
 * occurrence of one symbol. Dynamic programming optimizes the mean English
 * quadgram score (fractional programming); a rank is NEVER authentication.
 * node solver/ambiguous_checkerboard.cjs [controls|probe|run]
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),base=path.join(root,'_work','ambiguous_checkerboard_2026-09-15'),out=process.env.GSMG_CHECKERBOARD_PROFILE==='general'?path.join(base,'general_english'):base;
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const scoreBytes=fs.readFileSync(path.join(out,'quadgram.f32')),tab=Array.from({length:26**4},(_,i)=>scoreBytes.readFloatLE(i*4)),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const ALPHA='FUBCDORA.LETHINGKYMVPS.JQZXW';
const CONTROL_DIGITS='15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112';
const CONTROL_TEXT='INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE';
function score(text) {
  const s=[...text.replace(/[^A-Z]/g,'')].map(c=>c.charCodeAt(0)-65);if(s.length<4)return -Infinity;
  let total=0;for(let i=3;i<s.length;i++)total+=tab[((s[i-3]*26+s[i-2])*26+s[i-1])*26+s[i]];return total/(s.length-3);
}
function board(alpha,esc) {
  assert.equal(alpha.length,28);assert(esc.length===2&&esc[0]!==esc[1]);
  const table=new Map();let i=0;
  for(let d=0;d<10;d++)if(!esc.includes(d))table.set(String(d),alpha[i++]);
  for(const e of esc)for(let d=0;d<10;d++)table.set(`${e}${d}`,alpha[i++]);return table;
}
function decode(digits,table,esc) {
  let s='';for(let i=0;i<digits.length;) {
    const len=esc.includes(Number(digits[i]))?2:1;if(i+len>digits.length)return null;
    s+=table.get(digits.slice(i,i+len));i+=len;
  }return s;
}
function encode(text,table) {
  const inverse=new Map();for(const [code,ch] of table)if(!inverse.has(ch))inverse.set(ch,code);
  return [...text].map(c=>{assert(inverse.has(c));return inverse.get(c);}).join('');
}
function domains(source,alias,key=[0],mode='subtract') {
  return [...source].map((c,i)=>{
    const d=c.charCodeAt(0)-96,k=key[i%key.length];
    return [...new Set((c===alias?[0,d]:[d]).map(v=>(mode==='subtract'?v-k:mode==='add'?v+k:k-v)%10).map(v=>(v+10)%10))];
  });
}
function edgesFor(ds,table,esc) {
  return ds.map((digits,i)=>{
    const edges=[];for(const d of digits) {
      if(esc.includes(d)) {if(i+1<ds.length)for(const e of ds[i+1]){const code=`${d}${e}`;edges.push({step:2,code,char:table.get(code)});}}
      else {const code=String(d);edges.push({step:1,code,char:table.get(code)});}
    }return edges;
  });
}
function transition(state,c) {
  if(c<0||c>25)return {state,q:0,gram:0};
  if(state===0)return {state:1+c,q:0,gram:0};
  if(state<27)return {state:27+(state-1)*26+c,q:0,gram:0};
  if(state<703)return {state:703+(state-27)*26+c,q:0,gram:0};
  return {state:703+(state-703)%676*26+c,q:tab[(state-703)*26+c],gram:1};
}
function bestAt(edges,lambda) {
  const dp=Array.from({length:edges.length+1},()=>new Map());
  dp[0].set(0,{value:0,sum:0,grams:0,prev:null});let states=0;
  for(let i=0;i<edges.length;i++) {
    for(const [state,r] of dp[i])for(const e of edges[i]) {
      const t=transition(state,e.char.charCodeAt(0)-65),value=r.value+t.q-lambda*t.gram,dst=dp[i+e.step],old=dst.get(t.state);
      if(!old||value>old.value+1e-12)dst.set(t.state,{value,sum:r.sum+t.q,grams:r.grams+t.gram,prev:r,char:e.char,code:e.code});
    }
    states+=dp[i].size;dp[i].clear();
  }
  let best=null;for(const r of dp[edges.length].values())if(r.grams>0&&(!best||r.value>best.value))best=r;
  if(!best)return null;
  let text='',digits='';for(let p=best;p.prev;p=p.prev){text=p.char+text;digits=p.code+digits;}
  return {text,digits,score:best.sum/best.grams,residual:best.value,grams:best.grams,states};
}
function optimize(ds,table,esc) {
  const edges=edgesFor(ds,table,esc);let lambda=-5,states=0;
  for(let iteration=1;iteration<=30;iteration++) {
    const r=bestAt(edges,lambda);if(!r)return null;states+=r.states;
    if(Math.abs(r.score-lambda)<1e-11){assert(Math.abs(score(r.text)-r.score)<1e-10);return {...r,states,iterations:iteration};}
    lambda=r.score;
  }
  throw new Error('Fractional optimization did not converge');
}
function merged(digits,alias){return [...digits].map(d=>d==='0'?alias:String.fromCharCode(96+Number(d))).join('');}
function controls() {
  const table=board(ALPHA,[1,4]);assert.equal(decode(CONTROL_DIGITS,table,[1,4]),CONTROL_TEXT);assert.equal(encode(CONTROL_TEXT,table),CONTROL_DIGITS);
  let exhaustive=0,planted=0,exactRecovery=0;
  for(const text of ['THISPASSWORD',CONTROL_TEXT])for(const alias of 'abcdefghi') {
    const digits=encode(text,table),ds=domains(merged(digits,alias),alias),r=optimize(ds,table,[1,4]);assert(r);
    assert(r.score>=score(text)-1e-10);assert.equal(decode(r.digits,table,[1,4]),r.text);
    for(let i=0;i<digits.length;i++)assert(ds[i].includes(Number(digits[i]))&&ds[i].includes(Number(r.digits[i])));
    planted++;if(r.text===text)exactRecovery++;
  }
  for(const text of ['PASSWORD','ENGLISH','THEMATRIX','THISISATEST'])for(const alias of 'abcdefghi') {
    const ds=domains(merged(encode(text,table),alias),alias);let expected=-Infinity,paths=0;
    function visit(i,s) {if(i===ds.length){const p=decode(s,table,[1,4]);if(p!==null){expected=Math.max(expected,score(p));paths++;}return;}for(const d of ds[i])visit(i+1,s+d);}
    visit(0,'');const r=optimize(ds,table,[1,4]);assert(r&&paths>0);assert(Math.abs(r.score-expected)<1e-10);exhaustive++;
  }
  return {knownPhase32:true,planted,exactRecovery,exhaustive};
}
function alphabetList() {
  const words=['matrixsumlist','lastwordsbeforearchichoice','thispassword','cosmicduality','salphaseion','thematrixhasyou','primebasics','halfandbetterhalf','ourfirsthintisyourlastcommand'];
  const result=[{name:'phase32',alpha:ALPHA},{name:'alphabetical',alpha:'ABCDEFGHIJKLMNOPQRSTUVWXYZ..'},{name:'frequent-top',alpha:'ET AON RIS'.replace(/ /g,'')+'BCDFGHJKLMPQUVWXYZ..'}];
  for(const w of words)result.push({name:`keyed:${w}`,alpha:[...new Set((w+'abcdefghijklmnopqrstuvwxyz').toUpperCase())].join('')+'..'});
  for(const a of result)assert.equal(a.alpha.length,28);return result;
}
function main() {
  const checked=controls();console.log(JSON.stringify({controls:checked}));if(process.argv[2]==='controls')return;
  if(process.argv[2]==='probe') {
    for(const field of ['dbbi','faed'])for(const alias of ['g','b']){const r=optimize(domains(input[field],alias),board(ALPHA,[1,4]),[1,4]);console.log(JSON.stringify({field,alias,...r}));}return;
  }
  const alphabets=alphabetList(),file=path.join(out,'ranked.jsonl');fs.writeFileSync(file,'');
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify({hypothesis:'Direct straddling checkerboard; known A1..I9 values, independently ambiguous zero/nonzero at each occurrence of any one alias; all 90 ordered escape pairs, both field directions.',
    caveat:'Only the maximum mean quadgram-score path is recovered per model. Not an exhaustive authentication of all possible plaintexts. No transposition or keystream in this run.',
    alphabets,controls:checked,inputSHA256:sha(inputBytes),scorerSHA256:sha(scoreBytes),sourceSHA256:sha(fs.readFileSync(__filename))},null,2)+'\n');
  let cases=0,noPath=0,states=0;const best=[];
  for(const a of alphabets)for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
    const source=reverse?[...input[field]].reverse().join(''):input[field];let groupBest=null;
    for(const alias of 'abcdefghi')for(let e1=0;e1<10;e1++)for(let e2=0;e2<10;e2++)if(e1!==e2) {
      const r=optimize(domains(source,alias),board(a.alpha,[e1,e2]),[e1,e2]),record={alphabet:a.name,field,reverse,alias,esc:[e1,e2],...r};cases++;
      if(!r){noPath++;continue;}states+=r.states;fs.appendFileSync(file,JSON.stringify(record)+'\n');
      if(!groupBest||r.score>groupBest.score)groupBest=record;
    }
    best.push(groupBest);console.log(JSON.stringify({alphabet:a.name,field,reverse,cases,noPath,bestScore:groupBest?.score,head:groupBest?.text.slice(0,90)}));
  }
  const summary={cases,noPath,states,controls:checked,best};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');
}
if(require.main===module)main();
module.exports={score,board,decode,encode,domains,optimize,alphabetList,ALPHA,CONTROL_DIGITS,CONTROL_TEXT};
