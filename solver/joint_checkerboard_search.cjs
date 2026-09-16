/* Exploratory joint search: unknown 28-slot checkerboard alphabet plus
 * independent zero/nonzero choices for one source symbol. Heuristic only;
 * no finite run excludes the whole cipher family. General-English scorer.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
process.env.GSMG_CHECKERBOARD_PROFILE='general';
const G=require('./ambiguous_checkerboard.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','joint_checkerboard_2026-09-16');fs.mkdirSync(out,{recursive:true});
const data=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),qb=fs.readFileSync(path.join(root,'_work','ambiguous_checkerboard_2026-09-15','general_english','quadgram.f32'));
const q=new Float32Array(qb.buffer,qb.byteOffset,qb.byteLength/4),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function random(seed) {let x=seed>>>0||1;return()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return(x>>>0)/4294967296;};}
function shuffle(a,rng){a=[...a];for(let i=a.length-1;i>0;i--){const j=Math.floor(rng()*(i+1));[a[i],a[j]]=[a[j],a[i]];}return a;}
function slotsFor(digits,esc) {
  const top=Array(10).fill(-1);let k=0;for(let d=0;d<10;d++)if(!esc.includes(d))top[d]=k++;
  const slots=[];for(let i=0;i<digits.length;) {
    const d=digits[i++];if(d===esc[0]||d===esc[1]){if(i===digits.length)return null;slots.push((d===esc[0]?8:18)+digits[i++]);}
    else slots.push(top[d]);
  }return slots;
}
function scoreSlots(slots,alpha) {
  if(!slots)return -Infinity;let sum=0,last=0,n=0;
  for(let i=0;i<slots.length;i++){const c=alpha[slots[i]];if(c===26)return -Infinity;if(n>=3)sum+=q[last*26+c];last=(last%676)*26+c;n++;}
  return n>3?sum/(n-3):-Infinity;
}
function alphaText(alpha){return alpha.map(c=>c===26?'.':String.fromCharCode(65+c)).join('');}
function plainText(slots,alpha){return slots.map(s=>alpha[s]===26?'.':String.fromCharCode(65+alpha[s])).join('');}
function sourceEdges(source,alias,esc) {
  const top=Array(10).fill(-1);let k=0;for(let d=0;d<10;d++)if(!esc.includes(d))top[d]=k++;
  const ds=G.domains(source,alias);return ds.map((ds0,i)=>{
    const edges=[];for(const d of ds0)if(esc.includes(d)){if(ds[i+1])for(const d2 of ds[i+1])edges.push({end:i+2,slot:(d===esc[0]?8:18)+d2,code:String(d)+d2});}else edges.push({end:i+1,slot:top[d],code:String(d)});return edges;
  });
}
function blankPairs(edges) {
  const allowed=new Set();for(let a=0;a<28;a++)for(let b=a+1;b<28;b++) {
    const reach=new Uint8Array(edges.length+1);reach[0]=1;
    for(let i=0;i<edges.length;i++)if(reach[i])for(const e of edges[i])if(e.slot!==a&&e.slot!==b)reach[e.end]=1;
    if(reach[edges.length])allowed.add(a*28+b);
  }return allowed;
}
function bestMask(edges,alpha) {
  let lambda=-5;
  for(let it=0;it<30;it++) {
    const dp=Array.from({length:edges.length+1},()=>new Map());dp[0].set(0,{sum:0,n:0,value:0,prev:null});
    for(let i=0;i<edges.length;i++) {
      for(const e of edges[i]) {
        const c=alpha[e.slot];if(c===26)continue;
        for(const [s,r] of dp[i]) {
          let next,extra=0,ng=0;
          if(s===0)next=1+c;else if(s<27)next=27+(s-1)*26+c;else if(s<703)next=703+(s-27)*26+c;
          else {next=703+(s-703)%676*26+c;extra=q[(s-703)*26+c];ng=1;}
          const value=r.value+extra-lambda*ng,old=dp[e.end].get(next);if(!old||value>old.value)dp[e.end].set(next,{sum:r.sum+extra,n:r.n+ng,value,prev:r,code:e.code});
        }
      }dp[i].clear();
    }
    let best=null;for(const r of dp[edges.length].values())if(r.n>0&&(!best||r.value>best.value))best=r;if(!best)return null;
    const score=best.sum/best.n;if(Math.abs(score-lambda)<1e-11){let digits='';for(let p=best;p.prev;p=p.prev)digits=p.code+digits;return {score,digits};}lambda=score;
  }throw Error('No fractional convergence');
}
function search(source,alias,esc,{seed=1,restarts=6,iterations=20000,dpEvery=2000,tempStart=0.09,tempEnd=0.0001,optimizeMaskEveryKey=false}={}) {
  const rng=random(seed),digitsBase=[...source].map(c=>c.charCodeAt(0)-96),positions=[...source].flatMap((c,i)=>c===alias?[i]:[]),trueDigit=alias.charCodeAt(0)-96;
  const baseAlpha=[...Array(26).keys(),26,26],freq=[...'ETAOINSHRDLCUMWFGYPBVKJXQZ..'].map(c=>c==='.'?26:c.charCodeAt(0)-65),trace=[];
  let best=null,evaluations=0,dpCalls=0,accepted=0;const improvements=[],restartBests=[],started=Date.now(),edges=sourceEdges(source,alias,esc),allowedBlanks=blankPairs(edges);
  if(!allowedBlanks.size)return {source,alias,esc,seed,restarts,iterations,dpEvery,tempStart,tempEnd,evaluations:0,dpCalls:0,accepted:0,elapsedMs:Date.now()-started,best:null,trace:[],feasibleBlankPairs:0};
  for(let restart=0;restart<restarts;restart++) {
    const digits=[...digitsBase];for(const i of positions)digits[i]=rng()<.5?0:trueDigit;
    let slots=slotsFor(digits,esc)||[];
    const blankChoice=[...allowedBlanks][Math.floor(rng()*allowedBlanks.size)],blanks=[Math.floor(blankChoice/28),blankChoice%28];
    let alpha=Array(28).fill(26),order=Array.from({length:28},(_,i)=>i).filter(i=>!blanks.includes(i)),letters=shuffle(baseAlpha.slice(0,26),rng);
    if(restart%2===0){const counts=Array(28).fill(0);for(const s of slots)counts[s]++;order.sort((a,b)=>counts[b]-counts[a]||a-b);letters=freq.slice(0,26);}
    for(let i=0;i<26;i++)alpha[order[i]]=letters[i];
    const initial=bestMask(edges,alpha);dpCalls++;assert(initial);for(let i=0;i<digits.length;i++)digits[i]=Number(initial.digits[i]);slots=slotsFor(digits,esc);
    let current=scoreSlots(slots,alpha),restartBest=null;evaluations++;
    function remember() {
      if(!restartBest||current>restartBest.score+1e-12)restartBest={score:current,alphabet:alphaText(alpha),digits:digits.join(''),text:plainText(slots,alpha),restart};
      if(!best||current>best.score+1e-12){best=restartBest;improvements.push(best);}
    }
    remember();
    for(let iteration=0;iteration<iterations;iteration++) {
      const temperature=tempStart*Math.pow(tempEnd/tempStart,iteration/Math.max(1,iterations-1));
      if(optimizeMaskEveryKey||rng()<.78||positions.length===0) {
        const swaps=[];
        if(rng()<.12){const a=Math.floor(rng()*10),b=Math.floor(rng()*10);if(a===b)continue;swaps.push([8+a,8+b],[18+a,18+b]);}
        else {const a=Math.floor(rng()*28),b=Math.floor(rng()*28);if(alpha[a]===alpha[b])continue;swaps.push([a,b]);}
        for(const [a,b] of swaps)[alpha[a],alpha[b]]=[alpha[b],alpha[a]];
        let s=scoreSlots(slots,alpha),newDigits=null,newSlots=null;evaluations++;
        if(optimizeMaskEveryKey||!Number.isFinite(s)) {
          const blank=alpha.flatMap((c,i)=>c===26?[i]:[]);
          if(allowedBlanks.has(blank[0]*28+blank[1])){const r=bestMask(edges,alpha);dpCalls++;assert(r);newDigits=[...r.digits].map(Number);newSlots=slotsFor(newDigits,esc);s=scoreSlots(newSlots,alpha);}else s=-Infinity;
        }
        if(Number.isFinite(s)&&(s>=current||rng()<Math.exp((s-current)/temperature))){if(newDigits){for(let i=0;i<digits.length;i++)digits[i]=newDigits[i];slots=newSlots;}current=s;accepted++;remember();}else for(const [a,b] of swaps)[alpha[a],alpha[b]]=[alpha[b],alpha[a]];
      } else {
        const i=positions[Math.floor(rng()*positions.length)],old=digits[i];digits[i]=old?0:trueDigit;const next=slotsFor(digits,esc),s=scoreSlots(next,alpha);evaluations++;
        if(Number.isFinite(s)&&(s>=current||rng()<Math.exp((s-current)/temperature))){slots=next;current=s;accepted++;remember();}else digits[i]=old;
      }
      if(!optimizeMaskEveryKey&&dpEvery>0&&(iteration+1)%dpEvery===0) {
        const r=bestMask(edges,alpha);dpCalls++;assert(r&&r.score>=current-1e-10);
        for(let i=0;i<digits.length;i++)digits[i]=Number(r.digits[i]);slots=slotsFor(digits,esc);current=scoreSlots(slots,alpha);assert(Math.abs(current-r.score)<1e-10);remember();
      }
    }
    trace.push({restart,final:current,best:best.score});restartBests.push(restartBest);
  }
  return {source,alias,esc,seed,restarts,iterations,dpEvery,tempStart,tempEnd,optimizeMaskEveryKey,evaluations,dpCalls,accepted,elapsedMs:Date.now()-started,best,trace,improvements,restartBests,feasibleBlankPairs:allowedBlanks.size};
}
function crypt(text,alpha,esc,alias) {
  return [...G.encode(text,G.board(alpha,esc))].map(d=>d==='0'?alias:String.fromCharCode(96+Number(d))).join('');
}
function controls(options={}) {
  const text=('THEFUNCTIONOFTHEONEISNOWTORETURNTOTHESOURCEALLOWINGATEMPORARYDISSEMINATIONOFTHECODEYOUCARRYREINSERTINGTHEPRIMEPROGRAMAFTERWHICHYOUWILLBEREQUIREDTOSELECTFROMTHEMATRIXTWENTYTHREEINDIVIDUALSSIXTEENFEMALESSEVENMALESTOREBUILDZIONFAILURETOCOMPLYWITHTHISPROCESSWILLRESULTINACATACLYSMICSYSTEMCRASHKILLINGEVERYONECONNECTEDTOTHEMATRIXWHICHCOUPLEDWITHTHEEXTERMINATIONOFZIONWILLULTIMATELYRESULTINTHEEXTINCTIONOFTHEENTIREHUMANRACE');
  const results=[];
  for(const [index,esc] of [[0,[1,4]],[1,[0,7]],[2,[1,7]]]) {
    const alphabet=shuffle([...G.ALPHA],random(20260916+index)).join(''),source=crypt(text,alphabet,esc,'g');
    const trueDigits=G.encode(text,G.board(alphabet,esc)),trueSlots=slotsFor([...trueDigits].map(Number),esc),key=[...alphabet].map(c=>c==='.'?26:c.charCodeAt(0)-65);
    assert.equal(plainText(trueSlots,key),text);assert(Math.abs(scoreSlots(trueSlots,key)-G.score(text))<1e-10);
    const result=search(source,'g',esc,{seed:12345+index,...options}),rec=result.best?.text.replace(/\./g,'')||'';
    const positionalMatch=[...text].filter((c,i)=>rec[i]===c).length/text.length;
    results.push({index,alphabet,esc,text,trueScore:G.score(text),positionalMatch,...result});
    console.log(JSON.stringify({control:index,sourceLength:source.length,elapsedMs:result.elapsedMs,evaluations:result.evaluations,score:result.best?.score,trueScore:G.score(text),positionalMatch,head:result.best?.text.slice(0,160)}));
  }
  fs.writeFileSync(path.join(out,'controls.json'),JSON.stringify(results,null,2)+'\n');return results;
}
function main() {
  if(process.argv[2]==='controls'){controls({restarts:Number(process.argv[3]||6),iterations:Number(process.argv[4]||20000),optimizeMaskEveryKey:process.argv.includes('--exact-mask')});return;}
  throw new Error('Select controls; real-run specification must be chosen only after calibration.');
}
if(require.main===module)main();
module.exports={search,controls,slotsFor,scoreSlots,crypt,random,shuffle,plainText,sourceEdges,blankPairs,bestMask};
