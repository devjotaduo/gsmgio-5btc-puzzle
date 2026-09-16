'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const W=require('./checkerboard_word_decoder.cjs'),P=require('./checkerboard_word_paths.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','checkerboard_exact_mask_2026-09-16'),raw=fs.readFileSync(path.join(out,'count_2w.txt'));
const bigrams=new Map();let maxRatio=0;
for(const line of raw.toString('utf8').trim().split(/\r?\n/)){
  const [pair,count]=line.split('\t'),parts=pair.toUpperCase().split(' '),n=Number(count);if(parts.length!==2||!parts.every(w=>W.words.has(w)))continue;
  assert(n>0);const ratio=n/W.words.get(parts[0]);maxRatio=Math.max(maxRatio,ratio);bigrams.set(parts.join(' '),Math.log10(ratio));
}
function transition(previous,word,unigram){return previous===null?unigram:bigrams.get(previous+' '+word)??(unigram+Math.log10(0.4));}
function optimize(source,alpha,esc,alias){
  const edges=P.graph(source,alpha,esc,alias),dp=Array.from({length:source.length+1},()=>new Map());dp[0].set(null,{score:0,previous:null,word:null});let states=0;
  for(let i=0;i<source.length;i++){
    states+=dp[i].size;
    for(const [word,r]of dp[i])for(const e of edges[i]){
      const score=r.score+transition(word,e.word,e.score),old=dp[e.end].get(e.word);
      if(!old||score>old.score)dp[e.end].set(e.word,{score,previous:r,word:e.word});
    }
    dp[i].clear();
  }
  let best=null;for(const r of dp[source.length].values())if(!best||r.score>best.score)best=r;
  if(!best)return {found:false,states};
  const words=[];for(let r=best;r.previous;r=r.previous)words.push(r.word);words.reverse();const text=words.join('');
  assert.equal([...text].map(c=>P.codebook(alpha,esc,alias)[c]).join(''),source);
  return {found:true,sum:best.score,mean:best.score/text.length,text,words,states};
}
function main(){
  const controls=JSON.parse(fs.readFileSync(path.join(root,'_work','joint_checkerboard_2026-09-16','controls.json'))),probe=JSON.parse(fs.readFileSync(path.join(out,'probe_controls.json'))),results=[];
  for(const c of controls)for(const [keyName,alpha]of [['true',c.alphabet],['exact-mask',probe[c.index].best.alphabet]]){
    const start=Date.now(),r=optimize(c.source,alpha,c.esc,c.alias);results.push({index:c.index,keyName,alphabet:alpha,esc:c.esc,alias:c.alias,source:c.source,expected:c.text,elapsedMs:Date.now()-start,...r});console.log(JSON.stringify({index:c.index,keyName,exact:r.text===c.text,ms:Date.now()-start,text:r.words?.join(' ')}));
  }
  fs.writeFileSync(path.join(out,'bigram_controls.json'),JSON.stringify(results,null,2)+'\n');fs.writeFileSync(path.join(out,'bigram_model.json'),JSON.stringify({source:'https://norvig.com/ngrams/count_2w.txt',rawSHA256:crypto.createHash('sha256').update(raw).digest('hex'),entries:bigrams.size,maxObservedConditionalRatio:maxRatio,backoffWeight:0.4,sourceSHA256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),caveat:'Word-bigram rank with unigram backoff; not normalized over all continuations and never authentication.'},null,2)+'\n');
}
if(require.main===module)main();module.exports={optimize,transition};
