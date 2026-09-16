'use strict';
// Fixed-alphabet decoding with an independently sourced word-frequency model.
// A language score is not authentication and the alphabet is NOT inferred here.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','checkerboard_exact_mask_2026-09-16');
const raw=fs.readFileSync(path.join(out,'count_1w.txt')),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const nodes=[{next:new Map(),logp:null,word:null}],words=new Map();let total=0;
for(const line of raw.toString('utf8').trim().split(/\r?\n/)){
  const [w,c]=line.split('\t'),n=Number(c);assert(n>0&&Number.isFinite(n));total+=n;
  if(/^[a-z]+$/.test(w)&&w.length<=32&&(w.length>1||w==='a'||w==='i'))words.set(w.toUpperCase(),(words.get(w.toUpperCase())||0)+n);
}
for(const [word,count]of words){let at=0;for(const c of word){const letter=c.charCodeAt(0)-65;if(!nodes[at].next.has(letter)){nodes[at].next.set(letter,nodes.length);nodes.push({next:new Map(),logp:null,word:null});}at=nodes[at].next.get(letter);}nodes[at].logp=Math.log10(count/total);nodes[at].word=word;}
function codes(alpha,esc,alias){
  assert.equal(alpha.length,28);assert.equal(new Set(alpha.replaceAll('.','')).size,26);let at=0;const result=Array(26);
  function add(code){const letter=alpha.charCodeAt(at++)-65;if(letter>=0&&letter<26)result[letter]=[...code].map(d=>d==='0'?alias:String.fromCharCode(96+Number(d))).join('');}
  for(let i=0;i<10;i++)if(!esc.includes(i))add(String(i));for(const e of esc)for(let i=0;i<10;i++)add(String(e)+i);
  assert(result.every(Boolean));return result;
}
function optimize(source,alpha,esc,alias,{perCharacter=false,maxIterations=30}={}){
  const encoded=codes(alpha,esc,alias);let lambda=0,states=0;
  for(let iteration=0;iteration<maxIterations;iteration++){
    const dp=Array.from({length:source.length+1},()=>new Map());dp[0].set(0,{value:0,sum:0,n:0,previous:null});
    function set(at,node,r){const old=dp[at].get(node);if(!old||r.value>old.value)dp[at].set(node,r);}
    for(let i=0;i<source.length;i++){
      states+=dp[i].size;
      for(const [node,r]of dp[i])for(const [letter,next]of nodes[node].next){
        const code=encoded[letter];if(!source.startsWith(code,i))continue;
        const at=i+code.length,rec={value:r.value-lambda,sum:r.sum,n:r.n+1,previous:r,letter};
        set(at,next,rec);
        if(nodes[next].logp!==null)set(at,0,{value:rec.value+nodes[next].logp,sum:rec.sum+nodes[next].logp,n:rec.n,previous:rec,word:nodes[next].word});
      }
      dp[i].clear();
    }
    const best=dp[source.length].get(0);if(!best)return {complete:true,found:false,states,iterations:iteration+1};
    const mean=best.sum/best.n;
    if(!perCharacter||Math.abs(mean-lambda)<1e-11){
      const text=[],tokens=[];for(let r=best;r.previous;r=r.previous){if(r.letter!==undefined)text.push(String.fromCharCode(65+r.letter));if(r.word!==undefined)tokens.push(r.word);}
      text.reverse();tokens.reverse();assert.equal(tokens.join(''),text.join(''));
      assert.equal([...text].map(c=>encoded[c.charCodeAt(0)-65]).join(''),source);
      return {complete:true,found:true,text:text.join(''),words:tokens,sum:best.sum,mean,characters:best.n,states,iterations:iteration+1};
    }
    lambda=mean;
  }
  return {complete:false,found:false,states,iterations:maxIterations};
}
function main(){
  const J=require('./joint_checkerboard_search.cjs'),old=JSON.parse(fs.readFileSync(path.join(root,'_work','joint_checkerboard_2026-09-16','controls.json'))),probe=JSON.parse(fs.readFileSync(path.join(out,'probe_controls.json'))),results=[];
  for(const c of old)for(const [keyName,alpha]of [['true',c.alphabet],['old',c.best.alphabet],['exact-mask',probe.find(x=>x.index===c.index).best.alphabet]])for(const perCharacter of [false,true]){
    const start=Date.now(),r=optimize(c.source,alpha,c.esc,c.alias,{perCharacter});
    results.push({index:c.index,keyName,alphabet:alpha,source:c.source,esc:c.esc,alias:c.alias,expected:c.text,perCharacter,elapsedMs:Date.now()-start,...r});
    console.log(JSON.stringify({control:c.index,keyName,perCharacter,ms:Date.now()-start,found:r.found,states:r.states,exact:r.text===c.text,text:r.words?.join(' ')}));
    fs.writeFileSync(path.join(out,'word_controls.json'),JSON.stringify(results,null,2)+'\n');
  }
  fs.writeFileSync(path.join(out,'word_model.json'),JSON.stringify({source:'https://norvig.com/ngrams/count_1w.txt',rawSHA256:sha(raw),sourceSHA256:sha(fs.readFileSync(__filename)),entries:words.size,trieNodes:nodes.length,totalSourceCount:total,filter:'Lowercase a-z words up to 32 characters; one-letter words only a/i. Source total before filtering.',models:['maximum sum log10 probability','maximum mean log10 probability per decoded letter'],caveat:'Unigram word-frequency likelihood, no phrase/context model; never authentication.'},null,2)+'\n');
}
if(require.main===module)main();module.exports={optimize,codes,words,rawSHA256:sha(raw)};
