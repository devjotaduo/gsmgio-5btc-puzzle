'use strict';
// k-best distinct letter strings under the same word-unigram model.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const W=require('./checkerboard_word_decoder.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','checkerboard_exact_mask_2026-09-16');
const model=JSON.parse(fs.readFileSync(path.join(out,'word_model.json'))),trie=[{next:{},word:null,score:null}];
for(const [word,count]of W.words){let at=0;for(const c of word){if(trie[at].next[c]===undefined){trie[at].next[c]=trie.length;trie.push({next:{},word:null,score:null});}at=trie[at].next[c];}trie[at].word=word;trie[at].score=Math.log10(count/model.totalSourceCount);}
function codebook(alpha,esc,alias){
  const encoded={};let at=0;const codes=[];for(let d=0;d<10;d++)if(d!==esc[0]&&d!==esc[1])codes.push(String(d));for(const e of esc)for(let d=0;d<10;d++)codes.push(String(e)+d);
  for(const code of codes){const char=alpha[at++];if(char!=='.')encoded[char]=code.replaceAll('0','X').replace(/[1-9]/g,d=>String.fromCharCode(96+Number(d))).replaceAll('X',alias);}
  assert.equal(Object.keys(encoded).length,26);return encoded;
}
function graph(source,alpha,esc,alias){
  const codes=codebook(alpha,esc,alias),edges=Array.from({length:source.length+1},()=>[]);
  for(let start=0;start<source.length;start++){
    function walk(at,node){
      if(trie[node].word!==null)edges[start].push({end:at,word:trie[node].word,score:trie[node].score});
      for(const [c,next]of Object.entries(trie[node].next))if(source.startsWith(codes[c],at))walk(at+codes[c].length,next);
    }
    walk(start,0);
  }
  return edges;
}
function paths(source,alpha,esc,alias,{limit=100,maxPops=200000}={}){
  const edges=graph(source,alpha,esc,alias),suffix=Array(source.length+1).fill(-Infinity);suffix[source.length]=0;
  for(let i=source.length-1;i>=0;i--)for(const e of edges[i])suffix[i]=Math.max(suffix[i],e.score+suffix[e.end]);
  if(!Number.isFinite(suffix[0]))return {texts:[],complete:true,pops:0,wordEdges:edges.reduce((n,a)=>n+a.length,0)};
  const heap=[],seen=new Map(),texts=[];
  function push(r){let i=heap.length;heap.push(r);while(i>0){const p=(i-1)>>1;if(heap[p].bound>=r.bound)break;heap[i]=heap[p];i=p;heap[i]=r;}}
  function pop(){const r=heap[0],last=heap.pop();if(heap.length){heap[0]=last;let i=0;while(true){const a=2*i+1,b=a+1;let k=i;if(a<heap.length&&heap[a].bound>heap[k].bound)k=a;if(b<heap.length&&heap[b].bound>heap[k].bound)k=b;if(k===i)break;[heap[i],heap[k]]=[heap[k],heap[i]];i=k;}}return r;}
  push({at:0,text:'',words:[],sum:0,bound:suffix[0]});let pops=0;
  while(heap.length&&texts.length<limit&&pops<maxPops){
    const r=pop();pops++;const id=r.at+'/'+r.text;if((seen.get(id)??-Infinity)>=r.sum-1e-10)continue;seen.set(id,r.sum);
    if(r.at===source.length){texts.push({text:r.text,words:r.words,sum:r.sum,mean:r.sum/r.text.length});continue;}
    for(const e of edges[r.at])if(Number.isFinite(suffix[e.end]))push({at:e.end,text:r.text+e.word,words:[...r.words,e.word],sum:r.sum+e.score,bound:r.sum+e.score+suffix[e.end]});
  }
  for(let i=1;i<texts.length;i++)assert(texts[i].sum<=texts[i-1].sum+1e-8);
  return {texts,complete:!heap.length||texts.length===limit,exhaustive:!heap.length,pops,remainingHeap:heap.length,wordEdges:edges.reduce((n,a)=>n+a.length,0),optimum:suffix[0]};
}
function main(){
  const controls=JSON.parse(fs.readFileSync(path.join(root,'_work','joint_checkerboard_2026-09-16','controls.json'))),rows=[];
  for(const c of controls){const start=Date.now(),r=paths(c.source,c.alphabet,c.esc,c.alias,{limit:200}),rank=r.texts.findIndex(t=>t.text===c.text);rows.push({index:c.index,alphabet:c.alphabet,esc:c.esc,alias:c.alias,source:c.source,expected:c.text,correctRank:rank<0?null:rank+1,elapsedMs:Date.now()-start,...r});console.log(JSON.stringify({control:c.index,correctRank:rank<0?null:rank+1,texts:r.texts.length,pops:r.pops,complete:r.complete,ms:Date.now()-start}));fs.writeFileSync(path.join(out,'word_path_controls.json'),JSON.stringify(rows,null,2)+'\n');}
}
if(require.main===module)main();module.exports={paths,graph,codebook};
