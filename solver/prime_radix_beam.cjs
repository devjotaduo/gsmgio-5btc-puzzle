'use strict';
// Heuristic language ranking of g=0/7 assignments. Never an exhaustive exclusion.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {alphabets,shape}=require('./prime_alphabet_words.cjs');
const root=path.resolve(__dirname,'..'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const raw=fs.readFileSync(path.join(root,'_work/ambiguous_checkerboard_2026-09-15/general_english/quadgram.f32'));
assert.equal(sha(raw),'d2a64e70154725a0c0d1901690df47c73086e0bfc112ad419aad2eb069f89a43');
const quad=Array.from({length:26**4},(_,i)=>raw.readFloatLE(i*4));
const baseline=quad.reduce((s,x)=>s+x,0)/quad.length, symbols='0123456789abcdefghijklmnopqrstuvwxyz';
function evaluate(text) {
  let history=0,letters=0,sum=0;
  for(const c of text)if(c>='a'&&c<='z') {
    const d=c.charCodeAt(0)-97;if(letters>=3)sum+=quad[history*26+d];
    history=(history*26+d)%(26**3);letters++;
  }
  const count=Math.max(0,letters-3);
  return {letters,quadSum:sum,quadMean:count?sum/count:null,score:sum-baseline*count};
}
function decode(n,alphabet) {
  assert(alphabet.length<=36);
  return [...n.toString(alphabet.length)].map(c=>alphabet[symbols.indexOf(c)]).join('');
}
function stablePrefix(lo,hi,alphabet) {
  const a=lo.toString(alphabet.length),b=hi.toString(alphabet.length);
  if(a.length!==b.length)return '';
  let i=0;while(i<a.length&&a[i]===b[i])i++;
  return [...a.slice(0,i)].map(c=>alphabet[symbols.indexOf(c)]).join('');
}
function beam(source,alphabet,width,truth=null) {
  const {base,weights,tail}=shape(source),trace=[];
  let frontier=[{lo:base,mask:'',score:0}],evaluated=0,firstTruthDrop=null;
  for(let depth=0;depth<weights.length;depth++) {
    const next=[];
    for(const prior of frontier)for(const bit of [0,1]) {
      const lo=prior.lo+(bit?weights[depth]:0n),mask=prior.mask+bit;
      const prefix=stablePrefix(lo,lo+tail[depth+1],alphabet),rank=evaluate(prefix);
      next.push({lo,mask,score:rank.score,prefixLength:prefix.length});evaluated++;
    }
    next.sort((a,b)=>b.score-a.score||a.mask.localeCompare(b.mask));
    frontier=next.slice(0,width);
    if(truth&&!frontier.some(r=>truth.startsWith(r.mask))&&firstTruthDrop===null)firstTruthDrop=depth+1;
    trace.push({depth:depth+1,proposed:next.length,kept:frontier.length,best:frontier[0].score,cutoff:frontier.at(-1).score,
      minPrefix:Math.min(...frontier.map(r=>r.prefixLength)),maxPrefix:Math.max(...frontier.map(r=>r.prefixLength))});
  }
  const candidates=frontier.map(r=>{const text=decode(r.lo,alphabet),score=evaluate(text);assert.equal(score.score,r.score);return{mask:r.mask,decimal:String(r.lo),text,...score};});
  return {width,assignments: String(1n<<BigInt(weights.length)),evaluated,retained:candidates.length,firstTruthDrop,trace,candidates,
    exhaustive:BigInt(width)>=(1n<<BigInt(weights.length))};
}
function plant(text,alphabet) {
  const n=[...text].reduce((n,c)=>{const d=alphabet.indexOf(c);assert(d>=0);return n*BigInt(alphabet.length)+BigInt(d);},0n);
  assert.equal(decode(n,alphabet),text);
  let mask='';const source=[...String(n)].map(d=>{if(d==='0'||d==='7')mask+=d==='7'?'1':'0';return String.fromCharCode(96+(+d||7));}).join('');
  return {source,mask};
}
function shuffled(source) {
  const a=[...source],positions=a.flatMap((c,i)=>i>=16&&c!=='g'?[i]:[]);let state=0x5a170091;
  for(let i=positions.length-1;i>0;i--) {state=(Math.imul(state,1664525)+1013904223)>>>0;const j=state%(i+1);[a[positions[i]],a[positions[j]]]=[a[positions[j]],a[positions[i]]];}
  assert.equal(a.slice(0,16).join(''),source.slice(0,16));assert(a.every((c,i)=>(c==='g')===(source[i]==='g')));
  assert.equal([...source.slice(16)].sort().join(''),a.slice(16).sort().join(''));
  return a.join('');
}
function main() {
  const folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_radix_beam_2026-09-16'));
  assert(!fs.existsSync(folder),'Choose a fresh output folder');
  const inputRaw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(inputRaw),width=1024;
  const models=[{reverse:false,alphabetId:0},{reverse:false,alphabetId:1},{reverse:false,alphabetId:2},{reverse:false,alphabetId:3},{reverse:true,alphabetId:2}];
  fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,'spec.json'),JSON.stringify({sourceSHA256:sha(fs.readFileSync(__filename)),inputSHA256:sha(inputRaw),quadgramSHA256:sha(raw),baseline,width,models,alphabets,
    hypothesis:'The five partial word-concatenation prime-radix FAED models. Each g independently 0/7; all other letters fixed a1..i9. Retain a beam of1024 partial masks at each g. Rank the radix prefix fixed by the entire remaining numeric interval using lowercase letter quadgrams, ignoring separators. Sum minus uniform-quadgram baseline per gram; deterministic lexical-mask tie break.',
    limits:'Heuristic ranking only, not proof of optimality, exhaustive coverage or English. One shuffled comparison per model is not a p-value. Only final retained actual-input candidates go to AES; controls/nulls are excluded.'},null,2)+'\n');
  const texts=[input.phase32_text.slice(0,440).toLowerCase().replace(/\s+/g,' ').trim(),
    'follow the numbers carefully and write down every step before changing the order of the symbols. a useful answer must explain the entire message and reproduce the original sequence without leaving any part unused. when a proposed method gives only a few familiar words among random letters, those words are not enough to establish that the method is correct. compare the result with a separate calculation and preserve the exact spelling.'];
  const controls=[];
  for(let alphabetId=0;alphabetId<4;alphabetId++)for(const [textId,text0]of texts.entries()) {
    const alphabet=alphabets[alphabetId],text=[...text0].filter(c=>alphabet.includes(c)).join(''),p=plant(text,alphabet),result=beam(p.source,alphabet,width,p.mask);
    const rank=result.candidates.findIndex(c=>c.text===text),name=`control_${alphabetId}_${textId}.json`;
    fs.writeFileSync(path.join(folder,name),JSON.stringify({alphabetId,textId,text,source:p.source,truthMask:p.mask,...result})+'\n');
    const record={alphabetId,textId,file:name,rank,firstTruthDrop:result.firstTruthDrop,sourceLength:p.source.length,ambiguities:p.mask.length,trueScore:evaluate(text),bestScore:result.candidates[0].score};controls.push(record);console.log(JSON.stringify({control:record}));
  }
  fs.writeFileSync(path.join(folder,'controls.json'),JSON.stringify(controls,null,2)+'\n');
  assert(controls.every(c=>c.rank>=0),'Calibration failed: inspect before using the heuristic on real data');
  const cases=[],all=new Map();
  for(const [modelId,model]of models.entries())for(const kind of ['actual','shuffled']) {
    let source=model.reverse?[...input.faed].reverse().join(''):input.faed;if(kind==='shuffled')source=shuffled(source);
    const result=beam(source,alphabets[model.alphabetId],width),file=`${kind}_${modelId}.json`;
    fs.writeFileSync(path.join(folder,file),JSON.stringify({modelId,...model,kind,source,...result})+'\n');
    if(kind==='actual')for(const c of result.candidates)if(!all.has(c.text))all.set(c.text,{id:all.size,...c,provenance:file});
    const record={modelId,...model,kind,file,evaluated:result.evaluated,retained:result.retained,exhaustive:result.exhaustive,best:result.candidates[0],sha256:sha(fs.readFileSync(path.join(folder,file)))};cases.push(record);
    console.log(JSON.stringify({model:modelId,kind,bestScore:record.best.score,quadMean:record.best.quadMean,preview:record.best.text.slice(0,140)}));
  }
  fs.writeFileSync(path.join(folder,'candidates.json'),JSON.stringify([...all.values()],null,2)+'\n');
  fs.writeFileSync(path.join(folder,'summary.json'),JSON.stringify({completedBeamRuns:true,exhaustive:false,controls,cases,candidates:all.size,finalPasswordFound:false},null,2)+'\n');
}
if(require.main===module)main();
module.exports={evaluate,decode,stablePrefix,beam,plant,shuffled};
