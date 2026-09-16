/* Fixed-alignment matrix-list keystream, then the authenticated phase-3.2
 * checkerboard. All single zero aliases, original/reversed fields.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {domains,optimize,board,encode,score,ALPHA,CONTROL_TEXT}=require('./ambiguous_checkerboard.cjs');
const {baseLists}=require('./decimal_keystream_constraints.cjs'),{colorLists}=require('./decimal_carry_color.cjs');
const root=path.resolve(__dirname,'..'),base=path.join(root,'_work','ambiguous_checkerboard_2026-09-15'),profile=process.env.GSMG_CHECKERBOARD_PROFILE==='general'?path.join(base,'general_english'):base,out=path.join(profile,'matrix_keys');fs.mkdirSync(out,{recursive:true});
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const lists=[...baseLists(),...colorLists().lists],keys=new Map();
for(const list of lists)for(const form of ['residue10','decimal-digits'])for(const reverse of [false,true]) {
  let values=form==='residue10'?list.values.map(v=>((v%10)+10)%10):[...list.values.join('')].map(Number);if(reverse)values.reverse();
  const key=values.join(''),label={list:list.name,form,reverse};if(!keys.has(key))keys.set(key,{values,labels:[]});keys.get(key).labels.push(label);
}
const table=board(ALPHA,[1,4]);let planted=0,exactRecovery=0;
for(const key of [[6,0,8,7,6,6,5,4,9,9,7,8,7,9],[5,4,4,7]])for(const mode of ['subtract','add','beaufort'])for(const alias of 'abcdefghi') {
  const digits=encode(CONTROL_TEXT,table),cipher=[...digits].map((d,i)=>{
    const p=Number(d),k=key[i%key.length],c=((mode==='subtract'?p+k:mode==='add'?p-k:k-p)%10+10)%10;return c===0?alias:String.fromCharCode(96+c);
  }).join(''),r=optimize(domains(cipher,alias,key,mode),table,[1,4]);assert(r&&r.score>=score(CONTROL_TEXT)-1e-10);planted++;if(r.text===CONTROL_TEXT)exactRecovery++;
}
const spec={hypothesis:'Fixed-alignment cyclic decimal key from matrix lists, inverse mod10 add/subtract/Beaufort, then phase32 checkerboard alphabet with ordered escapes [1,4]. A1..I9, any single alias also zero; both full field directions.',
  caveat:'Highest mean quadgram-score plaintext only, not an exhaustive password search; no unknown alphabet, offset or transposition.',lists,keys:[...keys].map(([key,v])=>({key,...v})),alphabet:ALPHA,esc:[1,4],
  controls:{planted,exactRecovery},inputSHA256:sha(inputBytes),sourceSHA256:sha(fs.readFileSync(__filename)),optimizerSHA256:sha(fs.readFileSync(path.join(__dirname,'ambiguous_checkerboard.cjs')))};
fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');console.log(JSON.stringify({lists:lists.length,keys:keys.size,controls:spec.controls}));
const file=path.join(out,'ranked.jsonl');fs.writeFileSync(file,'');let cases=0,noPath=0,states=0;const best=[];
for(const field of ['dbbi','faed'])for(const reverse of [false,true]) {
  const source=reverse?[...input[field]].reverse().join(''):input[field];let groupBest=null;
  for(const [key,k] of keys)for(const mode of ['subtract','add','beaufort'])for(const alias of 'abcdefghi') {
    cases++;const r=optimize(domains(source,alias,k.values,mode),table,[1,4]);if(!r){noPath++;continue;}
    const record={field,reverse,key,mode,alias,esc:[1,4],...r};states+=r.states;fs.appendFileSync(file,JSON.stringify(record)+'\n');if(!groupBest||r.score>groupBest.score)groupBest=record;
  }
  best.push(groupBest);console.log(JSON.stringify({field,reverse,cases,noPath,bestScore:groupBest?.score,head:groupBest?.text.slice(0,100)}));
}
fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify({cases,noPath,states,best,controls:spec.controls},null,2)+'\n');
