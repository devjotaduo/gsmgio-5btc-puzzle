'use strict';
// Independent candidate reconstruction and ranking checks. No optimality claim.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_radix_beam_2026-09-16'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(inputRaw);
const spec=JSON.parse(fs.readFileSync(path.join(folder,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(folder,'summary.json')));
const profile=fs.readFileSync(path.join(root,'_work/ambiguous_checkerboard_2026-09-15/general_english/quadgram.f32'));
assert.equal(sha(profile),spec.quadgramSHA256);assert.equal(sha(inputRaw),spec.inputSHA256);
assert.equal(sha(fs.readFileSync(path.join(root,'solver/prime_radix_beam.cjs'))),spec.sourceSHA256);
let baseline=0;for(let i=0;i<profile.length;i+=4)baseline+=profile.readFloatLE(i);baseline/=26**4;
assert.equal(baseline,spec.baseline);
function rank(text) {
  const s=text.replace(/[^a-z]/g,'');let sum=0;
  for(let i=0;i+3<s.length;i++) {
    const index=[...s.slice(i,i+4)].reduce((n,c)=>n*26+c.charCodeAt(0)-97,0);
    sum+=profile.readFloatLE(4*index);
  }
  return {letters:s.length,quadSum:sum,quadMean:s.length>3?sum/(s.length-3):null,score:sum-baseline*Math.max(0,s.length-3)};
}
function number(source,mask) {
  let i=0;const decimal=Array.from(source,c=>c==='g'?(mask[i++]==='1'?'7':'0'):String(c.charCodeAt(0)-96)).join('');
  assert.equal(i,mask.length);return BigInt(decimal);
}
function decode(n,alphabet) {
  const base=BigInt(alphabet.length);let text='';
  do{text=alphabet[Number(n%base)]+text;n/=base;}while(n);return text;
}
function verify(row) {
  const alphabet=spec.alphabets[row.alphabetId],seen=new Set(),g=Array.from(row.source).filter(c=>c==='g').length;
  assert.equal(row.assignments,String(1n<<BigInt(g)));
  for(const c of row.candidates) {
    assert(c.mask.length===g&&/^[01]+$/.test(c.mask));assert(!seen.has(c.mask));seen.add(c.mask);
    const n=number(row.source,c.mask);assert.equal(String(n),c.decimal);assert.equal(decode(n,alphabet),c.text);
    const actual=rank(c.text);for(const k of ['letters','quadSum','quadMean','score'])assert.equal(actual[k],c[k]);
  }
  for(let i=1;i<row.candidates.length;i++) {
    const a=row.candidates[i-1],b=row.candidates[i];assert(a.score>b.score||a.score===b.score&&a.mask.localeCompare(b.mask)<=0);
  }
  assert.equal(row.trace.length,g);assert.equal(row.retained,row.candidates.length);
  row.trace.forEach((t,i)=>{assert.equal(t.depth,i+1);assert.equal(t.kept,Math.min(spec.width,2**(i+1)));assert.equal(t.proposed,i?2*row.trace[i-1].kept:2);});
  return row.candidates.length;
}
// Small beams retaining all masks must agree with a separately enumerated ranking.
const {beam}=require('./prime_radix_beam.cjs');let controls=0,bruteAssignments=0;
for(const alphabet of spec.alphabets.slice(0,4))for(const source of ['faedggabcgg','ggbbgfdgg','abiggggggg']) {
  const g=Array.from(source).filter(c=>c==='g').length,wanted=[];
  for(let m=0;m<2**g;m++) {
    const mask=m.toString(2).padStart(g,'0'),n=number(source,mask),text=decode(n,alphabet);
    wanted.push({mask,decimal:String(n),text,...rank(text)});bruteAssignments++;
  }
  wanted.sort((a,b)=>b.score-a.score||a.mask.localeCompare(b.mask));
  const actual=beam(source,alphabet,1024);assert(actual.exhaustive);assert.deepEqual(actual.candidates,wanted);controls++;
}
let planted=0,retained=0;const files={},actualCandidates=new Map();
for(const c of summary.controls) {
  const bytes=fs.readFileSync(path.join(folder,c.file)),row=JSON.parse(bytes);retained+=verify(row);
  const position=row.candidates.findIndex(r=>r.text===row.text);
  assert.equal(position,c.rank);assert(position>=0);assert.equal(row.firstTruthDrop,null);
  const n=[...row.text].reduce((n,ch)=>n*BigInt(spec.alphabets[row.alphabetId].length)+BigInt(spec.alphabets[row.alphabetId].indexOf(ch)),0n);
  assert.equal(number(row.source,row.truthMask),n);planted++;files[c.file]=sha(bytes);
}
for(const c of summary.cases) {
  const bytes=fs.readFileSync(path.join(folder,c.file)),row=JSON.parse(bytes),source=c.reverse?[...input.faed].reverse().join(''):input.faed;
  assert.equal(sha(bytes),c.sha256);assert(!row.exhaustive);retained+=verify(row);
  if(c.kind==='actual') {
    assert.equal(row.source,source);
    for(const x of row.candidates)if(!actualCandidates.has(x.text))actualCandidates.set(x.text,{id:actualCandidates.size,...x,provenance:c.file});
  }else {
    assert.equal(c.kind,'shuffled');assert.equal(row.source.slice(0,16),source.slice(0,16));
    assert.equal([...row.source.slice(16)].sort().join(''),[...source.slice(16)].sort().join(''));
    assert([...source].every((x,i)=>(x==='g')===(row.source[i]==='g')));
  }
  assert.deepEqual(row.candidates[0],c.best);files[c.file]=sha(bytes);
}
assert.deepEqual([...actualCandidates.values()],JSON.parse(fs.readFileSync(path.join(folder,'candidates.json'))));
const result={verifiedAt:new Date().toISOString(),plantedRecovered:planted,plantedRanks:summary.controls.map(c=>c.rank),smallExhaustiveBeamComparisons:controls,bruteAssignments,
  finalRetainedCandidatesReconstructed:retained,actualUniqueCandidates:actualCandidates.size,method:'Independent decimal reconstruction, radix conversion, sliced-quadgram scoring and small exhaustive rankings. Final candidates and control recovery verified; the heuristic beam is not an exhaustive search or a proof of global score optimum.',
  verifierSHA256:sha(fs.readFileSync(__filename)),files};
fs.writeFileSync(path.join(folder,'independent_verification.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({...result,files:Object.keys(files).length},null,2));
