'use strict';
// Independently verifies all candidates and complete cases. Partial-case pruning
// certificates are coverage-checked, not independently certified as exclusions.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_joined_words_2026-09-16'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const spec=JSON.parse(fs.readFileSync(path.join(folder,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(folder,'summary.json')));
const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw);
const corpus=fs.readFileSync(path.join(root,'_work/checkerboard_exact_mask_2026-09-16/count_1w.txt'));
assert.equal(sha(raw),spec.inputSHA256);assert.equal(sha(corpus),spec.corpusSHA256);
const words=new Set(),prefixDistance=new Map([['',0]]);
for(const line of corpus.toString().split(/\r?\n/)) {
  const [w,count]=line.split(/\s+/);
  if(+count<spec.threshold||!/^[a-z]+$/.test(w)||w.length>32||w.length===1&&!['a','i'].includes(w))continue;
  words.add(w);
  for(let i=1;i<=w.length;i++){const p=w.slice(0,i);prefixDistance.set(p,Math.min(prefixDistance.get(p)??Infinity,w.length-i));}
}
assert.equal(words.size,spec.words);
function accept(text) {
  for(const run of text.match(/[a-z]+/g)||[]) {
    const reachable=new Uint8Array(run.length+1);reachable[0]=1;
    for(let start=0;start<run.length;start++)if(reachable[start]) {
      for(let end=start+1;end<=Math.min(run.length,start+32);end++) {
        const w=run.slice(start,end);if(!prefixDistance.has(w))break;
        if(words.has(w))reachable[end]=1;
      }
    }
    if(!reachable[run.length])return false;
  }
  return true;
}
function digits(n,base) {
  let p=1n;const b=BigInt(base),ds=[];while(p*b<=n)p*=b;
  do{ds.push(Number(n/p));n%=p;p/=b;}while(p);return ds;
}
function interval(lo,hi,alphabet) {
  const low=digits(lo,alphabet.length),high=digits(hi,alphabet.length);
  function step(prefixes,c) {
    if(c<'a'||c>'z')return prefixes.includes('')?['']:[];
    const next=[];
    for(const p of prefixes){const n=p+c;if(prefixDistance.has(n)){next.push(n);if(words.has(n))next.push('');}}
    return [...new Set(next)];
  }
  for(let len=low.length;len<=high.length;len++) {
    const l=len===low.length?low:[1,...Array(len-1).fill(0)],h=len===high.length?high:Array(len).fill(alphabet.length-1);
    function walk(at,prefixes,tightLow,tightHigh) {
      if(!prefixes.length)return false;
      if(Math.min(...prefixes.map(p=>prefixDistance.get(p)))>len-at)return false;
      if(at===len)return prefixes.includes('');
      if(!tightLow&&!tightHigh)return true;
      for(let d=tightLow?l[at]:0;d<=(tightHigh?h[at]:alphabet.length-1);d++)
        if(walk(at+1,step(prefixes,alphabet[d]),tightLow&&d===l[at],tightHigh&&d===h[at]))return true;
      return false;
    }
    if(walk(0,[''],true,true))return true;
  }
  return false;
}
function endpoints(source,mask) {
  let at=0;const lo=[],hi=[];
  for(const c of source) {
    if(c!=='g'){lo.push(c.charCodeAt(0)-96);hi.push(c.charCodeAt(0)-96);}
    else{const d=at<mask.length?(mask[at]==='1'?7:0):null;lo.push(d??0);hi.push(d??7);at++;}
  }
  return [BigInt(lo.join('')),BigInt(hi.join(''))];
}
let controls=0,bruteAssignments=0,verifiedCompleteCertificates=0,partialUnverifiedExclusions=0,hits=0;
for(const a of spec.alphabets)for(let k=0;k<25;k++) {
  const lo=BigInt(k*71),hi=lo+38n;let expected=false;
  for(let n=lo;n<=hi;n++)if(accept(digits(n,a.length).map(d=>a[d]).join(''))){expected=true;break;}
  assert.equal(interval(lo,hi,a),expected);controls++;
}
const reconstructed=new Map(),cases=[];
for(const record of summary.cases) {
  const bytes=fs.readFileSync(path.join(folder,record.file));assert.equal(sha(bytes),record.sha256);
  const r=JSON.parse(bytes),source=r.reverse?[...input[r.field]].reverse().join(''):input[r.field],alphabet=spec.alphabets[r.alphabetId],g=[...source].filter(c=>c==='g').length;
  const hitMasks=new Set();
  for(const hit of r.hits) {
    assert(/^[01]+$/.test(hit.mask)&&hit.mask.length===g);assert(!hitMasks.has(hit.mask));hitMasks.add(hit.mask);
    const [n,hi]=endpoints(source,hit.mask);assert.equal(n,hi);assert.equal(String(n),hit.decimal);
    const fromText=[...hit.text].reduce((n,c)=>{const d=alphabet.indexOf(c);assert(d>=0);return n*BigInt(alphabet.length)+BigInt(d);},0n);
    assert.equal(fromText,n);assert.notEqual(alphabet.indexOf(hit.text[0]),0);assert(accept(hit.text));
    if(!reconstructed.has(hit.text))reconstructed.set(hit.text,{id:reconstructed.size,...hit,provenance:record.file});hits++;
  }
  if(r.field==='dbbi') {
    const expected=[];
    for(let mask=0;mask<2**g;mask++) {
      const bits=Array.from({length:g},(_,i)=>String((mask>>i)&1)).join(''),[n]=endpoints(source,bits);
      if(accept(digits(n,alphabet.length).map(d=>alphabet[d]).join('')))expected.push(bits);
      bruteAssignments++;
    }
    assert.deepEqual(expected.sort(),[...hitMasks].sort());
  }else {
    const sorted=[...r.terminal].sort((a,b)=>a.mask.localeCompare(b.mask));let mass=0n,excluded=0n,pending=0n,leaves=0;
    for(let i=0;i<sorted.length;i++) {
      const t=sorted[i];assert(/^[01]*$/.test(t.mask)&&t.mask.length<=g);
      if(i)assert(!t.mask.startsWith(sorted[i-1].mask));
      const count=1n<<BigInt(g-t.mask.length);mass+=count;
      if(t.status==='excluded') {
        excluded+=count;
        if(r.complete){const [lo,hi]=endpoints(source,t.mask);assert(!interval(lo,hi,alphabet));verifiedCompleteCertificates++;}
        else partialUnverifiedExclusions++;
      }else if(t.status==='pending')pending+=count;
      else {assert.equal(t.status,'hit');assert.equal(t.mask.length,g);assert(hitMasks.has(t.mask));leaves++;}
    }
    assert.equal(mass,1n<<BigInt(g));assert.equal(String(excluded),r.excluded);assert.equal(String(pending),r.pending);assert.equal(leaves,r.hits.length);assert.equal(r.complete,pending===0n);
  }
  cases.push({file:record.file,complete:r.complete,hits:r.hits.length});
  console.log(JSON.stringify({verified:record.file,hits:r.hits.length,complete:r.complete}));
}
assert.deepEqual([...reconstructed.values()],JSON.parse(fs.readFileSync(path.join(folder,'candidates.json'))));
const result={verifiedAt:new Date().toISOString(),cases,allRecordedCandidatesVerified:true,uniqueCandidates:reconstructed.size,hits,bruteAssignments,
  verifiedCompleteCertificates,partialUnverifiedExclusions,allRecordedMaskCoveragesVerified:true,controls,
  method:'Word-boundary DP over a rebuilt vocabulary, full DBBI enumeration, both-bound interval feasibility for complete FAED cases. Every candidate reencoded and every partial case mask partition checked. Exclusions inside partial cases were not independently certified.',
  verifierSHA256:sha(fs.readFileSync(__filename)),candidatesSHA256:sha(fs.readFileSync(path.join(folder,'candidates.json')))};
fs.writeFileSync(path.join(folder,'independent_verification.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({...result,cases:cases.length},null,2));
