'use strict';
// Independent interval feasibility with word-prefix strings; no successor/trie import.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),folder=path.resolve(process.argv[2]||path.join(root,'_work/prime_alphabet_words_2026-09-16'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const spec=JSON.parse(fs.readFileSync(path.join(folder,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(folder,'summary.json')));
const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw);
const corpus=fs.readFileSync(path.join(root,'_work/checkerboard_exact_mask_2026-09-16/count_1w.txt'));
assert.equal(sha(raw),spec.inputSHA256);assert.equal(sha(corpus),spec.corpusSHA256);
assert.equal(sha(fs.readFileSync(path.join(root,'solver/prime_alphabet_words.cjs'))),spec.sourceSHA256);
const words=new Set(),distance=new Map([['',0]]);
for(const line of corpus.toString().split(/\r?\n/)) {
  const w=line.split(/\s+/)[0];
  if(!/^[a-z]+$/.test(w)||w.length>32||w.length===1&&!['a','i'].includes(w))continue;
  words.add(w);
  for(let i=1;i<=w.length;i++) {const p=w.slice(0,i),d=w.length-i;distance.set(p,Math.min(distance.get(p)??Infinity,d));}
}
assert.equal(words.size,spec.words);
const accept=text=>(text.match(/[a-z]+/g)||[]).every(w=>words.has(w));
function radix(n,b) {
  const base=BigInt(b);let power=1n;
  while(power*base<=n)power*=base;
  const out=[];
  do{out.push(Number(n/power));n%=power;power/=base;}while(power);
  return out;
}
function intervalHasWordText(lo,hi,alphabet) {
  assert(lo<=hi&&lo>=0n);
  const base=alphabet.length,ld=radix(lo,base),hd=radix(hi,base);
  for(let length=ld.length;length<=hd.length;length++) {
    const left=length===ld.length?ld:[1,...Array(length-1).fill(0)];
    const right=length===hd.length?hd:Array(length).fill(base-1);
    function walk(at,prefix,lower,upper) {
      const remaining=length-at;
      if((distance.get(prefix)??Infinity)>remaining)return false;
      if(!lower&&!upper)return true; // Complete a shortest word, then pad with separators.
      if(!remaining)return prefix===''||words.has(prefix);
      const min=lower?left[at]:0,max=upper?right[at]:base-1;
      for(let d=min;d<=max;d++) {
        const ch=alphabet[d];let next;
        if(ch>='a'&&ch<='z') {next=prefix+ch;if(!distance.has(next))continue;}
        else {if(prefix&&!words.has(prefix))continue;next='';}
        if(walk(at+1,next,lower&&d===left[at],upper&&d===right[at]))return true;
      }
      return false;
    }
    if(walk(0,'',true,true))return true;
  }
  return false;
}

let controls=0;
for(const alphabet of spec.alphabets) {
  for(let k=0;k<40;k++) {
    const lo=BigInt(k*71),hi=lo+38n;
    let brute=false;
    for(let n=lo;n<=hi;n++)if(accept(radix(n,alphabet.length).map(d=>alphabet[d]).join(''))){brute=true;break;}
    assert.equal(intervalHasWordText(lo,hi,alphabet),brute);controls++;
  }
  for(const text of ['the matrix has you','follow the white rabbit','the answer is here']) {
    const n=[...text].reduce((n,c)=>n*BigInt(alphabet.length)+BigInt(alphabet.indexOf(c)),0n);
    assert(intervalHasWordText(n,n,alphabet));controls++;
  }
}
let models=0,certificates=0,dbbiAssignments=0;
const caseHashes={},seen=new Set();
for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(let alphabetId=0;alphabetId<spec.alphabets.length;alphabetId++) {
  const alphabet=spec.alphabets[alphabetId],file=`${field}_${reverse?'reverse':'forward'}_${alphabetId}.json`;
  const rawCase=fs.readFileSync(path.join(folder,file)),record=JSON.parse(rawCase);
  assert.equal(record.field,field);assert.equal(record.reverse,reverse);assert.equal(record.alphabetId,alphabetId);
  assert(record.complete);assert.equal(record.hits.length,0);assert.equal(record.pending,'0');
  const s=reverse?Array.from(input[field]).reverse().join(''):input[field],count=[...s].filter(c=>c==='g').length;
  const masks=record.terminal.map(t=>t.mask).sort();
  for(let i=1;i<masks.length;i++)assert(!masks[i].startsWith(masks[i-1]));
  let covered=0n;
  for(const t of record.terminal) {
    assert.equal(t.status,'excluded');assert(/^[01]*$/.test(t.mask)&&t.mask.length<=count);
    let at=0;const low=[],high=[];
    for(const ch of s) {
      if(ch!=='g'){low.push(ch.charCodeAt(0)-96);high.push(ch.charCodeAt(0)-96);continue;}
      if(at<t.mask.length){low.push(t.mask[at]==='1'?7:0);high.push(low.at(-1));}
      else {low.push(0);high.push(7);}at++;
    }
    assert(!intervalHasWordText(BigInt(low.join('')),BigInt(high.join('')),alphabet));
    covered+=1n<<BigInt(count-t.mask.length);certificates++;
  }
  assert.equal(covered,1n<<BigInt(count));assert.equal(String(covered),record.excluded);
  if(field==='dbbi')for(let mask=0;mask<2**count;mask++) {
    let at=0;const n=BigInt([...s].map(ch=>ch==='g'?((mask>>at++)&1?7:0):ch.charCodeAt(0)-96).join(''));
    assert(!accept(radix(n,alphabet.length).map(d=>alphabet[d]).join('')));dbbiAssignments++;
  }
  caseHashes[file]=sha(rawCase);assert.equal(summary.cases.find(c=>c.file===file).sha256,caseHashes[file]);
  seen.add(file);models++;
}
assert.equal(models,24);assert.equal(seen.size,summary.cases.length);assert(summary.complete&&summary.candidates===0);
const result={verifiedAt:new Date().toISOString(),complete:true,models,certificates,dbbiAssignments,controls,wordCount:words.size,
  method:'Rebuilt word-prefix Map; direct interval digit DP with both bounds, no producer successor. Independently reconstructs every decimal interval and full binary-mask coverage. Brute-force every DBBI assignment.',
  corpusSHA256:sha(corpus),caseHashes,verifierSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(folder,'independent_verification.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({...result,caseHashes:models},null,2));
