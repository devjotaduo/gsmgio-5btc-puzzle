'use strict';
// Independent arithmetic certificate verifier. Does not import the producer.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','positional_prime_prefix_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function primesBelow(max){const result=[];for(let n=2;n<max;n++){let yes=true;for(let d=2;d*d<=n;d++)if(n%d===0){yes=false;break;}if(yes)result.push(n);}return result;}
function coefficients(input,profile,radix,line){
  const powers=Array.from({length:14},(_,i)=>BigInt(radix)**BigInt(i)),result=[0n,0n,0n];
  for(let index=0;index<14;index++){
    const row=profile.axis==='row'?line:index,col=profile.axis==='row'?index:line,power=profile.reversePositions?index:13-index,color=input.colored.find(([,_,r,c])=>r===row&&c===col)?.[1];
    if(color)result[color==='B'?0:1]+=powers[power];else result[2]+=BigInt(input.matrix[row][col]===1?profile.white:profile.black)*powers[power];
  }
  return result;
}
const powers10=Array.from({length:100},(_,i)=>10n**BigInt(i));
function verifyRejection(low,high,target,position){
  assert(position>0);const length=low.toString().length;assert(high<powers10[length]);assert(position<=length);
  const scale=powers10[length-position],a=low/scale,b=high/scale;assert.equal(a,b);const digits=a.toString();assert.equal(digits.length,position);
  const last=position-1,digit=digits[last],letter=target[last];let contradiction=false;
  if(digit==='0'){const set=new Set();for(let i=0;i<=last;i++)if(digits[i]==='0')set.add(target[i]);contradiction=set.size>2;}
  else for(let i=0;i<last;i++)if(digits[i]!=='0'&&(target[i]===letter&&digits[i]!==digit||target[i]!==letter&&digits[i]===digit)){contradiction=true;break;}
  assert(contradiction,'No independent conflict witness at reported digit');return position;
}
function main(){
  const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),boundsRaw=fs.readFileSync(path.join(root,'_work','positional_prime_bases_2026-09-16','cases.json')),profiles=JSON.parse(boundsRaw).filter(c=>c.field==='faed'),raw=fs.readFileSync(path.join(out,'cases.jsonl')),records=raw.toString().trim().split(/\r?\n/).map(JSON.parse),cert=fs.readFileSync(path.join(out,'certificates.bin')),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
  assert(summary.finished&&summary.completeExclusion);assert.equal(sha(inputRaw),spec.inputSHA256);assert.equal(sha(boundsRaw),spec.boundsSHA256);assert.equal(sha(raw),summary.casesSHA256);assert.equal(sha(cert),summary.certificatesSHA256);assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(__dirname,'positional_prime_prefix.cjs'))));
  const expected=new Set();const allPrimes=primesBelow(1+Math.max(...profiles.flatMap(p=>p.primeBases))),targets=[input.faed,[...input.faed].reverse().join('')];
  // Independently recompute the bounds used to restrict an otherwise unbounded radix.
  function length(radix,profile,upper){const digit=upper?BigInt(radix-1):2n;let n=0;for(let line=0;line<14;line++){const c=coefficients(input,profile,radix,line);n+=((c[0]+c[1])*digit+c[2]).toString().length;}return n;}
  for(const [i,p]of profiles.entries()){
    assert(length(p.lower,p,true)>=570);if(p.lower>3)assert(length(p.lower-1,p,true)<570);assert(length(p.upper,p,false)<=570);assert(length(p.upper+1,p,false)>570);
    assert.deepEqual(p.primeBases,allPrimes.filter(r=>r>=p.lower&&r<=p.upper));for(const radix of p.primeBases)for(const line of [0,13])expected.add([i,radix,line].join('/'));
  }
  let offset=0,values=0,checks=0,pairs=0n;const histogram={};
  for(const c of records){
    assert(expected.delete([c.profileIndex,c.radix,c.firstLine].join('/')));assert.equal(c.unresolved.length,0);const pp=allPrimes.filter(p=>p<c.radix),coef=coefficients(input,profiles[c.profileIndex],c.radix,c.firstLine),dominant=c.dominant==='B'?0:1,other=1-dominant;
    assert.equal(dominant,coef[0]>=coef[1]?0:1);assert.equal(pp.length,c.primeCount);assert.equal(c.certificateOffset,offset);assert.equal(c.certificateLength,pp.length*2);
    const lowerOther=coef[other]*BigInt(pp[0])+coef[2],upperOther=coef[other]*BigInt(pp.at(-1))+coef[2];
    for(let i=0;i<pp.length;i++){const fixed=coef[dominant]*BigInt(pp[i]);for(let reverse=0;reverse<2;reverse++){const k=cert[offset+2*i+reverse];verifyRejection(fixed+lowerOther,fixed+upperOther,targets[reverse],k);histogram[k]=(histogram[k]||0)+1;checks++;}}
    values+=pp.length;pairs+=2n*BigInt(pp.length)**2n;offset+=c.certificateLength;
  }
  assert.equal(expected.size,0);assert.equal(offset,cert.length);assert.equal(checks,summary.certificateBytes);assert.equal(values,summary.dominantValues);assert.equal(String(pairs),summary.coveredPairs);
  const result={complete:true,cases:records.length,dominantValues:values,intervalCertificates:checks,coveredParameterCases:String(pairs),unresolved:0,boundariesIndependentlyChecked:true,certificatePositionHistogram:histogram,casesSHA256:sha(raw),certificatesSHA256:sha(cert),verifierSHA256:sha(fs.readFileSync(__filename)),scope:'Every interval certificate and the full prime-domain coverage. Independent matrix powers, trial-division primes, numeric prefix equality by division, and relational letter/digit contradictions. Natural/reversed line order only.'};fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();module.exports={coefficients,primesBelow,verifyRejection};
