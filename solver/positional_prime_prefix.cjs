'use strict';
// Necessary first-number constraints for the finite prime-radix intervals.
// Unknown digit bijection; zero may be represented by at most two letters.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','positional_prime_prefix_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),boundsRaw=fs.readFileSync(path.join(root,'_work','positional_prime_bases_2026-09-16','cases.json')),bounds=JSON.parse(boundsRaw);
const colors=new Map(input.colored.map(([,color,r,c])=>[r+','+c,color]));
const MAX_BASE=Math.max(...bounds.flatMap(c=>c.primeBases)),sieve=new Uint8Array(MAX_BASE+1).fill(1);sieve[0]=sieve[1]=0;for(let d=2;d*d<=MAX_BASE;d++)if(sieve[d])for(let n=d*d;n<=MAX_BASE;n+=d)sieve[n]=0;const primes=Array.from(sieve.keys()).filter(n=>sieve[n]);
function coefficients(radix,profile,line){
  const result=[0n,0n,0n],r=BigInt(radix);
  for(let j=0;j<14;j++){
    for(let k=0;k<3;k++)result[k]*=r;
    const index=profile.reversePositions?13-j:j,[row,col]=profile.axis==='row'?[line,index]:[index,line],color=colors.get(row+','+col);
    if(color)result[color==='B'?0:1]++;else result[2]+=BigInt(input.matrix[row][col]?profile.white:profile.black);
  }
  return result;
}
function common(low,high){const a=String(low),b=String(high);if(a.length!==b.length)return '';let n=0;while(n<a.length&&a[n]===b[n])n++;return a.slice(0,n);}
function matcher(target,maxZeroLetters=2){
  const indexes=Int8Array.from(target,c=>c.charCodeAt(0)-97),map=new Int8Array(9),inverse=new Int8Array(10),zeroSeen=new Uint8Array(9);
  return digits=>{
    assert(digits.length<=target.length);map.fill(0);inverse.fill(-1);zeroSeen.fill(0);let zeros=0;
    for(let pos=0;pos<digits.length;pos++){
      const c=indexes[pos],d=digits.charCodeAt(pos)-48;
      if(d===0){if(!zeroSeen[c]){zeroSeen[c]=1;if(++zeros>maxZeroLetters)return pos+1;}}
      else {if(map[c]&&map[c]!==d||inverse[d]>=0&&inverse[d]!==c)return pos+1;map[c]=d;inverse[d]=c;}
    }
    return 0;
  };
}
function controls(){
  const maps=[[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]];let exhaustive=0,plants=0;
  for(const source of ['abba','abca','aabb','aaaa'])for(let max=0;max<=2;max++)for(let value=0;value<256;value++){
    const ds=value.toString(4).padStart(4,'0'),zeroLetters=new Set([...source].filter((_,i)=>ds[i]==='0')),possible=zeroLetters.size<=max&&maps.some(m=>[...source].every((c,i)=>ds[i]==='0'||+ds[i]===m[c.charCodeAt(0)-97]));assert.equal(matcher(source,max)(ds)===0,possible);exhaustive++;
  }
  for(const profile of bounds.filter(c=>c.field==='faed'))for(const radix of [11,101,1601])for(const line of [0,13]){
    const pp=primes.filter(p=>p<radix),blue=pp[Math.floor(pp.length/3)],yellow=pp[Math.floor(pp.length*2/3)],coef=coefficients(radix,profile,line),dominant=coef[0]>=coef[1]?0:1,other=1-dominant,chosen=[blue,yellow][dominant],value=coef[0]*BigInt(blue)+coef[1]*BigInt(yellow)+coef[2],alphabet='ihgfedcba';let zero=0;
    const text=[...String(value)].map(d=>d==='0'?'be'[zero++%2]:alphabet[Number(d)-1]).join(''),test=matcher(text),lo=coef[dominant]*BigInt(chosen)+coef[other]*2n+coef[2],hi=coef[dominant]*BigInt(chosen)+coef[other]*BigInt(pp.at(-1))+coef[2];assert.equal(test(String(value)),0);assert.equal(test(common(lo,hi)),0);plants++;
  }
  return {exhaustive,plants};
}
function main(){
  fs.mkdirSync(out,{recursive:true});assert(!fs.existsSync(path.join(out,'cases.jsonl')),'Existing results: inspect before restarting');const checked=controls(),targets=[input.faed,[...input.faed].reverse().join('')],tests=targets.map(t=>matcher(t)),profiles=bounds.filter(c=>c.field==='faed');
  const spec={scope:'Fourteen positional row/column values concatenated as minimal decimal strings; natural or reversed line order, both field directions. Same prime radix r and prime colour digits 2<=B,Y<r. Fixed black/white weights 0 or 1 and both within-line orientations. Any fixed a..i to 1..9 bijection, each occurrence of at most two selected letters may also be zero. This screen constrains the first number only; unresolved entries are not solutions.',profiles:profiles.map(({primeBases,...p})=>({...p,primeBaseCount:primeBases.length})),controls:checked,inputSHA256:sha(inputRaw),boundsSHA256:sha(boundsRaw),sourceSHA256:sha(fs.readFileSync(__filename)),certificateEncoding:'Two uint8 rejection positions per dominant prime, original then reversed field. Zero means unresolved; nonzero is the first contradiction within the common decimal prefix for ALL secondary primes. Offsets in cases.jsonl.'};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');const fd=fs.openSync(path.join(out,'certificates.bin'),'wx');let cases=0,offset=0,dominantValues=0,coveredPairs=0n,unresolvedPairs=0n;const start=Date.now();
  try{
    for(const [profileIndex,profile]of profiles.entries())for(const radix of profile.primeBases){
      const pp=primes.filter(p=>p<radix),loPrime=BigInt(pp[0]),hiPrime=BigInt(pp.at(-1));
      for(const firstLine of [0,13]){
        const coef=coefficients(radix,profile,firstLine),dominant=coef[0]>=coef[1]?0:1,other=1-dominant,lowTail=coef[other]*loPrime+coef[2],highTail=coef[other]*hiPrime+coef[2],cert=Buffer.alloc(pp.length*2),unresolved=[];
        for(let i=0;i<pp.length;i++){
          const value=coef[dominant]*BigInt(pp[i]),prefix=common(value+lowTail,value+highTail);
          for(let direction=0;direction<2;direction++){const failure=tests[direction](prefix);assert(failure<=255);cert[2*i+direction]=failure;if(!failure)unresolved.push({dominantIndex:i,reverse:!!direction});}
        }
        fs.writeSync(fd,cert);const record={profileIndex,radix,firstLine,dominant:dominant===0?'B':'Y',primeCount:pp.length,certificateOffset:offset,certificateLength:cert.length,unresolved};fs.appendFileSync(path.join(out,'cases.jsonl'),JSON.stringify(record)+'\n');offset+=cert.length;cases++;dominantValues+=pp.length;coveredPairs+=BigInt(pp.length)**2n*2n;unresolvedPairs+=BigInt(unresolved.length)*BigInt(pp.length);
      }
      if(cases%200===0){const progress={finished:false,cases,dominantValues,coveredPairs:String(coveredPairs),unresolvedPairs:String(unresolvedPairs),elapsedMs:Date.now()-start};fs.writeFileSync(path.join(out,'progress.json'),JSON.stringify(progress)+'\n');console.log(JSON.stringify(progress));}
    }
  }finally{fs.closeSync(fd);}
  const summary={finished:true,cases,dominantValues,coveredPairs:String(coveredPairs),excludedPairs:String(coveredPairs-unresolvedPairs),unresolvedPairs:String(unresolvedPairs),completeExclusion:unresolvedPairs===0n,certificateBytes:offset,elapsedMs:Date.now()-start,casesSHA256:sha(fs.readFileSync(path.join(out,'cases.jsonl'))),certificatesSHA256:sha(fs.readFileSync(path.join(out,'certificates.bin')))};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}
if(require.main===module)main();module.exports={coefficients,common,matcher};
