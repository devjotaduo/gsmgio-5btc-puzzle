'use strict';
// Extend endpoint exclusions to arbitrary permutations of the fourteen lines.
// A rare surviving first-number interval is resolved over its secondary primes.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {coefficients,common,matcher}=require('./positional_prime_prefix.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','positional_prime_order_2026-09-16'),previous=path.join(root,'_work','positional_prime_prefix_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),boundsRaw=fs.readFileSync(path.join(root,'_work','positional_prime_bases_2026-09-16','cases.json')),profiles=JSON.parse(boundsRaw).filter(c=>c.field==='faed');
const max=Math.max(...profiles.flatMap(p=>p.primeBases)),flags=new Uint8Array(max+1).fill(1);flags[0]=flags[1]=0;for(let d=2;d*d<=max;d++)if(flags[d])for(let i=d*d;i<=max;i+=d)flags[i]=0;const primes=Array.from(flags.keys()).filter(n=>flags[n]);
function routes(values,first,target,maxNodes=100000){
  const test=matcher(target),stack=[[first]],leaves=[],hits=[];let nodes=0;
  while(stack.length&&nodes<maxNodes){
    const order=stack.pop(),digits=order.map(i=>values[i]).join(''),failure=test(digits);nodes++;
    if(failure){leaves.push({order,failure});continue;}
    if(order.length===14){assert.equal(digits.length,target.length);hits.push({order,digits});continue;}
    for(let i=13;i>=0;i--)if(!order.includes(i))stack.push([...order,i]);
  }
  return {complete:stack.length===0,nodes,leaves,hits,pending:stack};
}
function main(){
  fs.mkdirSync(out,{recursive:true});assert(!fs.existsSync(path.join(out,'cases.jsonl')),'Existing results: inspect before restarting');
  const endpointSummary=JSON.parse(fs.readFileSync(path.join(previous,'summary.json'))),endpointVerification=JSON.parse(fs.readFileSync(path.join(previous,'verification.json')));assert(endpointSummary.completeExclusion&&endpointVerification.complete);assert.equal(endpointSummary.certificatesSHA256,endpointVerification.certificatesSHA256);
  const targets=[input.faed,[...input.faed].reverse().join('')],tests=targets.map(t=>matcher(t));
  const spec={scope:'Arbitrary permutation of the 14 positional row/column numbers. All other premises match positional_prime_prefix: prime radix, prime colour digits below radix, fixed binary backgrounds, both inner orientations, both field directions, unknown digit bijection and at most two zero aliases. First lines 0/13 reuse independently verified endpoint certificates; all other first lines searched here.',inputSHA256:sha(inputRaw),boundsSHA256:sha(boundsRaw),endpointSummarySHA256:sha(fs.readFileSync(path.join(previous,'summary.json'))),endpointVerificationSHA256:sha(fs.readFileSync(path.join(previous,'verification.json'))),sources:Object.fromEntries(['positional_prime_order.cjs','positional_prime_prefix.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))])),certificateEncoding:'Two uint8 first-conflict positions per dominant prime; 0 references a residual secondary-prime table. In each residual qCodesLE is signed int16: >0 first-number rejection position; -1 full concatenation length is not 570; -2 a route certificate is supplied.',routeNodeLimit:100000};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');const fd=fs.openSync(path.join(out,'certificates.bin'),'wx');let cases=0,offset=0,dominantValues=0,firstIntervalCertificates=0,secondaryCases=0,lengthRejected=0,routeNodes=0,routeCases=0,incompleteRoutes=0,hits=0;const start=Date.now();
  try{
    for(const [profileIndex,profile]of profiles.entries())for(const radix of profile.primeBases){
      const pp=primes.filter(p=>p<radix),allCoef=Array.from({length:14},(_,i)=>coefficients(radix,profile,i));assert(allCoef.every(c=>c[0]>0n||c[1]>0n),'Every line must contain a coloured cell');
      for(let firstLine=1;firstLine<=12;firstLine++){
        const coef=allCoef[firstLine],dominant=coef[0]>=coef[1]?0:1,other=1-dominant,lowTail=coef[other]*2n+coef[2],highTail=coef[other]*BigInt(pp.at(-1))+coef[2],cert=Buffer.alloc(pp.length*2),residuals=[];
        for(let i=0;i<pp.length;i++){
          const fixed=coef[dominant]*BigInt(pp[i]),prefix=common(fixed+lowTail,fixed+highTail);
          for(let direction=0;direction<2;direction++){
            const failure=tests[direction](prefix);cert[2*i+direction]=failure;
            if(failure){firstIntervalCertificates++;continue;}
            const codes=Buffer.alloc(pp.length*2),routeCertificates=[];
            for(let j=0;j<pp.length;j++){
              secondaryCases++;const d=[0n,0n];d[dominant]=BigInt(pp[i]);d[other]=BigInt(pp[j]);const first=(coef[0]*d[0]+coef[1]*d[1]+coef[2]).toString(),firstFailure=tests[direction](first);
              if(firstFailure){codes.writeInt16LE(firstFailure,2*j);continue;}
              const values=allCoef.map(c=>(c[0]*d[0]+c[1]*d[1]+c[2]).toString());
              if(values.reduce((n,v)=>n+v.length,0)!==570){codes.writeInt16LE(-1,2*j);lengthRejected++;continue;}
              codes.writeInt16LE(-2,2*j);const route=routes(values,firstLine,targets[direction]);routeCertificates.push({secondaryIndex:j,...route});routeNodes+=route.nodes;routeCases++;incompleteRoutes+=Number(!route.complete);hits+=route.hits.length;
            }
            residuals.push({dominantIndex:i,reverse:!!direction,qCodesLE:codes.toString('base64'),routes:routeCertificates});
          }
        }
        fs.writeSync(fd,cert);fs.appendFileSync(path.join(out,'cases.jsonl'),JSON.stringify({profileIndex,radix,firstLine,dominant:dominant===0?'B':'Y',primeCount:pp.length,certificateOffset:offset,certificateLength:cert.length,residuals})+'\n');offset+=cert.length;cases++;dominantValues+=pp.length;
      }
      if(cases%2400===0){const progress={finished:false,cases,dominantValues,secondaryCases,routeCases,routeNodes,incompleteRoutes,hits,elapsedMs:Date.now()-start};fs.writeFileSync(path.join(out,'progress.json'),JSON.stringify(progress)+'\n');console.log(JSON.stringify(progress));}
    }
  }finally{fs.closeSync(fd);}
  const summary={finished:true,cases,dominantValues,firstIntervalCertificates,secondaryCases,lengthRejected,routeCases,routeNodes,incompleteRoutes,hits,completeExclusion:incompleteRoutes===0&&hits===0,certificateBytes:offset,elapsedMs:Date.now()-start,casesSHA256:sha(fs.readFileSync(path.join(out,'cases.jsonl'))),certificatesSHA256:sha(fs.readFileSync(path.join(out,'certificates.bin')))};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}
if(require.main===module)main();module.exports={routes};
