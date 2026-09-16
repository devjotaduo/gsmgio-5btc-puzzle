'use strict';
// Independent verification of arbitrary-order coverage, including rare route trees.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {coefficients,primesBelow,verifyRejection}=require('./verify_positional_prime_prefix.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','positional_prime_order_2026-09-16'),endpoint=path.join(root,'_work','positional_prime_prefix_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function conflict(digits,target,at){
  assert(at>0&&at<=digits.length);const zeros=new Set(),letterSets=new Map(),digitSets=new Map();
  for(let i=0;i<at;i++){const a=target[i],b=digits[i];if(b==='0')zeros.add(a);else {if(!letterSets.has(a))letterSets.set(a,new Set());letterSets.get(a).add(b);if(!digitSets.has(b))digitSets.set(b,new Set());digitSets.get(b).add(a);}}
  return zeros.size>2||[...letterSets.values()].some(v=>v.size>1)||[...digitSets.values()].some(v=>v.size>1);
}
function verifyRoute(r,values,first,target){
  const leaves=new Map(r.leaves.map(l=>[l.order.join(','),l]));assert.equal(leaves.size,r.leaves.length);const pending=new Set(r.pending.map(o=>o.join(','))),hits=new Map(r.hits.map(h=>[h.order.join(','),h]));
  let nodes=0;const stack=[[first]];
  while(stack.length){
    const order=stack.pop(),key=order.join(',');assert.equal(new Set(order).size,order.length);if(pending.has(key)){pending.delete(key);continue;}nodes++;
    const digits=order.map(i=>values[i]).join('');assert(digits.length<=target.length);
    if(leaves.has(key)){const leaf=leaves.get(key);assert(conflict(digits,target,leaf.failure));leaves.delete(key);continue;}
    if(hits.has(key)){const hit=hits.get(key);assert.equal(order.length,14);assert.equal(digits,target.length?hit.digits:'');assert.equal(digits.length,target.length);assert(!conflict(digits,target,digits.length));hits.delete(key);continue;}
    assert(!conflict(digits,target,digits.length));assert(order.length<14);
    for(let i=0;i<14;i++)if(!order.includes(i))stack.push([...order,i]);
  }
  assert.equal(nodes,r.nodes);assert.equal(leaves.size,0);assert.equal(pending.size,0);assert.equal(hits.size,0);assert.equal(r.complete,r.pending.length===0);return nodes;
}
function main(){
  const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),boundsRaw=fs.readFileSync(path.join(root,'_work','positional_prime_bases_2026-09-16','cases.json')),profiles=JSON.parse(boundsRaw).filter(p=>p.field==='faed'),raw=fs.readFileSync(path.join(out,'cases.jsonl')),records=raw.toString().trim().split(/\r?\n/).map(JSON.parse),cert=fs.readFileSync(path.join(out,'certificates.bin')),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json'))),ev=JSON.parse(fs.readFileSync(path.join(endpoint,'verification.json'))),es=JSON.parse(fs.readFileSync(path.join(endpoint,'spec.json')));
  assert(summary.finished&&ev.complete);assert.equal(spec.inputSHA256,sha(inputRaw));assert.equal(spec.boundsSHA256,sha(boundsRaw));assert.equal(es.inputSHA256,spec.inputSHA256);assert.equal(es.boundsSHA256,spec.boundsSHA256);assert.equal(spec.endpointVerificationSHA256,sha(fs.readFileSync(path.join(endpoint,'verification.json'))));assert.equal(ev.verifierSHA256,sha(fs.readFileSync(path.join(__dirname,'verify_positional_prime_prefix.cjs'))));assert.equal(spec.endpointSummarySHA256,sha(fs.readFileSync(path.join(endpoint,'summary.json'))));assert.equal(summary.casesSHA256,sha(raw));assert.equal(summary.certificatesSHA256,sha(cert));for(const [file,h]of Object.entries(spec.sources))assert.equal(h,sha(fs.readFileSync(path.join(__dirname,file))));
  const ppAll=primesBelow(1+Math.max(...profiles.flatMap(p=>p.primeBases))),targets=[input.faed,[...input.faed].reverse().join('')],expected=new Set();for(const [i,p]of profiles.entries())for(const r of p.primeBases)for(let first=1;first<=12;first++)expected.add([i,r,first].join('/'));
  let offset=0,dominantValues=0,firstIntervalCertificates=0,secondaryCases=0,lengthRejected=0,routeCases=0,routeNodes=0,incompleteRoutes=0,hits=0,recordsChecked=0;const begin=Date.now();
  for(const c of records){
    assert(expected.delete([c.profileIndex,c.radix,c.firstLine].join('/')));const pp=ppAll.filter(n=>n<c.radix),allCoef=Array.from({length:14},(_,line)=>coefficients(input,profiles[c.profileIndex],c.radix,line)),coef=allCoef[c.firstLine],dominant=coef[0]>=coef[1]?0:1,other=1-dominant;assert(allCoef.every(v=>v[0]>0n||v[1]>0n));assert.equal(c.dominant,dominant===0?'B':'Y');assert.equal(c.primeCount,pp.length);assert.equal(c.certificateOffset,offset);assert.equal(c.certificateLength,2*pp.length);
    const residuals=new Map(c.residuals.map(r=>[[r.dominantIndex,+r.reverse].join('/'),r]));assert.equal(residuals.size,c.residuals.length);const lowTail=coef[other]*BigInt(pp[0])+coef[2],highTail=coef[other]*BigInt(pp.at(-1))+coef[2];
    for(let i=0;i<pp.length;i++){
      const fixed=coef[dominant]*BigInt(pp[i]);
      for(let reverse=0;reverse<2;reverse++){
        const k=cert[offset+2*i+reverse],key=[i,reverse].join('/');
        if(k){verifyRejection(fixed+lowTail,fixed+highTail,targets[reverse],k);assert(!residuals.has(key));firstIntervalCertificates++;continue;}
        const r=residuals.get(key);assert(r);residuals.delete(key);const codes=Buffer.from(r.qCodesLE,'base64'),routes=new Map(r.routes.map(t=>[t.secondaryIndex,t]));assert.equal(codes.length,2*pp.length);assert.equal(routes.size,r.routes.length);
        for(let j=0;j<pp.length;j++){
          secondaryCases++;const d=[0n,0n];d[dominant]=BigInt(pp[i]);d[other]=BigInt(pp[j]);const first=coef[0]*d[0]+coef[1]*d[1]+coef[2],code=codes.readInt16LE(2*j);
          if(code>0){verifyRejection(first,first,targets[reverse],code);assert(!routes.has(j));continue;}
          const values=allCoef.map(v=>(v[0]*d[0]+v[1]*d[1]+v[2]).toString());
          if(code===-1){assert(values.reduce((n,v)=>n+v.length,0)!==570);assert(!routes.has(j));lengthRejected++;continue;}
          assert.equal(code,-2);assert.equal(values.reduce((n,v)=>n+v.length,0),570);const route=routes.get(j);assert(route);routes.delete(j);routeNodes+=verifyRoute(route,values,c.firstLine,targets[reverse]);routeCases++;incompleteRoutes+=+!route.complete;hits+=route.hits.length;
        }
        assert.equal(routes.size,0);
      }
    }
    assert.equal(residuals.size,0);offset+=c.certificateLength;dominantValues+=pp.length;recordsChecked++;if(recordsChecked%12000===0)console.log(JSON.stringify({recordsChecked,elapsedMs:Date.now()-begin}));
  }
  assert.equal(expected.size,0);assert.equal(offset,cert.length);const counts={cases:records.length,dominantValues,firstIntervalCertificates,secondaryCases,lengthRejected,routeCases,routeNodes,incompleteRoutes,hits,certificateBytes:offset};for(const [k,v]of Object.entries(counts))assert.equal(v,summary[k]);assert.equal(summary.completeExclusion,incompleteRoutes===0&&hits===0);
  const result={verificationComplete:true,completeExclusion:summary.completeExclusion,...counts,endpointFirstLinesVerified:[0,13],newFirstLinesVerified:Array.from({length:12},(_,i)=>i+1),coversAllLinePermutations:true,casesSHA256:sha(raw),certificatesSHA256:sha(cert),verifierSHA256:sha(fs.readFileSync(__filename)),dependencyVerifierSHA256:ev.verifierSHA256,elapsedMs:Date.now()-begin,scope:'Every newly declared first-line choice, root interval rejection, secondary-prime result and route tree independently checked. With the endpoint proof, all 14 possible first lines and arbitrary permutations of the remainder are covered under the declared positional-prime model.'};fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main();
