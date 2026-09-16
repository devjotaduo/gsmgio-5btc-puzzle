/* Independent grid construction and canonical equality-pattern comparator.
 * Regenerates every preimage and checks per-weight transcript commitments.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/dbbi_matrix_hash_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function normalize(xs){const distinct=[];return [...xs].map(x=>{let i=distinct.indexOf(x);if(i<0){i=distinct.length;distinct.push(x);}return i;}).join(',');}
function representations(v){
  const result=[['decimal-concat',v.map(String).join('')],['decimal-csv',v.map(String).join(',')],
    ['decimal-space',v.map(String).join(' ')],['decimal-lines',v.map(String).join('\n')],
    ['json-compact','['+v.map(String).join(',')+']'],['json-spaced','['+v.map(String).join(', ')+']']].map(([name,s])=>[name,Buffer.from(s)]);
  if(Math.max(...v)<256)result.push(['bytes',Buffer.from(v)]);
  for(const size of[2,4])if(Math.max(...v)<256**size)for(const endian of['BE','LE']){
    const bytes=[];for(const value of v){const one=[];for(let j=0;j<size;j++)one.push(Math.floor(value/256**j)%256);bytes.push(...(endian==='BE'?one.reverse():one));}
    result.push([`uint${size*8}-${endian}`,Buffer.from(bytes)]);
  }return result;
}
function main(){
  const read=n=>JSON.parse(fs.readFileSync(path.join(out,n))),spec=read('spec.json'),groups=read('groups.json'),hits=read('hits.json'),summary=read('summary.json');
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(raw);
  assert.equal(sha(raw),spec.inputSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver/dbbi_matrix_hash.cjs'))),spec.sourceSHA256);
  assert.equal(sha(fs.readFileSync(path.join(out,'groups.json'))),summary.groupsSHA256);
  const sieve=Array(197).fill(true);sieve[0]=sieve[1]=false;
  for(let p=2;p<197;p++)if(sieve[p])for(let m=2*p;m<197;m+=p)sieve[m]=false;
  const primes=sieve.flatMap((yes,i)=>yes?[i]:[]),domain=[0,1,...primes];assert.deepEqual(spec.primes,primes);assert.deepEqual(spec.domain,domain);
  for(const color of[spec.blueRGB,spec.yellowRGB]){
    assert.equal(parseInt(color.hex,16),color.value);let product=1;
    for(const factor of color.factors){for(let d=2;d*d<=factor.prime;d++)assert.notEqual(factor.prime%d,0);product*=factor.prime**factor.exponent;}
    assert.equal(product,color.value);
  }
  const expectedWeights=new Set(domain.flatMap(b=>domain.map(y=>`${b},${y}`)));
  for(const b of spec.blueRGB.factors)for(const y of spec.yellowRGB.factors)expectedWeights.add(`${b.prime},${y.prime}`);
  assert.equal(spec.weights.length,expectedWeights.size);for(const w of spec.weights)assert(expectedWeights.delete(`${w.blue},${w.yellow}`));assert.equal(expectedWeights.size,0);
  const inventory=[],targetPatterns=[];
  for(let a=0;a<9;a++)for(let b=a+1;b<9;b++)for(const reverseInput of[false,true]){
    const prefixes=String.fromCharCode(97+a,97+b),s=reverseInput?[...data.dbbi].reverse().join(''):data.dbbi,tokens=[];
    let incomplete=false;for(let i=0;i<s.length;i++){
      if(s[i]===prefixes[0]||s[i]===prefixes[1]){if(i+1===s.length){incomplete=true;break;}tokens.push(s[i]+s[++i]);}
      else tokens.push(s[i]);
    }
    const row={prefixes,reverseInput,tokens:incomplete?null:tokens.length,types:incomplete?null:new Set(tokens).size};inventory.push(row);
    if(!incomplete&&row.tokens===64&&row.types===16){targetPatterns.push(normalize(tokens));targetPatterns.push(normalize(tokens.slice().reverse()));}
  }
  assert.deepEqual(inventory,spec.tokenInventory);assert.deepEqual(targetPatterns,spec.targets.map(t=>t.pattern.join(',')));
  const colors=Array.from({length:14},()=>Array(14).fill(null));for(const[,color,r,c]of data.colored)colors[r][c]=color;
  let evaluations=0,comparisons=0;const regeneratedHits=[],seen=new Set();
  for(const group of groups){
    const id=`${group.blue},${group.yellow},${group.background}`;assert(!seen.has(id));seen.add(id);
    assert(spec.weights.some(w=>w.blue===group.blue&&w.yellow===group.yellow));assert(['bits','zero'].includes(group.background));
    const grid=data.matrix.map((row,r)=>row.map((v,c)=>colors[r][c]==='B'?group.blue:colors[r][c]==='Y'?group.yellow:group.background==='bits'?v:0));
    const rows=grid.map(row=>row.reduce((a,b)=>a+b,0)),columns=Array.from({length:14},(_,c)=>grid.reduce((sum,row)=>sum+row[c],0));
    const layouts=[['rows',rows],['columns',columns],['rows-columns',rows.concat(columns)],['columns-rows',columns.concat(rows)],
      ['interleaved',rows.reduce((a,v,i)=>a.concat([v,columns[i]]),[])],['total',[grid.flat().reduce((a,b)=>a+b,0)]]];
    const trace=crypto.createHash('sha256');let count=0;
    for(const[layout,values]of layouts)for(const reverse of[false,true])for(const[representation,preimage]of representations(reverse?values.slice().reverse():values)){
      const h=sha(preimage),p=normalize(h);let mask=0;
      targetPatterns.forEach((t,i)=>{if(t===p)mask|=1<<i;comparisons++;});
      trace.update(`${layout}:${reverse?'reverse':'forward'}:${representation}\t${preimage.toString('hex')}\t${h}\t${mask}\n`);count++;evaluations++;
      if(mask)regeneratedHits.push({blue:group.blue,yellow:group.yellow,background:group.background,layout,reverse,representation,
        preimageHex:preimage.toString('hex'),sha256:h,targetMask:mask});
    }
    assert.equal(count,group.evaluations);assert.equal(trace.digest('hex'),group.transcriptSHA256);
  }
  assert.equal(seen.size,spec.weights.length*2);assert.deepEqual(regeneratedHits,hits);
  assert.equal(evaluations,summary.hashEvaluations);assert.equal(comparisons,summary.patternComparisons);assert.equal(hits.length,summary.exactPatternHits);
  const result={verifiedAt:new Date().toISOString(),inputSHA256:sha(raw),groupsSHA256:summary.groupsSHA256,
    verifierSHA256:sha(fs.readFileSync(__filename)),groups:seen.size,hashEvaluations:evaluations,patternComparisons:comparisons,
    exactPatternHits:hits.length,allTranscriptsMatch:true,method:'Direct numeric grids and canonical first-occurrence patterns; independent from coefficient generation and bijection matching.',
    aesTrials:0,finalPasswordFound:false};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}
if(require.main===module)main();
