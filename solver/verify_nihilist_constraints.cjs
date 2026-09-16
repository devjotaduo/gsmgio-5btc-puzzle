/* Full digit-permutation walk, direct arithmetic and residue intersections.
 * Does not use the searcher's missing-pair or graph reductions.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/nihilist_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const valid=n=>Math.floor(n/10)>=1&&Math.floor(n/10)<=5&&n%10>=1&&n%10<=5;
const coords=Array.from({length:100},(_,i)=>i).filter(valid);
function nextPermutation(a){
  let i=a.length-2;while(i>=0&&a[i]>=a[i+1])i--;if(i<0)return false;
  let j=a.length-1;while(a[j]<=a[i])j--;[a[i],a[j]]=[a[j],a[i]];
  for(let l=i+1,r=a.length-1;l<r;l++,r--)[a[l],a[r]]=[a[r],a[l]];
  return true;
}
function main(){
  const read=n=>JSON.parse(fs.readFileSync(path.join(out,n)));
  const input=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(input);
  const spec=read('spec.json'),expected=read('results.json'),summary=read('summary.json');
  assert.equal(sha(input),spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root,'solver/nihilist_constraints.cjs'))),spec.sourceSHA256);
  assert.equal(sha(fs.readFileSync(path.join(out,'results.json'))),summary.resultsSHA256);
  assert.deepEqual(expected.map(x=>x.reversed),[false,true]);
  // Independently invert candidate ciphertext numbers for every key value.
  const possible=Array(100).fill(0);
  for(let c=0;c<100;c++)for(let k=0;k<25;k++)if(valid((c-coords[k]+100)%100))possible[c]|=1<<k;
  for(let tens=0;tens<10;tens++)assert.equal(possible[10*tens+1],0);
  assert.equal(possible[20],0);
  const verification=[];
  for(const item of expected){
    const source=item.reversed?[...data.faed].reverse().join(''):data.faed;
    const pairs=[];for(let i=0;i<source.length;i+=2)pairs.push((source.charCodeAt(i)-97)*9+source.charCodeAt(i+1)-97);
    assert.equal(source.length,570);assert.equal(pairs.length,285);
    // This verifies the premise making all eight other zero aliases impossible.
    assert.equal(new Set(pairs.map(x=>x%9)).size,9);
    const used=[...new Set(pairs)];
    const groupings=Array.from({length:285},(_,pi)=>{
      const sets=Array.from({length:pi+1},()=>new Set());pairs.forEach((pair,i)=>sets[i%(pi+1)].add(pair));
      return sets.map(s=>[...s]).sort((a,b)=>b.length-a.length);
    });
    const found=Array.from({length:285},()=>[]),map=[1,2,3,4,5,6,7,8,9];
    let visited=0,locallyPossible=0,periodDecisions=0;
    do{
      visited++;
      const masks=Array(81).fill(0);let rejected=false;
      for(const pair of used){
        const a=map[Math.floor(pair/9)],b=map[pair%9];let mask=0;
        for(const x of a===1?[0,1]:[a])for(const y of b===1?[0,1]:[b])mask|=possible[10*x+y];
        if(mask===0){rejected=true;break;}masks[pair]=mask;
      }
      if(rejected)continue;
      locallyPossible++;
      for(let pi=0;pi<285;pi++){
        let ok=true;periodDecisions++;
        for(const group of groupings[pi]){
          let choices=(1<<25)-1;for(const pair of group){choices&=masks[pair];if(!choices)break;}
          if(!choices){ok=false;break;}
        }
        if(ok)found[pi].push(map.join(''));
      }
    }while(nextPermutation(map));
    assert.equal(visited,362880);assert.equal(locallyPossible,item.reducedMappings);
    for(let i=0;i<285;i++)assert.deepEqual(found[i].sort(),item.periods[i].mappings);
    const min=found.findIndex(a=>a.length)+1;assert.equal(min,item.minimumPeriod);
    const known=found.flatMap((maps,i)=>maps.includes('123456789')?[i+1]:[]);
    assert.deepEqual(known,item.knownMappingPeriods);
    assert.equal(item.witnesses.length,found[min-1].length);
    const witnessMaps=new Set();
    for(const w of item.witnesses){
      assert.equal(w.period,min);assert.equal(w.keyCoordinates.length,min);
      assert.equal(w.plaintextCoordinates.length,285);assert.equal(w.ciphertextNumbers.length,285);
      assert.deepEqual(w.mapping.slice().sort((a,b)=>a-b),[1,2,3,4,5,6,7,8,9]);
      const id=w.mapping.join('');assert(found[min-1].includes(id)&&!witnessMaps.has(id));witnessMaps.add(id);
      assert(w.keyCoordinates.every(valid)&&w.plaintextCoordinates.every(valid));
      assert.equal(w.zeroAlias,String.fromCharCode(97+w.mapping.indexOf(1)));
      const digits=w.plaintextCoordinates.map((p,i)=>String((p+w.keyCoordinates[i%min])%100).padStart(2,'0')).join('');
      assert.equal(digits,w.ciphertextNumbers.map(n=>String(n).padStart(2,'0')).join(''));
      assert.equal([...digits].map(d=>String.fromCharCode(97+w.mapping.indexOf(Number(d)===0?1:Number(d)))).join(''),source);
    }
    verification.push({reversed:item.reversed,permutations:visited,aliasesExcludedByUnit1PerPermutation:8,
      locallyPossibleMappings:locallyPossible,periodDecisions,all285PeriodListsMatch:true,minimumPeriod:min,
      independentlyReencryptedWitnesses:item.witnesses.length});
    console.log(JSON.stringify(verification.at(-1)));
  }
  const result={verifiedAt:new Date().toISOString(),inputSHA256:sha(input),resultsSHA256:summary.resultsSHA256,
    verifierSHA256:sha(fs.readFileSync(__filename)),verification,aesTrials:0,finalPasswordFound:false};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');
}
if(require.main===module)main();
