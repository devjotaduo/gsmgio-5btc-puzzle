'use strict';
// Independent necessary-condition verifier: residues mod 10 and mod 100.
// Does not import the producer, use its decimal-carry solver, or trust its lengths.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const folder=path.resolve(process.argv[2]||path.join(root,'_work/ring_sum_decimal_2026-09-16'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json'));
const input=JSON.parse(inputRaw),spec=JSON.parse(fs.readFileSync(path.join(folder,'spec.json')));
assert.equal(sha(inputRaw),spec.inputSHA256);
assert.equal(sha(fs.readFileSync(path.join(root,'solver/ring_sum_decimal.cjs'))),spec.sourceSHA256);

function rebuildProfiles() {
  const result=[];
  for(const oneWeight of [0,1])for(const zeroWeight of [0,1]) {
    const sums=[];
    for(let radius=13;radius>=1;radius-=2) {
      const row=[0,0,0];
      for(let r=0;r<14;r++)for(let c=0;c<14;c++)if(Math.max(Math.abs(2*r-13),Math.abs(2*c-13))===radius) {
        const color=input.colored.find(x=>x[2]===r&&x[3]===c)?.[1];
        if(color==='B')row[0]++;else if(color==='Y')row[1]++;
        else row[2]+=input.matrix[r][c]===1?oneWeight:zeroWeight;
      }
      sums.push(row);
    }
    const minimumValues=sums.map(([a,b,c])=>2*a+2*b+c);
    for(const i of [0,1,2,3,4,5])for(const j of [0,1,2,3,5]) {
      assert(sums[i][0]<10*sums[j][0]&&sums[i][1]<10*sums[j][1]&&minimumValues[i]<10*minimumValues[j]);
    }
    result.push({id:result.length,oneWeight,zeroWeight,sums,minimumValues});
  }
  return result;
}

function partitions(total,profile) {
  const found=[];
  // Fix the actual length of ring 0, then vary the other mixed-ring lengths
  // by -1,0,+1. This is different from the producer's minimum/mask enumeration.
  for(let a=1;a<=total;a++)for(let b=a-1;b<=a+1;b++)for(let c=a-1;c<=a+1;c++)for(let d=a-1;d<=a+1;d++)for(let f=a-1;f<=a+1;f++) {
    const mixed=[a,b,c,d,f],lo=Math.min(...mixed),hi=Math.max(...mixed);
    if(lo<1||hi-lo>1)continue;
    const e=total-a-b-c-d-f;
    if(e<1||e>lo+1)continue;
    const row=[a,b,c,d,e,f];
    if(row.some((n,i)=>10**Math.min(n,6)<=profile.minimumValues[i]))continue;
    found.push(row);
  }
  return found.sort((a,b)=>a.join(',').localeCompare(b.join(',')));
}

function residueSets(parts,aliases,digits) {
  return parts.map(part=> {
    let values=[0];
    for(let k=0;k<digits;k++) {
      const pos=part.length-1-k;
      const choices=pos<0?[0]:[part.charCodeAt(pos)-96];
      if(pos>0&&aliases.includes(part[pos]))choices.push(0);
      values=values.flatMap(v=>choices.map(d=>v+d*10**k));
    }
    return new Set(values);
  });
}

function compatible(sums,sets,modulus) {
  const pairs=[];
  for(let p=0;p<modulus;p++)for(let q=0;q<modulus;q++) {
    if(sums.slice(0,6).every(([a,b,c],i)=>sets[i].has((a*p+b*q+c)%modulus)))pairs.push([p,q]);
  }
  return pairs;
}

const ps=rebuildProfiles();assert.deepEqual(ps,spec.profiles);
const expectedAliases=['',...'abcdefghi'];
for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)expectedAliases.push('abcdefghi'[i]+'abcdefghi'[j]);
assert.deepEqual([...spec.aliases].sort(),expectedAliases.sort());
const records=fs.readFileSync(path.join(folder,'cases.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
const key=x=>[x.field,x.profile,+x.sourceReverse,+x.ringReverse,x.aliases].join('|');
const byKey=new Map(records.map(x=>[key(x),x]));assert.equal(byKey.size,records.length);
const cachedLengths=new Map();
let models=0,centers=0,total=0,unitsRejected=0,tensRejected=0,controls=0;
const lastDigitSurvivors=[];
for(const profile of ps)for(const field of ['dbbi','faed']) {
  cachedLengths.set(profile.id+field,partitions(input[field].length-1,profile));
  for(const sourceReverse of [false,true])for(const ringReverse of [false,true])for(const aliases of expectedAliases) {
    const model={field,profile:profile.id,sourceReverse,ringReverse,aliases};
    const record=byKey.get(key(model));assert(record);models++;
    let text=sourceReverse?Array.from(input[field]).reverse().join(''):input[field];
    const ch=ringReverse?text[0]:text.at(-1),center=profile.sums[6][2];
    const valid=center===0?aliases.includes(ch):ch.charCodeAt(0)-96===center;
    if(!valid) {assert.equal(record.reason,'constant-center');assert.equal(record.partitions,0);centers++;continue;}
    text=ringReverse?text.slice(1):text.slice(0,-1);
    const lens=cachedLengths.get(profile.id+field),byLength=new Map(record.results.map(r=>[r.lengths.join(','),r]));
    assert.equal(byLength.size,lens.length);assert.equal(record.partitions,lens.length);
    for(const lengths of lens) {
      total++;const row=byLength.get(lengths.join(','));assert(row);
      const ordered=ringReverse?[...lengths].reverse():lengths;
      const parts=[];let pos=0;
      for(const n of ordered){parts.push(text.substring(pos,pos+n));pos+=n;}assert.equal(pos,text.length);
      if(ringReverse)parts.reverse();
      const units=compatible(profile.sums,residueSets(parts,aliases,1),10);
      if(!units.length)unitsRejected++;
      else {
        const tens=compatible(profile.sums,residueSets(parts,aliases,2),100);
        assert.equal(tens.length,0,'A case survives modulo 100; further verification is required');
        tensRejected++;lastDigitSurvivors.push({...model,lengths,units});
      }
      assert.deepEqual(row.matches,[]);
    }
  }
}
// Forward controls include long operands and zero digits; their residues must survive.
for(const profile of ps)for(const [p,q] of [[2n,2n],[3n,17n],[47n,53n],[1000003n,1000033n],[2n,10n**95n+37n]]) {
  const values=profile.sums.slice(0,6).map(([a,b,c])=>String(BigInt(a)*p+BigInt(b)*q+BigInt(c)));
  const parts=values.map(s=>[...s].map((d,i)=>d==='0'?'be'[i%2]:String.fromCharCode(96+ +d)).join(''));
  const actualLens=values.map(s=>s.length).join(',');
  assert(partitions(values.reduce((n,s)=>n+s.length,0),profile).some(l=>l.join(',')===actualLens));
  assert(compatible(profile.sums,residueSets(parts,'be',2),100).some(([a,b])=>a===Number(p%100n)&&b===Number(q%100n)));
  controls++;
}
assert.equal(models,1472);assert.equal(total,64756);assert.equal(unitsRejected+tensRejected,total);
const report={verifiedAt:new Date().toISOString(),method:'Independent ring geometry, first-length enumeration, all p/q residues mod10 and mod100; no decimal-carry recursion',
  models,constantCenterRejected:centers,partitions:total,unitsRejected,tensRejected,controls,lastDigitSurvivors,
  conclusion:'Every possible partition in this model is inconsistent already modulo 100. No integer p,q>=2 solution, and hence no prime-weight solution.',
  hashes:Object.fromEntries(['spec.json','cases.jsonl','summary.json'].map(n=>[n,sha(fs.readFileSync(path.join(folder,n)))])),verifierSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(folder,'independent_verification.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({...report,lastDigitSurvivors:lastDigitSurvivors.length},null,2));
