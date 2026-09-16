'use strict';
// Conditional inverse of seven concentric ring sums, including hidden zeros.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const bit = n => 1 << n;
const mod10 = n => ((n % 10) + 10) % 10;
const mixed = [0,1,2,3,5];

function profiles(input) {
  const colors = new Map(input.colored.map(([,co,r,c]) => [r+','+c,co]));
  const result = [];
  for (const oneWeight of [0,1]) for (const zeroWeight of [0,1]) {
    const sums = Array.from({length:7}, () => [0,0,0]);
    for (let r=0;r<14;r++) for (let c=0;c<14;c++) {
      const row=sums[Math.min(r,c,13-r,13-c)], co=colors.get(r+','+c);
      if (co==='B') row[0]++; else if (co==='Y') row[1]++;
      else row[2] += input.matrix[r][c] ? oneWeight : zeroWeight;
    }
    assert.deepEqual(sums.map(x=>x.slice(0,2)),[[5,1],[4,2],[3,1],[2,2],[0,2],[1,1],[0,0]]);
    assert.equal(sums[6][2],4*zeroWeight);
    const d=sums.map(([a,b,c])=>2*a+2*b+c);
    // For p,q >=2 write p=p'+2,q=q'+2. Coefficient-wise strict
    // inequality proves S_i < 10*S_j, including all nonnegative p',q'.
    for (const i of mixed) for (const j of mixed) {
      assert(sums[i][0] < 10*sums[j][0]);
      assert(sums[i][1] < 10*sums[j][1]); assert(d[i] < 10*d[j]);
    }
    for (const j of mixed) {
      assert(sums[4][0] < 10*sums[j][0]);
      assert(sums[4][1] < 10*sums[j][1]); assert(d[4] < 10*d[j]);
    }
    result.push({id:result.length,oneWeight,zeroWeight,sums,minimumValues:d});
  }
  return result;
}

function lengths(total, minimumValues) {
  const result=[];
  // The five mixed ring sums have lengths L or L+1 and at least one L.
  // S_4 < 10*every mixed sum, so its length cannot exceed L+1.
  for (let l=1;5*l+1<=total;l++) for (let mask=0;mask<31;mask++) {
    const v=new Array(6), extras=mixed.reduce((n,_,i)=>n+((mask>>i)&1),0);
    mixed.forEach((k,i)=>{v[k]=l+((mask>>i)&1);});
    v[4]=total-5*l-extras;
    if (v[4]<1 || v[4]>l+1) continue;
    if (v.some((n,i)=>n<String(minimumValues[i]).length)) continue;
    result.push(v);
  }
  assert.equal(new Set(result.map(x=>x.join(','))).size,result.length);
  return result;
}

function domains(parts, aliases) {
  return parts.map(s=>[...s].reverse().map((ch,k)=> {
    let m=bit(ch.charCodeAt(0)-96);
    if (aliases.includes(ch) && k!==s.length-1) m |= bit(0);
    return m;
  }));
}

function solveDigits(sums, parts, aliases) {
  const ds=domains(parts,aliases), width=Math.max(...parts.map(x=>x.length));
  let nodes=0, transitions=0;
  const failed=new Set(), matches=[];
  // 'small' tracks exact p or q when still 0/1, otherwise the value 2 means >=2.
  function visit(k,carry,p,q,smallP,smallQ,power) {
    nodes++;
    if (k===width) {
      if (carry.every(x=>x===0) && smallP===2 && smallQ===2) matches.push({p:String(p),q:String(q)});
      return carry.every(x=>x===0) && smallP===2 && smallQ===2;
    }
    const key=k+':'+carry.join(',')+':'+smallP+smallQ;
    if(failed.has(key)) return false;
    const masks=ds.map(d=>k<d.length?d[k]:1);
    let found=false;
    for(let qd=0;qd<10;qd++) {
      const t4=2*qd+carry[4];
      if(!(masks[4]&bit(t4%10)))continue;
      // Ring 5 has coefficients (1,1), fixing pd modulo ten for each target digit.
      for(let target=0;target<10;target++) if(masks[5]&bit(target)) {
        const pd=mod10(target-qd-carry[5]);
        const totals=sums.slice(0,6).map(([a,b],i)=>a*pd+b*qd+carry[i]);
        if(totals.some((n,i)=>!(masks[i]&bit(n%10))))continue;
        transitions++;
        const nextP=smallP===2 || pd>=2 || (k>0&&pd>0) ? 2 : Math.max(smallP,pd);
        const nextQ=smallQ===2 || qd>=2 || (k>0&&qd>0) ? 2 : Math.max(smallQ,qd);
        if(visit(k+1,totals.map(n=>Math.floor(n/10)),p+BigInt(pd)*power,q+BigInt(qd)*power,
          nextP,nextQ,power*10n))found=true;
      }
    }
    if(!found)failed.add(key);
    return found;
  }
  visit(0,sums.slice(0,6).map(row=>row[2]),0n,0n,0,0,1n);
  for(const m of matches) {
    assert(BigInt(m.p)>=2n && BigInt(m.q)>=2n);
    sums.slice(0,6).forEach(([a,b,c],i)=> {
      const text=String(BigInt(a)*BigInt(m.p)+BigInt(b)*BigInt(m.q)+BigInt(c));
      assert.equal(text.length,parts[i].length);
      for(let j=0;j<text.length;j++) assert(text[j]==='0'?aliases.includes(parts[i][j]):+text[j]===parts[i].charCodeAt(j)-96);
    });
  }
  return {nodes,transitions,deadStates:failed.size,matches};
}

function encode(n,aliases='g') {
  return [...String(n)].map((c,i)=>c==='0'?aliases[i%aliases.length]:String.fromCharCode(96+ +c)).join('');
}

function controls(ps) {
  let planted=0, exhaustive=0;
  for(const profile of ps) for(const [p,q] of [[2n,2n],[3n,17n],[47n,53n],[1000003n,1000033n],[2n,10n**95n+37n]]) {
    const values=profile.sums.slice(0,6).map(([a,b,c])=>BigInt(a)*p+BigInt(b)*q+BigInt(c));
    const parts=values.map(n=>encode(n,'be')), lens=values.map(n=>String(n).length);
    assert(lengths(lens.reduce((a,b)=>a+b,0),profile.minimumValues).some(l=>l.join(',')===lens.join(',')));
    assert(solveDigits(profile.sums,parts,'be').matches.some(m=>m.p===String(p)&&m.q===String(q)));planted++;
  }
  for(const profile of ps) for(const [p,q] of [[2n,3n],[7n,17n],[11n,19n]]) {
    const parts=profile.sums.slice(0,6).map(([a,b,c])=>encode(BigInt(a)*p+BigInt(b)*q+BigInt(c),'bg'));
    const max=10**Math.max(...parts.map(x=>x.length));
    const expected=[];
    for(let x=2;x<max;x++) for(let y=2;y<max;y++) {
      const actual=profile.sums.slice(0,6).map(([a,b,c])=>String(a*x+b*y+c));
      if(actual.every((s,i)=>s.length===parts[i].length&&[...s].every((d,j)=>d==='0'?'bg'.includes(parts[i][j]):+d===parts[i].charCodeAt(j)-96)))expected.push({p:String(x),q:String(y)});
    }
    const order=x=>x.sort((a,b)=>Number(a.p)-Number(b.p)||Number(a.q)-Number(b.q));
    assert.deepEqual(order(solveDigits(profile.sums,parts,'bg').matches),order(expected));exhaustive++;
  }
  return {planted,exhaustive};
}

function main() {
  const destination=path.resolve(process.argv[2]||path.join(root,'_work/ring_sum_decimal_2026-09-16'));
  assert(!fs.existsSync(destination),'Use a new output directory');
  const inputRaw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json'));
  const input=JSON.parse(inputRaw), ps=profiles(input), aliases=[''];
  for(const a of 'abcdefghi') {aliases.push(a);for(const b of 'abcdefghi')if(a<b)aliases.push(a+b);}
  const control=controls(ps);
  fs.mkdirSync(destination,{recursive:true});
  const spec={inputSHA256:sha(inputRaw),sourceSHA256:sha(fs.readFileSync(__filename)),profiles:ps,aliases,
    hypothesis:'Seven concentric ring sums, outer/inner order and both source directions. Every blue cell p>=2, yellow q>=2; uncoloured 1/0 weights independently 0 or 1. Minimal decimal sums concatenated. a..i=1..9; occurrences of at most two chosen letters may also denote zero.',
    method:'Exact length constraints from positive linear forms, then decimal carries for all p,q digits. All integer weights are covered; no prime ceiling. Full original DBBI/FAED only.',
    lengthProof:'For mixed rings i,j, Si<10*Sj after shifting p,q by 2. Their lengths are L or L+1. Ring 4 is <10*every mixed ring, so length<=L+1. Its length is fixed by total after the one-digit centre sum.',controls:control};
  fs.writeFileSync(path.join(destination,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  const fd=fs.openSync(path.join(destination,'cases.jsonl'),'wx'), hits=[];
  let models=0,fixedRejected=0,partitions=0,nodes=0,transitions=0;
  for(const field of ['dbbi','faed']) for(const profile of ps) for(const sourceReverse of [false,true]) for(const ringReverse of [false,true])for(const zeroAliases of aliases) {
    const text=sourceReverse?[...input[field]].reverse().join(''):input[field];
    const center=ringReverse?text[0]:text.at(-1),fixed=profile.sums[6][2];
    const model={id:models++,field,profile:profile.id,sourceReverse,ringReverse,aliases:zeroAliases};
    if(!(fixed===0?zeroAliases.includes(center):center===encode(fixed))) {
      fixedRejected++;fs.writeSync(fd,JSON.stringify({...model,reason:'constant-center',partitions:0,nodes:0,transitions:0,matches:[]})+'\n');continue;
    }
    const body=ringReverse?text.slice(1):text.slice(0,-1), ls=lengths(body.length,profile.minimumValues);
    const results=[];
    for(const canonicalLengths of ls) {
      const ordered=ringReverse?[...canonicalLengths].reverse():canonicalLengths;
      let at=0;const parts=ordered.map(n=>{const s=body.slice(at,at+n);at+=n;return s;});assert.equal(at,body.length);
      if(ringReverse)parts.reverse();
      const result=solveDigits(profile.sums,parts,zeroAliases);
      results.push({lengths:canonicalLengths,...result});partitions++;nodes+=result.nodes;transitions+=result.transitions;
      result.matches.forEach(m=>hits.push({...model,lengths:canonicalLengths,...m}));
    }
    fs.writeSync(fd,JSON.stringify({...model,reason:'decimal-carries',partitions:ls.length,results})+'\n');
  }
  fs.closeSync(fd);
  fs.writeFileSync(path.join(destination,'hits.json'),JSON.stringify(hits,null,2)+'\n');
  const summary={complete:true,models,fixedRejected,partitions,nodes,transitions,matches:hits.length,
    controls:control,casesSHA256:sha(fs.readFileSync(path.join(destination,'cases.jsonl'))),finalPasswordFound:false};
  fs.writeFileSync(path.join(destination,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module) main();
module.exports={profiles,lengths,solveDigits,encode};
