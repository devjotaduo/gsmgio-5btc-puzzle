/* Exact inverse of the conditional model: one integer per colour, then
 * concatenate the 14 decimal row/column sums, with decimal 0 and 7 both g.
 * node solver/color_sum_constraints.cjs
 * No brute-force ceiling for the colour integers: length/repetition bounds
 * are derived from the entire input. No AES or network calls in this script.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','matrix_hint_2026-09-11');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'));
const input=JSON.parse(inputBytes),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const encode=n=>[...n.toString()].map(c=>c==='0'?'g':String.fromCharCode(96+Number(c))).join('');
const decimalLength=n=>n.toString().length;
const value=(c,p,q)=>BigInt(c[0])*p+BigInt(c[1])*q+BigInt(c[2]);
const sumString=(cs,p,q)=>cs.map(c=>value(c,p,q).toString()).join('');
function repeatedSubstring(text) {
  let before=new Uint16Array(text.length+1),best=0,witness=null;
  for(let i=1;i<=text.length;i++) {
    const current=new Uint16Array(text.length+1);
    for(let j=i+1;j<=text.length;j++)if(text[i-1]===text[j-1]) {
      current[j]=before[j-1]+1;
      if(current[j]>best) {best=current[j];witness=[i-best+1,j-best+1];}
    }
    before=current;
  }
  return {length:best,positions:witness,text:witness?text.slice(witness[0]-1,witness[0]-1+best):''};
}
function prefixes(text,offset,maxDigits) {
  const result=[];let variants=[''];
  for(let length=1;length<=maxDigits&&offset+length<=text.length;length++) {
    const c=text[offset+length-1];
    const digits=c==='g'?['0','7']:[String(c.charCodeAt(0)-96)];
    variants=variants.flatMap(prefix=>digits.map(d=>prefix+d)).filter(v=>v[0]!=='0');
    for(const digits of variants)result.push({length,n:BigInt(digits)});
  }
  return result;
}
function solve(text,cs,controlBound=null) {
  assert.match(text,/^[a-i]+$/);assert(cs.every(c=>c.length===3&&c.every(n=>Number.isSafeInteger(n)&&n>=0)));
  assert(cs.length>0&&cs[0][0]+cs[0][1]>0);
  const rep=repeatedSubstring(text),groups=new Map();
  cs.forEach((c,i)=>{const k=c.join(',');if(!groups.has(k))groups.set(k,[]);groups.get(k).push(i);});
  const duplicateGroups=[...groups.values()].filter(g=>g.length>1);
  const derivedBounds=[0,1].map(variable=>{
    const occurrences=cs.filter(c=>c[variable]>0).length;
    assert(occurrences>0);
    const maxDigits=Math.floor((text.length-(cs.length-occurrences))/occurrences);
    let maximum=10n**BigInt(maxDigits)-1n;
    for(const g of duplicateGroups) {
      const c=cs[g[0]];if(!c[variable])continue;
      const numerator=10n**BigInt(rep.length)-1n-BigInt(c[2])-2n*BigInt(c[1-variable]);
      maximum=maximum<numerator/BigInt(c[variable])?maximum:numerator/BigInt(c[variable]);
    }
    return maximum;
  });
  const bounds=derivedBounds.map(n=>controlBound!==null&&n>controlBound?controlBound:n);
  const maxEncodedLength=bounds.some(n=>n<2n)?0:cs.reduce((s,c)=>s+decimalLength(value(c,...bounds)),0);
  const metadata={repeat:rep,duplicateGroups:duplicateGroups.map(g=>g.map(i=>i+1)),
    upperBounds:{blue:derivedBounds[0].toString(),yellow:derivedBounds[1].toString()},maxEncodedLength,
    complete:true,firstPrefixes:0,secondPrefixes:0,integerPairs:0,matches:[]};
  if(maxEncodedLength<text.length) return {...metadata,reason:'Length exceeds the maximum allowed by repeated sums.'};
  const c0=cs[0],second=cs.findIndex(c=>c0[0]*c[1]-c0[1]*c[0]!==0);
  assert(second>0,'Two independent colour coefficients are needed.');
  const seen=new Set();
  const maxFirst=decimalLength(value(c0,...bounds));
  for(const first of prefixes(text,0,maxFirst)) {
    metadata.firstPrefixes++;
    const n0=first.n-BigInt(c0[2]);if(n0<2n*BigInt(c0[0]+c0[1]))continue;
    let pos=first.length,consistent=true;
    for(let i=1;i<second;i++) {
      const v=c0[0]?0:1;
      const numerator=n0*BigInt(cs[i][v]);
      if(numerator%BigInt(c0[v])){consistent=false;break;}
      const s=numerator/BigInt(c0[v])+BigInt(cs[i][2]),enc=encode(s);
      if(!text.startsWith(enc,pos)){consistent=false;break;}pos+=enc.length;
    }
    if(!consistent)continue;
    const c1=cs[second],det=BigInt(c0[0]*c1[1]-c0[1]*c1[0]);
    for(const next of prefixes(text,pos,decimalLength(value(c1,...bounds)))) {
      metadata.secondPrefixes++;
      const n1=next.n-BigInt(c1[2]);
      const pn=n0*BigInt(c1[1])-n1*BigInt(c0[1]),qn=BigInt(c0[0])*n1-BigInt(c1[0])*n0;
      if(pn%det||qn%det)continue;
      const p=pn/det,q=qn/det;
      if(p<2n||q<2n||p>bounds[0]||q>bounds[1])continue;
      metadata.integerPairs++;
      const decimal=sumString(cs,p,q);if(encode(decimal)!==text)continue;
      const id=`${p},${q}`;if(seen.has(id))continue;seen.add(id);
      metadata.matches.push({blue:p.toString(),yellow:q.toString(),decimal,sums:cs.map(c=>value(c,p,q).toString())});
    }
  }
  return {...metadata,reason:metadata.matches.length?'Exact complete-input matches.':'Every feasible prefix pair checked; no complete-input match.'};
}
const color=new Map(input.colored.map(([,co,r,c])=>[`${r},${c}`,co]));
function coefficients(direction,background) {
  return Array.from({length:14},(_,i)=>{
    const c=[0,0,0];
    for(let j=0;j<14;j++) {
      const [r,col]=direction==='row'?[i,j]:[j,i],co=color.get(`${r},${col}`);
      if(co==='B')c[0]++;else if(co==='Y')c[1]++;else c[2]+=background==='bits'?input.matrix[r][col]:background==='inverted-bits'?1-input.matrix[r][col]:0;
    }
    return c;
  });
}
const profiles=[];
for(const direction of ['row','column'])for(const background of ['bits','inverted-bits','zero'])for(const reverse of [false,true]) {
  const cs=coefficients(direction,background);if(reverse)cs.reverse();
  profiles.push({label:`${direction}/${background}/${reverse?'reverse':'forward'}`,cs});
}
module.exports={solve,encode,sumString,repeatedSubstring,coefficients,input,profiles,sha};
if(require.main===module) {
fs.mkdirSync(out,{recursive:true});
const save=(f,x)=>fs.writeFileSync(path.join(out,f),JSON.stringify(x,null,2)+'\n');
save('color_sum_spec.json',{sourceSHA256:sha(fs.readFileSync(__filename)),inputsSHA256:sha(inputBytes),
  hypothesis:'Assign the same integer p>=2 to every blue cell and q>=2 to every yellow cell. Concatenate the 14 minimal decimal line sums. a..i map 1..9; each g can mean 0 or 7 independently.',
  scope:'Row/column sums, each direction, with uncoloured original bits, inverted bits, or zero. Complete original DBBI and FAED, no separators or leading zero padding.',
  proof:'Every repeated coefficient triple yields an identical decimal block and therefore identical encoded substring. Longest repeated substring bounds both colour weights. Digit count supplies independent finite bounds. Two independent sums determine p,q exactly.',
  prime_note:'Search covers all integer weights >=2, including all primes, rather than selecting a finite list of primes.',profiles});
const controls=[];
for(const profile of profiles)for(const [p,q] of [[3n,17n],[37n,101n],[1000003n,1000033n]]) {
  const text=encode(sumString(profile.cs,p,q)),r=solve(text,profile.cs);
  assert(r.matches.some(x=>x.blue===p.toString()&&x.yellow===q.toString()));
  controls.push({profile:profile.label,blue:p.toString(),yellow:q.toString(),length:text.length,recovered:true});
}
// Small exact inverse controls: compare every solution <= 30 against brute
// force, including ambiguities introduced by encoding both zero and seven g.
let exactControls=0;
for(const cs of [[[1,0,3],[2,0,1],[1,1,2],[0,1,1],[1,0,3]],[[1,1,2],[2,0,1],[0,2,3],[1,1,2]]])for(const pair of [[2n,7n],[7n,17n],[13n,29n]]) {
  const text=encode(sumString(cs,...pair));
  const got=solve(text,cs,30n).matches.map(x=>`${x.blue},${x.yellow}`).sort();
  const want=[];for(let p=2n;p<=30n;p++)for(let q=2n;q<=30n;q++)if(encode(sumString(cs,p,q))===text)want.push(`${p},${q}`);
  assert.deepEqual(got,want.sort());exactControls++;
}
save('color_sum_controls.json',{planted:controls,exactInverseBruteForceControls:exactControls});
const results=[];
for(const field of ['dbbi','faed'])for(const profile of profiles)results.push({field,profile:profile.label,...solve(input[field],profile.cs)});
save('color_sum_results.json',results);
const summary={profiles:profiles.length,searches:results.length,complete:results.filter(r=>r.complete).length,
  matches:results.flatMap(r=>r.matches.map(m=>({field:r.field,profile:r.profile,...m}))),
  totalFirstPrefixes:results.reduce((s,r)=>s+r.firstPrefixes,0),totalSecondPrefixes:results.reduce((s,r)=>s+r.secondPrefixes,0),
  integerPairs:results.reduce((s,r)=>s+r.integerPairs,0),
  lengthRejected:results.filter(r=>r.maxEncodedLength<input[r.field].length).map(r=>({field:r.field,profile:r.profile,maxEncodedLength:r.maxEncodedLength,actualLength:input[r.field].length})),
  controls:{planted:controls.length,exactInverseBruteForce:exactControls},
  scope:'Only the declared direct decimal concatenation of 14 uniform-colour sums; not all uses of primes or matrixsumlist.'};
save('color_sum_summary.json',summary);console.log(JSON.stringify(summary,null,2));
}
