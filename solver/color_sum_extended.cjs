/* Additional exact inverses, declared separately from the 14-sum model.
 * node solver/color_sum_extended.cjs
 * Binary place values target DBBI only; combined count sums and the known
 * spiral-byte grouping target both original fields. No crypto or network.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {solve,encode,sumString,coefficients,input,sha}=require('./color_sum_constraints.cjs');
const out=path.resolve(__dirname,'../_work/matrix_hint_2026-09-11');
const color=new Map(input.colored.map(([,co,r,c])=>[`${r},${c}`,co]));
function addCell(cs,r,c,weight,background) {
  const co=color.get(`${r},${c}`);
  if(co==='B')cs[0]+=weight;
  else if(co==='Y')cs[1]+=weight;
  else cs[2]+=weight*(background==='bits'?input.matrix[r][c]:background==='inverted-bits'?1-input.matrix[r][c]:0);
}
function positional(direction,background,reverseBits) {
  return Array.from({length:14},(_,i)=>{
    const cs=[0,0,0];
    for(let j=0;j<14;j++) {
      const [r,c]=direction==='row'?[i,j]:[j,i];
      addCell(cs,r,c,2**(reverseBits?j:13-j),background);
    }
    return cs;
  });
}
function spiralBytes(background,includeTail) {
  const groups=[];
  for(let offset=0;offset<(includeTail?196:192);offset+=8) {
    const cells=input.spiral.slice(offset,offset+8),cs=[0,0,0];
    cells.forEach(([r,c],j)=>addCell(cs,r,c,2**(cells.length-1-j),background));
    groups.push(cs);
  }
  return groups;
}
const profiles=[];
for(const background of ['bits','inverted-bits','zero']) {
  for(const direction of ['row','column'])for(const reverseBits of [false,true])for(const reverse of [false,true]) {
    const cs=positional(direction,background,reverseBits);if(reverse)cs.reverse();
    profiles.push({label:`binary-place/${direction}/${background}/${reverseBits?'LSB-first':'MSB-first'}/${reverse?'reverse':'forward'}`,fields:['dbbi'],cs});
  }
  for(const first of ['row','column'])for(const reverseFirst of [false,true])for(const reverseSecond of [false,true]) {
    const a=coefficients(first,background),b=coefficients(first==='row'?'column':'row',background);
    if(reverseFirst)a.reverse();if(reverseSecond)b.reverse();
    profiles.push({label:`both-lines/${first}-first/${background}/${reverseFirst?'reverse':'forward'}/${reverseSecond?'reverse':'forward'}`,fields:['dbbi','faed'],cs:[...a,...b]});
  }
  for(const includeTail of [false,true]) {
    const cs=spiralBytes(background,includeTail);
    profiles.push({label:`spiral-bytes/${background}/${includeTail?'with-tail':'without-tail'}`,fields:['dbbi','faed'],cs});
    // Only reverse whole byte lists when the first group contains a colour.
    if(!includeTail)profiles.push({label:`spiral-bytes/${background}/without-tail/reverse`,fields:['dbbi','faed'],cs:cs.slice().reverse()});
  }
}
fs.mkdirSync(out,{recursive:true});
const save=(f,x)=>fs.writeFileSync(path.join(out,f),JSON.stringify(x,null,2)+'\n');
save('color_sum_extended_spec.json',{sourceSHA256:sha(fs.readFileSync(__filename)),solverSHA256:sha(fs.readFileSync(path.join(__dirname,'color_sum_constraints.cjs'))),
  inputsSHA256:sha(fs.readFileSync(path.resolve(__dirname,'../_work/prime_geometry_2026-09-11/inputs.json'))),
  hypothesis:'Uniform blue p>=2 and yellow q>=2. Concatenate minimal decimal linear sums; 0 and 7 both encode g. Full original input, no padding/separators.',
  scope:'DBBI: 14 binary-place line values. DBBI and FAED: 28 row+column count sums; 24 original spiral bytes, optionally followed by the last four bits as one value. Background bits/inverted-bits/zero. Orders explicitly enumerated below.',
  exclusion:'Binary-place FAED is not searched by this campaign.',profiles});
let planted=0;
for(const profile of profiles)for(const [p,q] of [[3n,17n],[37n,101n],[1000003n,1000033n]]) {
  const text=encode(sumString(profile.cs,p,q));
  const r=solve(text,profile.cs);
  assert(r.matches.some(x=>x.blue===p.toString()&&x.yellow===q.toString()),profile.label);planted++;
}
// Independent bounded exhaustive oracle for real coefficient sets.
let exhaustive=0;
for(const profile of profiles) {
  const text=encode(sumString(profile.cs,7n,17n));
  const got=solve(text,profile.cs,30n).matches.map(x=>`${x.blue},${x.yellow}`).sort(),want=[];
  for(let p=2n;p<=30n;p++)for(let q=2n;q<=30n;q++)if(encode(sumString(profile.cs,p,q))===text)want.push(`${p},${q}`);
  assert.deepEqual(got,want.sort(),profile.label);exhaustive++;
}
const results=[];
for(const profile of profiles)for(const field of profile.fields) {
  results.push({field,profile:profile.label,...solve(input[field],profile.cs)});
}
save('color_sum_extended_results.json',results);
const summary={profiles:profiles.length,searches:results.length,complete:results.filter(x=>x.complete).length,controls:{planted,exhaustive},
  lengthRejected:results.filter(x=>x.maxEncodedLength<input[x.field].length).length,
  firstPrefixes:results.reduce((s,r)=>s+r.firstPrefixes,0),secondPrefixes:results.reduce((s,r)=>s+r.secondPrefixes,0),
  integerPairs:results.reduce((s,r)=>s+r.integerPairs,0),matches:results.flatMap(r=>r.matches.map(m=>({field:r.field,profile:r.profile,...m}))),
  scope:'Only the exact concatenated decimal models in color_sum_extended_spec.json; not all interpretations of matrixsumlist.'};
save('color_sum_extended_summary.json',summary);console.log(JSON.stringify(summary,null,2));
