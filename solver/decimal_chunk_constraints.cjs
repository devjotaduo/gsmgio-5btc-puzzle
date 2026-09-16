/* All fixed decimal chunk widths and variable decimal ASCII code points.
 * a=1..i=9; one chosen symbol may independently be zero at each occurrence.
 * node solver/decimal_chunk_constraints.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_decimal_2026-09-15');
const input=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'))),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const allowed=[9,10,13,...Array.from({length:95},(_,i)=>32+i)],allowedSet=new Set(allowed);
const powers10=[1n],powersA=[1n];for(let i=1;i<=600;i++){powers10.push(powers10[i-1]*10n);powersA.push(powersA[i-1]*BigInt(allowed.length));}
function bytes(n){const h=n.toString(16);return Buffer.from(h.length%2?'0'+h:h,'hex');}
function model(s,alias) {
  const lo=BigInt([...s].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...s].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*powers10[s.length-i-1]]:[]),tail=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tail[i]=tail[i+1]+weights[i];return {lo,weights,tail};
}
function search(m) {
  let nodes=0,partial=false;const certificates=[],hits=[];
  function visit(i,lo,prefix) {
    if(nodes>=50000){partial=true;return;}nodes++;
    if(nextAscii(lo,false)>lo+m.tail[i]){certificates.push(prefix);return;}
    if(i===m.weights.length){hits.push(bytes(lo).toString('hex'));return;}
    visit(i+1,lo,prefix+'0');if(!partial)visit(i+1,lo+m.weights[i],prefix+'1');
  }
  visit(0,m.lo,'');return {nodes,partial,certificates,hits};
}
// Independently count all positive minimal-width printable byte integers <= n.
function countPrintable(n) {
  if(n<0n)return 0n;const b=bytes(n);let count=0n;
  for(let size=1;size<b.length;size++)count+=powersA[size];
  for(let i=0;i<b.length;i++) {
    const smaller=allowed.filter(v=>v<b[i]).length;count+=BigInt(smaller)*powersA[b.length-i-1];if(!allowedSet.has(b[i]))return count;
  }
  return count+1n;
}
function verifyExcluded(m,result) {
  assert(!result.partial&&result.hits.length===0);let coverage=0n;
  const prefixes=[...result.certificates].sort();
  for(let j=0;j<prefixes.length;j++) {
    const p=prefixes[j];assert.match(p,/^[01]*$/);assert(p.length<=m.weights.length);if(j)assert(!p.startsWith(prefixes[j-1]));
    const lo=[...p].reduce((n,c,i)=>n+(c==='1'?m.weights[i]:0n),m.lo),hi=lo+m.tail[p.length];
    assert.equal(countPrintable(hi)-countPrintable(lo-1n),0n);coverage+=1n<<BigInt(m.weights.length-p.length);
  }
  assert.equal(coverage,1n<<BigInt(m.weights.length));
}
function matches(s,at,code,alias) {
  const d=code.toString();if(at+d.length>s.length)return false;
  return [...d].every((v,j)=>Number(v)===s.charCodeAt(at+j)-96||(v==='0'&&s[at+j]===alias));
}
function codepointWays(s,alias) {
  const dp=Array(s.length+1).fill(0n);dp[0]=1n;
  for(let i=0;i<s.length;i++)if(dp[i])for(const code of allowed)if(matches(s,i,code,alias))dp[i+code.toString().length]+=dp[i];
  // Suffix recursion provides a different traversal/check on the same grammar.
  const memo=new Map([[s.length,1n]]);
  function suffix(at){if(memo.has(at))return memo.get(at);let n=0n;for(const code of allowed)if(matches(s,at,code,alias))n+=suffix(at+code.toString().length);memo.set(at,n);return n;}
  assert.equal(dp.at(-1),suffix(0));return {ways:dp.at(-1).toString(),reachableOffsets:dp.flatMap((v,i)=>v>0n?[i]:[])};
}
function encodeDecimal(decimal,alias){return [...decimal].map(c=>c==='0'?alias:String.fromCharCode(96+Number(c))).join('');}
function controls() {
  let running=0n;for(let n=0;n<65536;n++){if([...bytes(BigInt(n))].every(v=>allowedSet.has(v)))running++;assert.equal(countPrintable(BigInt(n)),running);}
  let planted=0,brute=0;
  for(const alias of 'abcdefghi') {
    for(const [size,width]of [[2,5],[3,8],[4,11]]) {
      const plain=Buffer.from('prime matrix list');const blocks=[];for(let i=0;i<plain.length;i+=size)blocks.push(plain.subarray(i,i+size));
      const source=blocks.map(b=>encodeDecimal(BigInt('0x'+b.toString('hex')).toString().padStart(width,'0'),alias)).join('');
      for(let i=0;i<blocks.length;i++){const r=search(model(source.slice(i*width,(i+1)*width),alias));assert(!r.partial&&r.hits.includes(blocks[i].toString('hex')));}planted++;
    }
    const plain='matrix sum list',source=encodeDecimal([...Buffer.from(plain)].join(''),alias);assert(BigInt(codepointWays(source,alias).ways)>0n);planted++;
    for(const source of [alias.repeat(4),`c${alias}${alias}b`]) {
      const count=[...source].filter(c=>c===alias).length,expected=[];
      for(let mask=0;mask<2**count;mask++){let bit=0;const n=BigInt([...source].map(c=>c===alias?(((mask>>bit++)&1)?c.charCodeAt(0)-96:0):c.charCodeAt(0)-96).join(''));const b=bytes(n);if([...b].every(v=>allowedSet.has(v)))expected.push(b.toString('hex'));}
      const m=model(source,alias),r=search(m);assert(!r.partial);assert.deepEqual(r.hits.sort(),expected.sort());if(!r.hits.length)verifyExcluded(m,r);brute++;
    }
  }
  return {integerCountControls:65536,plantedModels:planted,bruteForceCases:brute};
}
const checked=controls();fs.mkdirSync(out,{recursive:true});const cases=[],codepoints=[];let excluded=0,partial=0,certificates=0;
for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of 'abcdefghi') {
  const s=reverse?[...input[field]].reverse().join(''):input[field];
  for(let width=1;width<=s.length;width++) {
    let status='survives',witness=null,ways=1n;
    for(let at=0;at<s.length;at+=width) {
      const m=model(s.slice(at,at+width),alias),r=search(m);
      if(r.partial){status='partial';partial++;witness={at,...r};break;}
      if(!r.hits.length){status='excluded';excluded++;verifyExcluded(m,r);certificates+=r.certificates.length;witness={at,chunkLength:Math.min(width,s.length-at),certificates:r.certificates,nodes:r.nodes};break;}
      ways*=BigInt(r.hits.length);
    }
    cases.push({field,reverse,alias,width,status,witness,...(status==='survives'?{ways:ways.toString()}:{})});
  }
  codepoints.push({field,reverse,alias,...codepointWays(s,alias)});
}
const result={hypothesis:'Fixed a1..i9; any one symbol independently zero or original digit. Fixed-width chunks, including final short chunk, each interpreted as a decimal integer and minimal big-endian printable ASCII+TAB/LF/CR. Separately: variable-width minimal decimal code points for the same alphabet.',
  scope:'All widths from 1 through field length, all 9 zero aliases, both complete field orientations; no discarded digits. Variable code points allow no extra leading zeros. Unknown permutations combined with chunking are NOT covered.',
  controls:checked,cases:cases.length,excluded,partial,survivors:cases.filter(c=>c.status==='survives'),independentlyCheckedCertificates:certificates,codepointCases:codepoints.length,codepointSurvivors:codepoints.filter(c=>c.ways!=='0'),sourceSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(out,'chunk_cases.json'),JSON.stringify(cases,null,2)+'\n');fs.writeFileSync(path.join(out,'codepoint_cases.json'),JSON.stringify(codepoints,null,2)+'\n');fs.writeFileSync(path.join(out,'chunk_summary.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
