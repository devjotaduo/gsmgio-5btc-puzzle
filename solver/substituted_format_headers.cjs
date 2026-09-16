'use strict';
// Necessary file signatures under any digit bijection and <=2 zero aliases.
// Header compatibility is NOT valid decompression or a puzzle solution.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_format_headers_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw);
const formats={gzip:['1f8b08'],zlib:[],zip:['504b'],bzip2:Array.from({length:9},(_,i)=>Buffer.from('BZh'+(i+1)).toString('hex')),xz:['fd377a585a00'],'7z':['377abcaf271c']};
for(let c=8;c<=120;c+=16)for(let f=0;f<256;f++)if((256*c+f)%31===0)formats.zlib.push(Buffer.from([c,f]).toString('hex'));
function solve(source,aliases,lower,upper,digitCount=9){
  const lo=lower.toString().padStart(source.length,'0'),hi=upper.toString().padStart(source.length,'0');assert(lo.length===source.length&&hi.length===source.length&&lower<=upper);
  const map=Array(digitCount).fill(0),nodes=[],memo=new Map();
  function visit(at,tightLo,tightHi,prefix){
    const key=[at,Number(tightLo),Number(tightHi),map.join('')].join('/');if(memo.has(key))return {node:memo.get(key),witness:null};
    const id=nodes.length,node={at,tightLo,tightHi,map:map.join(''),edges:[]};nodes.push(node);
    if(at===source.length||!tightLo&&!tightHi){
      const final=[...map],unused=Array.from({length:digitCount},(_,i)=>i+1).filter(d=>!final.includes(d));for(let i=0;i<final.length;i++)if(!final[i])final[i]=unused.shift();
      const digits=prefix+[...source.slice(at)].map(c=>final[c.charCodeAt(0)-97]).join(''),n=BigInt(digits);assert(n>=lower&&n<=upper);node.witness={digits,mapping:final.join('')};return {node:id,witness:node.witness};
    }
    const s=source.charCodeAt(at)-97,a=tightLo?Number(lo[at]):0,b=tightHi?Number(hi[at]):9;
    for(let d=a;d<=b;d++){
      if(d===0&&!aliases.includes(source[at]))continue;if(d>digitCount)continue;
      if(d>0&&(map[s]?map[s]!==d:map.includes(d)))continue;
      const old=map[s];if(d)map[s]=d;const r=visit(at+1,tightLo&&d===a,tightHi&&d===b,prefix+d);map[s]=old;node.edges.push({digit:d,to:r.node});
      if(r.witness)return {node:id,witness:r.witness};
    }
    memo.set(key,id);return {node:id,witness:null};
  }
  const r=visit(0,true,true,'');return {compatible:Boolean(r.witness),witness:r.witness,nodes};
}
function byteLength(n){return Math.ceil(n.toString(16).length/2);}
function intervals(source,aliases,magic){
  let zeros=0;while(zeros<source.length&&aliases.includes(source[zeros]))zeros++;
  assert(zeros<source.length,'Main inputs contain more than two distinct letters.');
  const minimum=10n**BigInt(source.length-zeros-1),maximum=10n**BigInt(source.length)-1n,loLength=byteLength(minimum),hiLength=byteLength(maximum),ranges=[];
  for(let bytes=loLength;bytes<=hiLength;bytes++)for(const hex of magic){
    const size=hex.length/2;if(size>bytes)continue;const scale=256n**BigInt(bytes-size),prefix=BigInt('0x'+hex);let lower=prefix*scale,upper=(prefix+1n)*scale-1n;
    if(lower<minimum)lower=minimum;if(upper>maximum)upper=maximum;if(lower<=upper)ranges.push({bytes,magic:hex,lower:lower.toString(),upper:upper.toString()});
  }
  return {maxLeadingZeros:zeros,minimum:minimum.toString(),maximum:maximum.toString(),byteLengths:[loLength,hiLength],ranges};
}
function controls(){
  let bruteCases=0,assignments=0,plants=0;
  const maps=[];for(let a=1;a<=3;a++)for(let b=1;b<=3;b++)for(let c=1;c<=3;c++)if(new Set([a,b,c]).size===3)maps.push([a,b,c]);
  for(const source of ['abca','aaabb','aabcc','bacba'])for(const aliases of ['','a','ab'])for(const [l,h]of [[0,99],[100,399],[1111,2222],[1234,1234],[20202,30303],[32100,32199],[0,99999],[9876,12345]]){
    const max=10**source.length-1,lower=BigInt(Math.min(l,max)),upper=BigInt(Math.min(h,max));let possible=false;
    for(const map of maps){const places=[...source].flatMap((c,i)=>aliases.includes(c)?[i]:[]);for(let mask=0;mask<2**places.length;mask++){const ds=[...source].map(c=>map[c.charCodeAt(0)-97]);places.forEach((p,i)=>{if(mask&(1<<i))ds[p]=0;});const n=BigInt(ds.join(''));if(n>=lower&&n<=upper)possible=true;assignments++;}}
    const r=solve(source,aliases,lower,upper,3);assert.equal(r.compatible,possible);bruteCases++;
  }
  for(const magic of Object.values(formats).map(a=>a[0]))for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]])for(const aliases of ['g','bd']){
    const payload=Buffer.concat([Buffer.from(magic,'hex'),Buffer.from('matrixsumlist')]),n=BigInt('0x'+payload.toString('hex'));let at=0;const source=[...n.toString()].map(d=>d==='0'?aliases[at++%aliases.length]:String.fromCharCode(97+map.indexOf(Number(d)))).join(''),r=solve(source,aliases,n,n);assert(r.compatible&&r.witness.digits===n.toString());plants++;
  }
  return {bruteCases,bruteAssignments:assignments,plantedExactIntegers:plants};
}
function main(){
  fs.mkdirSync(out,{recursive:true});const checked=controls(),aliases=['',...'abcdefghi'];for(let a=0;a<9;a++)for(let b=a+1;b<9;b++)aliases.push(String.fromCharCode(97+a,97+b));
  const spec={hypothesis:'Complete original/reversed DBBI and FAED are decimal integers under any bijection a..i to 1..9. Every occurrence of up to two chosen letters may independently be zero instead. Minimal big-endian bytes must start with a listed file signature.',limits:'Necessary header compatibility only. A witness is not decompressed data. No byte reversal, removed symbols, extra prefix/suffix bytes, three zero aliases, other numeral bases, or other file formats.',formats,controls:checked,inputSHA256:sha(inputRaw),sourceSHA256:sha(fs.readFileSync(__filename)),references:['https://www.rfc-editor.org/rfc/rfc1952.html','https://www.rfc-editor.org/rfc/rfc1950.html','https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT','https://sourceware.org/bzip2/manual/manual.html','https://tukaani.org/xz/xz-file-format.txt','https://www.7-zip.org/recover.html']};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');const cases=[];let nodes=0,rangeCases=0;
  for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of aliases)for(const [format,magic]of Object.entries(formats)){
    const source=reverse?[...input[field]].reverse().join(''):input[field],bounds=intervals(source,alias,magic),results=[];
    for(const range of bounds.ranges){const r=solve(source,alias,BigInt(range.lower),BigInt(range.upper));nodes+=r.nodes.length;rangeCases++;results.push({...range,...r});}
    cases.push({field,reverse,aliases:alias,format,...bounds,ranges:undefined,results,compatible:results.some(r=>r.compatible)});
  }
  fs.writeFileSync(path.join(out,'cases.json'),JSON.stringify(cases)+'\n');
  const groups=Object.keys(formats).map(format=>({format,cases:cases.filter(c=>c.format===format).length,compatible:cases.filter(c=>c.format===format&&c.compatible).length,excluded:cases.filter(c=>c.format===format&&!c.compatible).length}));
  const summary={complete:true,cases:cases.length,rangeCases,nodes,groups,casesSHA256:sha(fs.readFileSync(path.join(out,'cases.json')))};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}
if(require.main===module)main();module.exports={solve,intervals,formats};
