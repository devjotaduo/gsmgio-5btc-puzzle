'use strict';
// Independent certificate checker: does not import the interval/search program.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_format_headers_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),raw=fs.readFileSync(path.join(out,'cases.json')),cases=JSON.parse(raw),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
assert.equal(spec.inputSHA256,sha(inputRaw));assert.equal(summary.casesSHA256,sha(raw));assert(summary.complete);
assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(root,'solver','substituted_format_headers.cjs'))));
const formats={gzip:['1f8b08'],zlib:[],zip:['504b'],bzip2:Array.from({length:9},(_,i)=>'425a68'+(49+i).toString(16)),xz:['fd377a585a00'],'7z':['377abcaf271c']};
// Exhaust all 16-bit values, not the producer's CMF/FLG loops.
for(let n=0;n<65536;n++)if((n>>8&15)===8&&(n>>12)<=7&&n%31===0)formats.zlib.push(n.toString(16).padStart(4,'0'));
assert.deepEqual(spec.formats,formats);
const aliases=['',...'abcdefghi'];for(let a=0;a<9;a++)for(let b=a+1;b<9;b++)aliases.push('abcdefghi'[a]+'abcdefghi'[b]);
const expected=new Set();for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of aliases)for(const format of Object.keys(formats))expected.add(JSON.stringify([field,reverse,alias,format]));
let checkedNodes=0,rangeCases=0,negativeRanges=0,positiveRanges=0,positiveCases=0;
function width(n){let size=0;do{size++;n>>=8n;}while(n);return size;}
function witness(w,source,alias,lower,upper){
  assert(w);assert.match(w.mapping,/^[1-9]{9}$/);assert.equal(new Set(w.mapping).size,9);assert.match(w.digits,/^[0-9]+$/);assert.equal(w.digits.length,source.length);
  for(let i=0;i<source.length;i++){const d=w.digits[i];assert(d===w.mapping[source.charCodeAt(i)-97]||d==='0'&&alias.includes(source[i]));}
  const n=BigInt(w.digits);assert(n>=lower&&n<=upper);return n;
}
for(const c of cases){
  const id=JSON.stringify([c.field,c.reverse,c.aliases,c.format]);assert(expected.delete(id),'Missing/duplicate/unexpected case '+id);
  const source=c.reverse?Array.from(input[c.field]).reverse().join(''):input[c.field];let firstPositive=0;while(c.aliases.includes(source[firstPositive]))firstPositive++;
  const lowerLimit=BigInt('1'+'0'.repeat(source.length-firstPositive-1)),upperLimit=BigInt('9'.repeat(source.length));
  assert.equal(c.maxLeadingZeros,firstPositive);assert.equal(c.minimum,lowerLimit.toString());assert.equal(c.maximum,upperLimit.toString());assert.deepEqual(c.byteLengths,[width(lowerLimit),width(upperLimit)]);
  const expectedRanges=[];
  // Enumerate all byte widths up to the full decimal source, then intersect.
  for(let bytes=1;bytes<=width(upperLimit);bytes++)for(const magic of formats[c.format]){
    const n=BigInt('0x'+magic),extra=bytes-magic.length/2;if(extra<0)continue;
    let lower=n<<BigInt(extra*8),upper=((n+1n)<<BigInt(extra*8))-1n;
    if(lower<lowerLimit)lower=lowerLimit;if(upper>upperLimit)upper=upperLimit;
    if(lower<=upper)expectedRanges.push({bytes,magic,lower:String(lower),upper:String(upper)});
  }
  assert.deepEqual(c.results.map(r=>({bytes:r.bytes,magic:r.magic,lower:r.lower,upper:r.upper})),expectedRanges);
  for(const r of c.results){
    rangeCases++;const lower=BigInt(r.lower),upper=BigInt(r.upper),lo=String(lower).padStart(source.length,'0'),hi=String(upper).padStart(source.length,'0');
    if(r.compatible){
      positiveRanges++;const n=witness(r.witness,source,c.aliases,lower,upper),hex=n.toString(16).padStart(2*width(n),'0');assert.equal(width(n),r.bytes);assert(hex.startsWith(r.magic));
    }else{negativeRanges++;assert.equal(r.witness,null);}
    assert(r.nodes.length>0);const visited=new Set(),pending=[{id:0,at:0,tightLo:true,tightHi:true,map:'000000000'}];
    while(pending.length){
      const state=pending.pop(),node=r.nodes[state.id];assert(node);for(const key of ['at','tightLo','tightHi','map'])assert.deepEqual(node[key],state[key]);
      if(visited.has(state.id))continue;visited.add(state.id);checkedNodes++;
      const assigned=[...node.map].filter(x=>x!=='0');assert.equal(new Set(assigned).size,assigned.length);
      if(node.witness){assert(r.compatible);witness(node.witness,source,c.aliases,lower,upper);assert(node.at===source.length||!node.tightLo&&!node.tightHi);assert.equal(node.edges.length,0);continue;}
      assert(node.at<source.length);assert(node.tightLo||node.tightHi);
      const letter=source[node.at],idx=letter.charCodeAt(0)-97,allowed=[];
      for(let d=0;d<10;d++){
        if(node.tightLo&&d<Number(lo[node.at])||node.tightHi&&d>Number(hi[node.at]))continue;
        if(d===0){if(!c.aliases.includes(letter))continue;}
        else if(node.map[idx]!=='0'?node.map[idx]!==String(d):node.map.includes(String(d)))continue;
        allowed.push(d);
      }
      const actual=node.edges.map(e=>e.digit);
      // A successful tree may stop at its first witness; a rejection must cover every legal digit.
      if(r.compatible)assert.deepEqual(actual,allowed.slice(0,actual.length));else assert.deepEqual(actual,allowed);
      assert.equal(new Set(actual).size,actual.length);
      for(const edge of node.edges){const map=[...node.map];if(edge.digit)map[idx]=String(edge.digit);pending.push({id:edge.to,at:node.at+1,tightLo:node.tightLo&&edge.digit===Number(lo[node.at]),tightHi:node.tightHi&&edge.digit===Number(hi[node.at]),map:map.join('')});}
    }
    assert.equal(visited.size,r.nodes.length);
  }
  assert.equal(c.compatible,c.results.some(r=>r.compatible));if(c.compatible)positiveCases++;
}
assert.equal(expected.size,0);assert.equal(cases.length,1104);assert.equal(summary.cases,cases.length);assert.equal(summary.rangeCases,rangeCases);assert.equal(summary.nodes,checkedNodes);
const groups=Object.keys(formats).map(format=>({format,cases:cases.filter(c=>c.format===format).length,compatible:cases.filter(c=>c.format===format&&c.compatible).length,excluded:cases.filter(c=>c.format===format&&!c.compatible).length}));assert.deepEqual(summary.groups,groups);
const result={complete:true,cases:cases.length,rangeCases,negativeRanges,positiveRanges,positiveCases,checkedNodes,groups,casesSHA256:sha(raw),verifierSHA256:sha(fs.readFileSync(__filename)),scope:'All interval boundaries and case coverage independently reconstructed. Every rejected range has a complete legal-digit DAG certificate; every accepted range has a valid full digit-bijection/zero-alias witness. Header compatibility only; no decompression claim.'};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
