/* Whole decimal -> multiply/divide by a prime -> minimal 7-bit bytes.
 * Every g is independently 0/7. Exact interval pruning; no arbitrary mask
 * truncation. Prime factors are explicitly limited to the original 196 cells.
 * node solver/prime_scale_constraints.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const {input,sha}=require('./color_sum_constraints.cjs');
const out=path.resolve(__dirname,'../_work/matrix_hint_2026-09-11');
const bytes=n=>{let h=n.toString(16);return Buffer.from(h.length%2?'0'+h:h,'hex');};
const isPrime=n=>n>=2&&Array.from({length:Math.max(0,Math.floor(Math.sqrt(n))-1)},(_,i)=>i+2).every(d=>n%d);
const primes=Array.from({length:197},(_,i)=>i).filter(isPrime);
const pattern=t=>[...t].map(c=>c==='g'?'?':c.charCodeAt(0)-96).join('');
function solve(pat,a,b,{maxNodes=2000000,maxMs=10000}={}) {
  a=BigInt(a);b=BigInt(b);assert(a>0n&&b>0n&&/^[0-9?]+$/.test(pat));
  const minimum=BigInt(pat.replaceAll('?','0'));
  const weights=[...pat].flatMap((c,i)=>c==='?'?[7n*10n**BigInt(pat.length-1-i)]:[]),tail=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tail[i]=tail[i+1]+weights[i];
  let nodes=0,pruned=0,complete=true;const hits=[],start=Date.now();
  function visit(i,n) {
    if(nodes>=maxNodes||Date.now()-start>maxMs){complete=false;return;}
    nodes++;
    const lo=(n*a+b-1n)/b,hi=((n+tail[i])*a)/b;
    if(lo>hi||nextAscii(lo,true)>hi){pruned++;return;}
    if(i===weights.length) {
      assert(n*a%b===0n);const m=n*a/b;
      assert([...bytes(m)].every(x=>x<128));
      hits.push({decimal:n.toString(),outputDecimal:m.toString(),hex:bytes(m).toString('hex'),ascii:bytes(m).toString('ascii')});return;
    }
    visit(i+1,n);if(complete)visit(i+1,n+weights[i]);
  }
  visit(0,minimum);
  return {numerator:a.toString(),denominator:b.toString(),ambiguous:weights.length,assignments:(1n<<BigInt(weights.length)).toString(),nodes,pruned,complete,elapsedMs:Date.now()-start,hits};
}
function run() {
  fs.mkdirSync(out,{recursive:true});
  const save=(f,x)=>fs.writeFileSync(path.join(out,f),JSON.stringify(x,null,2)+'\n');
  save('prime_scale_spec.json',{sourceSHA256:sha(fs.readFileSync(__filename)),successorSHA256:sha(fs.readFileSync(path.join(__dirname,'zero_decimal_constraints.cjs'))),
    inputSHA256:sha(fs.readFileSync(path.resolve(__dirname,'../_work/prime_geometry_2026-09-11/inputs.json'))),primes,
    hypothesis:'Map a..i to 1..9; each g independently 0/7. Treat complete field as decimal integer N. Output M=N*p or M=N/p, requiring exact division. Every minimal big-endian byte must be 0..127.',
    motivation:'The same page represents other text as whole decimal integers. Confirmed primes may act as a factor, rather than radix or cell weights.',
    scope:'Original DBBI and FAED, primes <=196 (the original matrix cell count). No claim that the creator specifies this range, operation or character map. No byte stripping, UTF-8 or binary payload test.',
    jointScope:'Separately bound FAED/DBBI, product, sum, difference, XOR over all masks of both fields; interval rejection is sufficient, not a full inverse solver for these joint models.'});
  let exhaustive=0,planted=0;
  for(const pat of ['?2?','1???','?7?3?','??????'])for(const p of [2,3,47,101,193])for(const divide of [false,true]) {
    const a=divide?1n:BigInt(p),b=divide?BigInt(p):1n,want=[];
    const count=[...pat].filter(c=>c==='?').length;
    for(let mask=0;mask<2**count;mask++) {
      let i=0;const n=BigInt(pat.replaceAll('?',()=>mask&(1<<i++)?'7':'0'));
      if(n*a%b===0n&&[...bytes(n*a/b)].every(x=>x<128))want.push(n.toString());
    }
    const got=solve(pat,a,b);assert(got.complete);assert.deepEqual(got.hits.map(x=>x.decimal).sort(),want.sort());exhaustive++;
  }
  for(const p of [2,3,47,101,193])for(const divide of [false,true]) {
    let plain=null;
    for(let x=32;x<=126&&plain===null;x++)for(let y=32;y<=126;y++) {
      const n=BigInt('0x'+Buffer.concat([Buffer.from('matrixsumlist'),Buffer.from([x,y])]).toString('hex'));
      if(divide||n%BigInt(p)===0n){plain=n;break;}
    }
    assert(plain!==null);
    const n=divide?plain*BigInt(p):plain/BigInt(p),r=solve(n.toString().replace(/[07]/g,'?'),divide?1:p,divide?p:1);
    assert(r.complete&&r.hits.some(x=>x.outputDecimal===plain.toString()));planted++;
  }
  const results=[];
  for(const field of ['dbbi','faed'])for(const p of primes)for(const divide of [false,true])
    results.push({field,prime:p,operation:divide?'divide':'multiply',...solve(pattern(input[field]),divide?1:p,divide?p:1)});
  const bounds=t=>[0,7].map(g=>BigInt(pattern(t).replaceAll('?',String(g))));
  const [dl,dh]=bounds(input.dbbi),[fl,fh]=bounds(input.faed);
  const pow=1n<<BigInt(dh.toString(2).length);
  const jointCases=[['FAED/DBBI',(fl+dh-1n)/dh,fh/dl],['FAED*DBBI',fl*dl,fh*dh],
    ['FAED+DBBI',fl+dl,fh+dh],['FAED-DBBI',fl-dh,fh-dl],['FAED XOR DBBI',(fl/pow)*pow,(fh/pow+1n)*pow-1n]];
  const joint=jointCases.map(([operation,lo,hi])=>({operation,lower:lo.toString(),upper:hi.toString(),next7bit:nextAscii(lo,true).toString(),
    lowerHex:bytes(lo).subarray(0,8).toString('hex'),upperHex:bytes(hi).subarray(0,8).toString('hex'),rejected:nextAscii(lo,true)>hi}));
  save('prime_scale_results.json',{results,joint});
  const summary={primes:primes.length,searches:results.length,complete:results.filter(r=>r.complete).length,nodes:results.reduce((s,r)=>s+r.nodes,0),
    rootRejected:results.filter(r=>r.nodes===1&&r.pruned===1).length,
    hits:results.flatMap(r=>r.hits.map(h=>({field:r.field,prime:r.prime,operation:r.operation,...h}))),
    joint:joint.map(({operation,rejected,lowerHex,upperHex})=>({operation,rejected,lowerHex,upperHex})),controls:{exhaustive,planted},
    scope:'Only specified factors and whole minimal 7-bit byte outputs; not arbitrary primes or binary/other encodings.'};
  save('prime_scale_summary.json',summary);console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)run();
module.exports={solve};
