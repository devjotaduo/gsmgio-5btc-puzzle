/* Necessary condition for repeated-key XOR -> seven-bit bytes:
 * ciphertext byte MSBs repeat with the key period. Search ALL zero masks,
 * not wordlists or XOR keys. Compatibility alone is NOT a decoded message.
 * node solver/xor_period_constraints.cjs [controls|probe|run]
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','xor_period_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const ten=[1n];for(let i=1;i<=600;i++)ten.push(ten[i-1]*10n);
function bytes(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
function periodic(n,period){const b=bytes(n);return [...b].every((v,i)=>i<period||(v>>7)===(b[i-period]>>7));}
function nextPeriodic(n,period) {
  assert(n>=0n&&Number.isInteger(period)&&period>=1);
  const b=bytes(n);
  for(let i=period;i<b.length;i++) {
    const wanted=b[i%period]>>7;
    if((b[i]>>7)===wanted)continue;
    let at=i;
    if(wanted===1)b[at]=128;
    else {
      for(at=i-1;at>=0;at--) {
        const ceiling=at<period?255:(b[at%period]>>7)?255:127;
        if(b[at]<ceiling){b[at]++;break;}
      }
      assert(at>=0);
    }
    for(let j=at+1;j<b.length;j++)b[j]=j<period?0:(b[j%period]>>7)*128;
    const result=BigInt('0x'+b.toString('hex'));assert(result>=n);return result;
  }
  return n;
}
function model(source,alias) {
  const low=BigInt([...source].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*ten[source.length-i-1]]:[]),tails=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];return {low,weights,tails};
}
function search(source,alias,period,{maxNodes=5000000,maxMs=15000,firstOnly=false}={}) {
  const {low,weights,tails}=model(source,alias),certificates=[],pending=[],hits=[];let nodes=0,covered=0n,stopped=false;const start=Date.now();
  function visit(i,lo,mask) {
    if(stopped||nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}
    nodes++;
    if(nextPeriodic(lo,period)>lo+tails[i]){certificates.push(mask);covered+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length){assert(periodic(lo,period));hits.push({mask,decimal:lo.toString(),hex:bytes(lo).toString('hex')});if(firstOnly)stopped=true;return;}
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,low,'');
  const remaining=pending.reduce((n,m)=>n+(1n<<BigInt(weights.length-m.length)),0n);assert.equal(covered+BigInt(hits.length)+remaining,1n<<BigInt(weights.length));
  return {period,ambiguous:weights.length,nodes,complete:pending.length===0,certificates,pending,hits,firstOnly,elapsedMs:Date.now()-start};
}
function controls() {
  let successors=0,bruteForce=0,planted=0;
  for(const period of [1,2,3,4]) {
    let next=65536n;while(!periodic(next,period))next++;
    for(let n=65535n;n>=0n;n--){if(periodic(n,period))next=n;assert.equal(nextPeriodic(n,period),next);successors++;}
    for(const source of ['ggbg','abcgg','gggggg','fgadggi'])for(const alias of ['b','g']) {
      const count=[...source].filter(c=>c===alias).length,expected=[];
      for(let mask=0;mask<2**count;mask++) {
        let j=0;const n=BigInt([...source].map(c=>c===alias?(mask&(1<<j++)?c.charCodeAt(0)-96:0):c.charCodeAt(0)-96).join(''));
        if(periodic(n,period))expected.push(n.toString());
      }
      const result=search(source,alias,period);assert(result.complete);assert.deepEqual(result.hits.map(h=>h.decimal).sort(),expected.sort());bruteForce++;
    }
  }
  for(const key of [Buffer.from([0x81]),Buffer.from([0xFE,0x23,0xCA]),Buffer.from('matrixsumlist')]) {
    const text=Buffer.from('A matrix list could specify a repeated XOR key.'),cipher=Buffer.from(text.map((b,i)=>b^key[i%key.length]));
    const decimal=BigInt('0x'+cipher.toString('hex')).toString(),source=[...decimal].map(d=>d==='0'?'g':String.fromCharCode(96+Number(d))).join('');
    const r=search(source,'g',key.length,{maxMs:5000});assert(r.complete);assert(r.hits.some(h=>h.hex===cipher.toString('hex')));planted++;
  }
  return {successors,bruteForce,planted};
}
function main() {
  const checked=controls();console.log(JSON.stringify({controls:checked}));if(process.argv[2]==='controls')return;
  if(process.argv[2]==='probe') {
    for(const period of [14,24,32]){const r=search(input.faed,'g',period);console.log(JSON.stringify({...r,certificates:r.certificates.length,pending:r.pending.length,hits:r.hits.length}));}return;
  }
  fs.mkdirSync(out,{recursive:true});
  const spec={hypothesis:'Whole decimal integer, a=1..i=9 and any one symbol may independently be zero, then minimal big-endian ciphertext bytes; any repeated byte XOR key of periods 1..32 must produce seven-bit plaintext.',
    caveat:'Only an unconfirmed model. Matching the necessary MSB condition is not a recovered key or readable plaintext. FAED tests all 9 zero aliases, DBBI g only. No arbitrary encoding/transposition/padding.',
    periods:[1,32],fields:{dbbi:['g'],faed:[...'abcdefghi']},directions:['original','reversed-symbols'],limits:{maxNodes:5000000,maxMs:15000},
    controls:checked,sourceSHA256:sha(fs.readFileSync(__filename)),inputSHA256:sha(inputBytes),reference:'https://cryptopals.com/sets/1/challenges/6'};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  let cases=0,nodes=0,certificates=0;const partial=[],compatible=[],excluded=[],byFamily={};
  for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of spec.fields[field]) {
    const source=reverse?[...input[field]].reverse().join(''):input[field],family=`${field}-${reverse?'reverse':'original'}-${alias}`;
    const records=[];
    for(let period=1;period<=32;period++) {
      const r=search(source,alias,period,{...spec.limits,firstOnly:field==='faed'}),id={field,reverse,alias,period};
      records.push({...id,...r});cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      if(r.hits.length)compatible.push({...id,witnesses:r.hits.length,firstOnly:r.firstOnly});
      if(!r.complete&&!r.hits.length)partial.push({...id,nodes:r.nodes});
      if(r.complete&&!r.hits.length)excluded.push(id);
      if(r.elapsedMs>2000)console.log(JSON.stringify({...id,nodes:r.nodes,complete:r.complete,hits:r.hits.length,elapsedMs:r.elapsedMs}));
    }
    fs.writeFileSync(path.join(out,`${family}.json`),JSON.stringify(records)+'\n');byFamily[family]={cases:32,excluded:records.filter(r=>r.complete&&!r.hits.length).length,compatible:records.filter(r=>r.hits.length).length,partial:records.filter(r=>!r.complete&&!r.hits.length).length};
    console.log(JSON.stringify({family,...byFamily[family],cases,nodes}));
  }
  const summary={cases,nodes,certificates,excluded,compatible,partial,byFamily,controls:checked};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');
  console.log(JSON.stringify({cases,nodes,certificates,excluded:excluded.length,compatible:compatible.length,partial:partial.length}));
}
if(require.main===module)main();
module.exports={nextPeriodic,periodic,search,controls};
