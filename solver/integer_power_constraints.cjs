/* Hypothesis: a whole unknown decimal number is P**e, where e>=2 and
 * P's minimum big-endian bytes are all <128. All e up to log2(max N),
 * all choices for ONE zero alias a..i, both complete symbol directions.
 * node solver/integer_power_constraints.cjs [controls|probe|run]
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {nextAscii}=require('./zero_decimal_constraints.cjs');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','integer_power_2026-09-15');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const ten=[1n];for(let i=1;i<=600;i++)ten.push(ten[i-1]*10n);
function bytes(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
function floorRoot(n,e) {
  assert(n>=0n&&Number.isInteger(e)&&e>=2);if(n<2n)return n;
  const E=BigInt(e),bits=n.toString(2).length;
  if(e>=bits)return 1n;
  let x=1n<<BigInt(Math.ceil(bits/e));
  for(;;){const y=((E-1n)*x+n/(x**(E-1n)))/E;if(y>=x)return x;x=y;}
}
function domain(source,alias) {
  const low=BigInt([...source].map(c=>c===alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...source].flatMap((c,i)=>c===alias?[BigInt(c.charCodeAt(0)-96)*ten[source.length-i-1]]:[]),tails=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];return {low,weights,tails};
}
function search(d,e,{maxNodes=200000,maxMs=2000}={}) {
  const {low,weights,tails}=d,certificates=[],pending=[],hits=[],E=BigInt(e);let nodes=0,covered=0n;const start=Date.now();
  function visit(i,lo,mask) {
    if(nodes>=maxNodes||Date.now()-start>=maxMs){pending.push(mask);return;}
    nodes++;const hi=lo+tails[i],lowerFloor=floorRoot(lo,e),lower=lowerFloor**E===lo?lowerFloor:lowerFloor+1n,upper=floorRoot(hi,e);
    if(lower>upper||nextAscii(lower,true)>upper){certificates.push(mask);covered+=1n<<BigInt(weights.length-i);return;}
    if(i===weights.length) {
      assert.equal(lower**E,lo);assert(bytes(lower).every(b=>b<128));hits.push({mask,cipherDecimal:lo.toString(),rootDecimal:lower.toString(),plaintextHex:bytes(lower).toString('hex')});return;
    }
    visit(i+1,lo,mask+'0');visit(i+1,lo+weights[i],mask+'1');
  }
  visit(0,low,'');const unvisited=pending.reduce((sum,m)=>sum+(1n<<BigInt(weights.length-m.length)),0n);assert.equal(covered+BigInt(hits.length)+unvisited,1n<<BigInt(weights.length));
  return {e,ambiguous:weights.length,nodes,complete:pending.length===0,certificates,pending,hits,elapsedMs:Date.now()-start};
}
function controls() {
  let roots=0,planted=0,bruteForce=0;
  for(let e=2;e<=12;e++)for(let n=0n;n<2000n;n++) {
    let r=0n;while((r+1n)**BigInt(e)<=n)r++;assert.equal(floorRoot(n,e),r);roots++;
  }
  for(const e of [2,3,5,7,17,41])for(let i=1;i<=25;i++) {
    const n=BigInt('0x'+sha(`root-control/${e}/${i}`).slice(0,Math.max(1,Math.floor(200/e)))),p=n**BigInt(e);assert.equal(floorRoot(p,e),n);assert.equal(floorRoot(p+1n,e),n);if(n>1n)assert.equal(floorRoot(p-1n,e),n-1n);roots+=3;
  }
  for(const e of [2,3,5,7])for(const alias of ['a','b','g']) {
    const text='thispassword',n=BigInt('0x'+Buffer.from(text).toString('hex'))**BigInt(e),source=[...n.toString()].map(d=>d==='0'?alias:String.fromCharCode(96+Number(d))).join('');
    const r=search(domain(source,alias),e,{maxNodes:1000000,maxMs:5000});assert(r.complete);assert(r.hits.some(h=>h.plaintextHex===Buffer.from(text).toString('hex')));planted++;
    for(const s of ['ggbg','abbbg','abcdegg']) {
      const d=domain(s,alias),expected=[];
      for(let mask=0;mask<2**d.weights.length;mask++) {
        const n=d.weights.reduce((a,w,i)=>a+(mask&(1<<i)?w:0n),d.low),r=floorRoot(n,e);
        if(r**BigInt(e)===n&&bytes(r).every(b=>b<128))expected.push(n.toString());
      }
      const r=search(d,e);assert(r.complete);assert.deepEqual(r.hits.map(h=>h.cipherDecimal).sort(),expected.sort());bruteForce++;
    }
  }
  return {roots,planted,bruteForce};
}
function main() {
  const checked=controls();console.log(JSON.stringify({controls:checked}));if(process.argv[2]==='controls')return;
  if(process.argv[2]==='probe'){for(const field of ['dbbi','faed'])for(const e of [2,3,5,7,17,41]){const r=search(domain(input[field],'g'),e);console.log(JSON.stringify({field,...r,certificates:r.certificates.length,pending:r.pending.length,hits:r.hits.length}));}return;}
  fs.mkdirSync(out,{recursive:true});
  const limits={maxNodes:200000,maxMs:2000},spec={hypothesis:'N=P**e, e>=2 integer, P minimum big-endian bytes all <=127. All a=1..i=9 except any ONE alias may independently be zero. Whole original or reverse-symbol DBBI/FAED.',
    caveat:'A conjectured use of prime numbers as exponents, generalized to all integers. Not modular exponentiation/RSA, not arbitrary byte encodings.',
    upperBound:'e<=floor(log2(max N)); any larger e requires P<2 and cannot yield N>1.',limits,controls:checked,inputSHA256:sha(inputBytes),sourceSHA256:sha(fs.readFileSync(__filename))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  let cases=0,nodes=0,certificates=0;const partial=[],candidates=[],groups=[];
  for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of 'abcdefghi') {
    const source=reverse?[...input[field]].reverse().join(''):input[field],d=domain(source,alias),maxN=d.low+d.tails[0],maxExponent=maxN.toString(2).length-1,records=[];
    for(let e=2;e<=maxExponent;e++) {
      const r=search(d,e,limits),id={field,reverse,alias,e};records.push({...id,...r});cases++;nodes+=r.nodes;certificates+=r.certificates.length;
      if(!r.complete)partial.push({...id,nodes:r.nodes,pending:r.pending.length});for(const h of r.hits)candidates.push({...id,...h});
    }
    const group={field,reverse,alias,maxExponent,cases:records.length,partial:records.filter(r=>!r.complete).length,candidates:records.reduce((n,r)=>n+r.hits.length,0)};groups.push(group);
    fs.writeFileSync(path.join(out,`${field}-${reverse?'reverse':'original'}-${alias}.json`),JSON.stringify(records)+'\n');console.log(JSON.stringify({...group,totalCases:cases,totalNodes:nodes}));
  }
  const pass=new Map(),padding=[];let aesAttempts=0;
  for(const c of candidates)for(const form of ['direct','sha256-hex']) {
    const b=Buffer.from(c.plaintextHex,'hex'),pw=form==='direct'?b:Buffer.from(sha(b)),hex=pw.toString('hex');if(!pass.has(hex))pass.set(hex,{passwordHex:hex,preimageHex:c.plaintextHex,form});
  }
  for(const p of pass.values())for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    aesAttempts++;const b=open(Buffer.from(p.passwordHex,'hex'),blob,digest);if(b)padding.push({passwordHex:p.passwordHex,blob:name,digest,plaintextHex:b.toString('hex')});
  }
  fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');fs.writeFileSync(path.join(out,'aes.json'),JSON.stringify({passwords:[...pass.values()],attempts:aesAttempts,padding},null,2)+'\n');
  const summary={cases,nodes,certificates,partial,candidates:candidates.length,groups,aesAttempts,padding:padding.length,controls:checked};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({...summary,groups:undefined},null,2));
}
if(require.main===module)main();
module.exports={floorRoot,domain,search};
