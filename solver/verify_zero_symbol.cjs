/* Independent counting verification of the interval certificates.
 * Does not import the search algorithm or its ASCII successor function.
 * node solver/verify_zero_symbol.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','zero_symbol_2026-09-15');
const reportBytes=fs.readFileSync(path.join(out,'results.json'));
const report=JSON.parse(reportBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');

// Number of integers in [0,n] whose minimal base-256 digits are all <=127.
// Leading zero bytes may be included: they preserve the predicate and give
// one unique representation per integer at any fixed width.
function countSevenBit(n) {
  if(n<0n)return 0n;
  const digits=[];
  do {digits.unshift(Number(n%256n));n/=256n;} while(n);
  let count=0n;
  for(let i=0;i<digits.length;i++) {
    count+=BigInt(Math.min(digits[i],128))*128n**BigInt(digits.length-i-1);
    if(digits[i]>=128)return count;
  }
  return count+1n;
}
function controls() {
  let expected=0n;
  for(let n=0;n<65536;n++) {
    if((n&255)<128 && (n>>8)<128)expected++;
    assert.equal(countSevenBit(BigInt(n)),expected);
  }
  assert.equal(countSevenBit(-1n),0n);
  for(let width=1;width<=300;width++) {
    assert.equal(countSevenBit(256n**BigInt(width)-1n),128n**BigInt(width));
    assert.equal(countSevenBit(256n**BigInt(width)),128n**BigInt(width)+1n);
  }
}
controls();
const readme=fs.readFileSync(path.join(root,'README.md'),'utf8');
const line=readme.split(/\r?\n/).find(l=>l.startsWith('> d b b i')).slice(2).replace(/[ *]/g,'');
const fields={dbbi:line.slice(0,91),faed:line.slice(195,765)};
const cases=new Set();
let checked=0;
for(const r of report.results) {
  assert(['dbbi','faed'].includes(r.field));
  assert.equal(typeof r.reversed,'boolean');
  assert.match(r.zeroSymbol,/^[a-i]$/);
  const id=[r.field,r.reversed,r.zeroSymbol].join('/');
  assert(!cases.has(id));cases.add(id);
  assert(r.complete && r.hits.length===0 && r.pending.length===0);
  assert.equal(sha(fields[r.field]),report.sourceHashes[r.field]);
  assert.equal(fields[r.field],report.fields[r.field]);
  const text=r.reversed?[...fields[r.field]].reverse().join(''):fields[r.field];
  const count=[...text].filter(c=>c===r.zeroSymbol).length;
  assert.equal(count,r.ambiguous);
  let coverage=0n;
  const prefixes=[];
  for(const c of r.certificate) {
    assert.match(c.mask,/^[01]*$/);
    assert(c.mask.length<=count);
    assert(!prefixes.some(p=>p.startsWith(c.mask)||c.mask.startsWith(p)));
    prefixes.push(c.mask);
    function endpoint(high) {
      let j=0;
      return BigInt([...text].map(ch=>{
        const d=ch.charCodeAt(0)-96;
        if(ch!==r.zeroSymbol)return d;
        const branch=j<c.mask.length?Number(c.mask[j]):Number(high);j++;
        return branch?d:0;
      }).join(''));
    }
    const lo=endpoint(false),hi=endpoint(true);
    assert.equal(lo.toString(),c.lo);assert.equal(hi.toString(),c.hi);
    assert.equal(countSevenBit(hi)-countSevenBit(lo-1n),0n);
    coverage+=1n<<BigInt(count-c.mask.length);checked++;
  }
  assert.equal(coverage,1n<<BigInt(count));
  assert.equal(coverage.toString(),r.assignments);
  assert.equal(coverage.toString(),r.excludedAssignments);
}
assert.equal(cases.size,36);
const result={method:'Independent counting of the 7-bit integer language inside every excluded interval; source-derived endpoints and complete prefix-free mask coverage.',
  cases:cases.size,certificates:checked,integerCountControls:65536,largeWidthControls:600,
  reportSHA256:sha(reportBytes),verifierSHA256:sha(fs.readFileSync(__filename)),allPassed:true};
fs.writeFileSync(path.join(out,'independent_verification.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result,null,2));
