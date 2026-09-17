'use strict';
// Test an unknown affine nonce recurrence shared by the two signing batches.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const mod = x => (x % N + N) % N;
function pow(a, b) { let r = 1n; a = mod(a); for (; b; b >>= 1n, a = a * a % N) if (b & 1n) r = r * a % N; return r; }
function inv(a) { a = mod(a); assert(a); let [t, next, r, rest] = [0n, 1n, N, a]; while (rest) { const q = r / rest; [t, next] = [next, t - q * next]; [r, rest] = [rest, r - q * rest]; } assert.equal(r, 1n); return mod(t); }
let odd = N - 1n, shifts = 0; while (!(odd & 1n)) { odd >>= 1n; shifts++; }
let nonresidue = 2n; while (pow(nonresidue, (N - 1n) / 2n) !== N - 1n) nonresidue++;
function sqrt(a) {
  a = mod(a); if (!a) return 0n; if (pow(a, (N - 1n) / 2n) !== 1n) return null;
  let c = pow(nonresidue, odd), x = pow(a, (odd + 1n) / 2n), t = pow(a, odd), m = shifts;
  while (t !== 1n) { let i = 1, v = t * t % N; while (i < m && v !== 1n) { v = v * v % N; i++; } assert(i < m);
    const b = pow(c, 1n << BigInt(m - i - 1)); x = x * b % N; c = b * b % N; t = t * c % N; m = i; }
  assert.equal(x * x % N, a); return x;
}
function roots(poly) {
  const [c,b,a] = poly.map(mod);
  if (!a) return b ? {all: false, roots: [mod(-c * inv(b))]} : {all: !c, roots: []};
  const d = sqrt(b*b - 4n*a*c); if (d === null) return {all: false, roots: []};
  const q = inv(2n*a), rs = [...new Set([mod((-b+d)*q), mod((-b-d)*q)])];
  for (const r of rs) assert.equal(mod(c+b*r+a*r*r),0n); return {all: false, roots: rs};
}
const difference = (a,b) => [mod(a[0]-b[0]),mod(a[1]-b[1])];
const product = (a,b) => [a[0]*b[0],a[0]*b[1]+a[1]*b[0],a[1]*b[1]];
function coefficients(a,b) {
  // k(d) = z/s + (r/s)*d. Equal ratios of consecutive differences:
  // (a2-a1)/(a1-a0) = (b2-b1)/(b1-b0).
  const left = product(difference(a[2],a[1]),difference(b[1],b[0]));
  const right = product(difference(b[2],b[1]),difference(a[1],a[0]));
  return left.map((v,i) => mod(v-right[i]));
}
function permutations(a) { if (!a.length) return [[]]; return a.flatMap((v,i) => permutations(a.filter((_,j) => j!==i)).map(t => [v,...t])); }
function publicKey(d) { if (d<=0n || d>=N) return null; const e = crypto.createECDH('secp256k1'); e.setPrivateKey(Buffer.from(d.toString(16).padStart(64,'0'),'hex')); return e.getPublicKey('hex','uncompressed'); }
function controls() {
  let squareCases=0;
  for (let i=0n;i<100n;i++) { const a=BigInt('0x'+crypto.createHash('sha256').update('sqrt-control-'+i).digest('hex'))%N; const r=sqrt(a*a%N); assert(r!==null && r*r%N===a*a%N); squareCases++; }
  assert.equal(sqrt(nonresidue),null);
  assert.deepEqual(roots([6n,-5n,1n]).roots.sort(),[2n,3n]); assert.equal(roots([0n,0n,0n]).all,true);
  const d=123456789n, multiplier=BigInt('0x123456789abcdef'), triples=[];
  for (let batch=0;batch<2;batch++) {
    let k=BigInt(batch+2)*987654321n, increment=BigInt(batch+7)*1234567n; const triple=[];
    for (let j=0;j<3;j++) { const alpha=BigInt('0x'+crypto.createHash('sha256').update(`alpha-${batch}-${j}`).digest('hex'))%N;
      triple.push([mod(k-alpha*d),alpha]); k=mod(multiplier*k+increment); }
    triples.push(triple);
  }
  const poly=coefficients(...triples), solution=roots(poly); assert(!solution.all); assert(solution.roots.includes(d));
  return {squareRootControls:squareCases,nonresidueRejected:true,quadraticRootsVerified:true,plantedUnknownMultiplierKeyRecovered:true,
    distinctBatchIncrementsSupported:true,positivePrivateKey:d.toString(16),positiveTriples:triples.map(t=>t.map(p=>p.map(v=>v.toString(16)))),positivePolynomial:poly.map(v=>v.toString(16))};
}
function main() {
  const root=path.resolve(__dirname,'..'), src=path.resolve(process.argv[2] || path.join(root,'_work/prize_nonce_2026-09-17/inputs/signatures.json'));
  const out=path.resolve(process.argv[3] || path.join(root,'_work/prize_nonce_2026-09-17/recurrence'));
  assert(!fs.existsSync(out),'Use a fresh output directory.'); fs.mkdirSync(out,{recursive:true});
  const save=(f,v)=>fs.writeFileSync(path.join(out,f),JSON.stringify(v,null,2)+'\n',{flag:'wx'});
  save('controls.json',controls()); const raw=fs.readFileSync(src), sigs=JSON.parse(raw); assert.equal(sigs.length,6);
  const data=JSON.parse(fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json'))), groups=new Map();
  for (const s of sigs) { assert.equal(s.publicKey,data.target_pubkey); if (!groups.has(s.txid)) groups.set(s.txid,[]); groups.get(s.txid).push(s); }
  const batches=[...groups.values()]; assert.equal(batches.length,2); assert(batches.every(b=>b.length===3));
  const rows=sigs.map(s=>{const inverse=inv(BigInt('0x'+s.s));return [mod(BigInt('0x'+s.z)*inverse),mod(BigInt('0x'+s.r)*inverse)];});
  const orders=batches.map(b=>permutations(b.map(s=>sigs.indexOf(s)))), seen=new Set(), hits=[], identities=[], cases=[];
  let withRoots=0; const started=Date.now();
  for (const a of orders[0]) for (const b of orders[1]) for (let mask=0;mask<64;mask++) {
    const signed=rows.map((p,i)=>p.map(v=>mod((mask & (1<<i)) ? -v : v)));
    const poly=coefficients(a.map(i=>signed[i]),b.map(i=>signed[i])), solution=roots(poly);
    const record={orders:[a,b],signMask:mask,polynomial:poly.map(v=>v.toString(16)),roots:solution.roots.map(v=>v.toString(16)),all:solution.all};cases.push(record);
    if (solution.all) identities.push({orders:[a,b],signMask:mask}); if (solution.roots.length) withRoots++;
    for (const d of solution.roots) { const hex=d.toString(16).padStart(64,'0'); if (seen.has(hex)) continue; seen.add(hex);
      if (publicKey(d)===data.target_pubkey) hits.push({privateKeyHex:hex,orders:[a,b],signMask:mask}); }
  }
  save('cases.json',cases); save('spec.json',{hypothesis:'Within each three-input transaction, nonce generation is k_next=A*k+B modulo secp256k1 order. A is shared between batches; B and initial seed may differ. Every internal order and every s-sign normalization is tested.',
    derivation:'For each signature k=(z+r*d)/s. Equal consecutive-difference ratios across the two batches give a quadratic in d. Solve all roots modulo the prime group order, then compare d*G with the original prize public key.',
    inputSHA256:crypto.createHash('sha256').update(raw).digest('hex'),sourceSHA256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
    exclusions:'Does not cover different multipliers between batches, skipped generator outputs, nonlinear generators, or a recurrence modulo another integer.'});
  const result={cases:cases.length,withRoots,distinctRootCandidates:seen.size,identicallyZeroCases:identities,hits,authenticatedSolution:hits.length>0,elapsedMs:Date.now()-started};
  save('summary.json',result); console.log(JSON.stringify(result,null,2));
}
if (require.main===module) main();
module.exports={mod,inv,sqrt,roots,coefficients,N};
