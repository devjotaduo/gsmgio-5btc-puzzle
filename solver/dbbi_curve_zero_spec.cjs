'use strict';
// Experimental interpretation of DBBI as a scalar, not a claim about its role.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), folder = path.join(root, '_work/dbbi_curve_zero_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function build(input) {
  const moduli = { n: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', p: 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f' }, cases = [];
  for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) for (const reverse of [false, true]) for (const modulus of ['n','p']) {
    const aliases = String.fromCharCode(97 + a,97 + b), source = reverse ? [...input.dbbi].reverse().join('') : input.dbbi, positions = [], weights = []; let base = 0n;
    for (let i = 0; i < source.length; i++) { const w = BigInt(source.charCodeAt(i)-96) * 10n ** BigInt(source.length-i-1); if (aliases.includes(source[i])) { positions.push(i); weights.push(String(w)); } else base += w; }
    const split = Math.ceil(weights.length/2), m = BigInt('0x'+moduli[modulus]);
    cases.push({ id: cases.length, aliases, reverse, modulus, source, base: String(base), positions, weights, residues: weights.map(w=>String(BigInt(w)%m)), baseResidue:String(base%m), ambiguous:weights.length, split, assignments:String(1n<<BigInt(weights.length)), leftAssignments:2**split, rightAssignments:2**(weights.length-split), queryBranches:modulus==='n'?2:4 });
  }
  assert.equal(cases.length,144); return {moduli,cases};
}
function main() {
  fs.mkdirSync(folder,{recursive:true});assert(!fs.existsSync(path.join(folder,'spec.json')),'Inspect existing scalar search before rerunning');
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw),plan=build(input);
  const spec={hypothesis:'DBBI is one decimal integer under a1..i9, with every occurrence of at most TWO selected letters independently zero or its original digit. Use complete original/reversed field; reduce integer modulo secp256k1 group order n or field prime p. Result must be a valid scalar 1..n-1 matching target public key or its negation. No hash, truncation, byte reversal, unknown digit permutation or extra cipher.',inputSHA256:sha(raw),sourceSHA256:sha(fs.readFileSync(__filename)),targetPublicKey:input.target_pubkey,targetHash160:input.target_h160,...plan,coverage:'All 36 pairs dominate all singleton/zero-letter alias sets; overlaps are intentional, so sums of assignment counts are not unique keys.',algorithm:'Split the selected decimal-position weights. L=sum(left) mod m; R=(base+sum(right)) mod m. For m=n, match L*G against +/-P-R*G. For m=p, match against +/-P-R*G+c*p*G, c in {0,1}; validate c and scalar on collision. Keep all masks when point keys collide. Gray recurrence producer and binary-recursion verifier traverse every half assignment. Commutative stream fingerprints include masks, residue scalars and points.',sources:['https://www.secg.org/sec2-v2.pdf','https://ofek.dev/coincurve/api/']};
  fs.writeFileSync(path.join(folder,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  console.log(JSON.stringify({cases:plan.cases.length,maxAmbiguous:Math.max(...plan.cases.map(c=>c.ambiguous)),largestTable:Math.max(...plan.cases.map(c=>c.leftAssignments)),logicalAssignments:plan.cases.reduce((s,c)=>s+BigInt(c.assignments),0n).toString(),leftRows:plan.cases.reduce((s,c)=>s+c.leftAssignments,0),queryRows:plan.cases.reduce((s,c)=>s+c.rightAssignments*c.queryBranches,0)}));
}
if(require.main===module)main();module.exports={build};
