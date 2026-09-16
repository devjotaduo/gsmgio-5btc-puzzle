/* Exact, bounded tests of one zero-ambiguous decimal symbol.
 * node solver/zero_symbol_constraints.cjs
 * Each occurrence of ONE selected symbol independently means zero or a1z26.
 * The other eight symbols retain their a1z26 values. No network operations.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {nextAscii} = require('./zero_decimal_constraints.cjs');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'zero_symbol_2026-09-15');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const bytesOf = n => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
};

function search(symbols, zeroSymbol, {maxNodes = 1000000, maxMs = 15000} = {}) {
  assert.match(symbols, /^[a-i]+$/);
  assert.match(zeroSymbol, /^[a-i]$/);
  const digit = zeroSymbol.charCodeAt(0) - 96;
  const decimal = [...symbols].map(c => c === zeroSymbol ? '0' : String(c.charCodeAt(0) - 96)).join('');
  const minimum = BigInt(decimal);
  const weights = [...symbols].flatMap((c, i) => c === zeroSymbol ? [BigInt(digit) * 10n ** BigInt(symbols.length-i-1)] : []);
  const tails = Array(weights.length+1).fill(0n);
  for (let i=weights.length-1; i>=0; i--) tails[i] = tails[i+1]+weights[i];
  const certificate = [], hits = [], pending = [];
  let nodes = 0, ruledOut = 0n;
  const started = Date.now();
  function visit(i, lo, mask) {
    if (nodes >= maxNodes || Date.now()-started >= maxMs) {
      pending.push({mask, depth:i}); return;
    }
    nodes++;
    const hi = lo+tails[i], next = nextAscii(lo, true);
    if (next > hi) {
      ruledOut += 1n << BigInt(weights.length-i);
      certificate.push({mask, lo:lo.toString(), hi:hi.toString(), nextSevenBit:next.toString()});
      return;
    }
    if (i === weights.length) {
      assert([...bytesOf(lo)].every(b => b < 128));
      hits.push({mask, decimal:lo.toString(), hex:bytesOf(lo).toString('hex')}); return;
    }
    visit(i+1, lo, mask+'0');
    visit(i+1, lo+weights[i], mask+'1');
  }
  visit(0, minimum, '');
  const total = 1n << BigInt(weights.length);
  const unvisited = pending.reduce((n,p) => n+(1n << BigInt(weights.length-p.depth)), 0n);
  assert.equal(ruledOut+BigInt(hits.length)+unvisited, total);
  return {zeroSymbol, digit, ambiguous:weights.length, assignments:total.toString(), nodes,
    complete:pending.length===0, excludedAssignments:ruledOut.toString(), pendingAssignments:unvisited.toString(),
    elapsedMs:Date.now()-started, hits, pending, certificate};
}

function encode(decimal, digit) {
  return [...decimal].map(c => String.fromCharCode(96+(c==='0'?digit:Number(c)))).join('');
}
function controls() {
  let exhaustive=0, planted=0;
  for (let d=1; d<=9; d++) {
    const symbol = String.fromCharCode(96+d);
    for (const decimal of ['0','10020','707090','1200192','9990027','0000001']) {
      const source=encode(decimal,d), count=[...source].filter(c=>c===symbol).length, expected=[];
      for(let mask=0; mask<2**count; mask++) {
        let j=0;
        const value=BigInt([...source].map(c=>c===symbol ? ((mask>>j++)&1?d:0) : c.charCodeAt(0)-96).join(''));
        if([...bytesOf(value)].every(b=>b<128)) expected.push(value.toString());
      }
      const result=search(source,symbol);
      assert(result.complete);
      assert.deepEqual(result.hits.map(x=>x.decimal).sort(),expected.sort());
      exhaustive++;
    }
    for(const text of ['matrixsumlist','lastwordsbeforearchichoice','thispassword']) {
      const value=BigInt('0x'+Buffer.from(text).toString('hex'));
      const result=search(encode(value.toString(),d),symbol);
      assert(result.complete);
      assert(result.hits.some(x=>x.decimal===value.toString()));
      planted++;
    }
  }
  const limited=search('bbbbbbbbbbbbbbbb','b',{maxNodes:1});
  assert(!limited.complete);
  return {exhaustiveSmallCases:exhaustive,plantedRecoveries:planted,limitAccounting:true};
}

function main() {
  const checked=controls();
  const sourceBytes=fs.readFileSync(path.join(root,'README.md'));
  const source=sourceBytes.toString('utf8').split(/\r?\n/).find(l=>l.startsWith('> d b b i')).slice(2).replace(/[ *]/g,'');
  const fields={dbbi:source.slice(0,91),faed:source.slice(195,765)};
  const reference=JSON.parse(fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')));
  for(const [field,s] of Object.entries(fields)) assert.equal(s,reference[field]);
  const results=[];
  for(const [field,original] of Object.entries(fields)) for(const reversed of [false,true]) {
    const text=reversed?[...original].reverse().join(''):original;
    for(const symbol of 'abcdefghi') {
      const r={field,reversed,...search(text,symbol)};
      results.push(r);
      console.log(JSON.stringify({field,reversed,symbol,complete:r.complete,nodes:r.nodes,hits:r.hits.length}));
    }
  }
  fs.mkdirSync(out,{recursive:true});
  const report={date:'2026-09-15',hypothesis:'Each occurrence of one selected symbol is zero or its a1z26 digit. Other symbols retain a1z26. Whole field as decimal integer to minimal big-endian bytes; all bytes must be <=127.',
    limits:'One ambiguous symbol at a time; original or fully reversed field. No removals, insertions, extra cipher, or mixed alphabets.',
    sourceHashes:{script:sha(fs.readFileSync(__filename)),readme:sha(sourceBytes),...Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,sha(v)]))},
    fields,controls:checked,results};
  fs.writeFileSync(path.join(out,'results.json'),JSON.stringify(report,null,2)+'\n');
  const summary={controls:checked,cases:results.length,complete:results.filter(r=>r.complete).length,
    totalNodes:results.reduce((n,r)=>n+r.nodes,0),certificates:results.reduce((n,r)=>n+r.certificate.length,0),
    candidates:results.flatMap(r=>r.hits.map(h=>({field:r.field,reversed:r.reversed,zeroSymbol:r.zeroSymbol,...h}))),
    incomplete:results.filter(r=>!r.complete).map(({field,reversed,zeroSymbol,nodes,pendingAssignments})=>({field,reversed,zeroSymbol,nodes,pendingAssignments}))};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');
  console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={search,encode};
