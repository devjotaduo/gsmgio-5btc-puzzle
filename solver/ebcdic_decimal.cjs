'use strict';
// Whole decimal integers -> IBM EBCDIC 1141. Only local puzzle inputs.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {prepare,eachPermutation}=require('./substituted_decimal_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','ebcdic_decimal_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'));
const input=JSON.parse(inputRaw),tableRaw=fs.readFileSync(path.join(out,'encoding.json'));
const table=JSON.parse(tableRaw.toString('utf8').replace(/^\uFEFF/,''));
const printable=c=>c.length===1&&((c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126)||[9,10,13].includes(c.charCodeAt(0)));
const allowed=table.decoded.flatMap((c,i)=>printable(c)?[i]:[]),allowedSet=new Set(allowed);
assert.equal(allowed.length,98);assert(!allowedSet.has(0));
function bytes(n){let h=n.toString(16);return Buffer.from(h.length%2?'0'+h:h,'hex');}
function successor(n){
  const bs=[...bytes(n)];
  for(let i=0;i<bs.length;i++)if(!allowedSet.has(bs[i])){
    for(let j=i;j>=0;j--){const a=allowed.find(v=>v>bs[j]);if(a!==undefined){bs[j]=a;bs.fill(allowed[0],j+1);return BigInt('0x'+Buffer.from(bs).toString('hex'));}}
    return BigInt('0x'+Buffer.alloc(bs.length+1,allowed[0]).toString('hex'));
  }
  return n;
}
function search(low,weights,maxNodes=200000){
  const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
  let nodes=0,complete=true;const hits=[];
  function visit(i,n){
    if(nodes>=maxNodes){complete=false;return;}nodes++;
    if(successor(n)>n+tails[i])return;
    if(i===weights.length){hits.push({decimal:n.toString(),hex:bytes(n).toString('hex')});return;}
    visit(i+1,n);if(complete)visit(i+1,n+weights[i]);
  }
  visit(0,low);return {nodes,complete,hits};
}
function mapped(model,map){return {low:model.coefficients.reduce((n,c,i)=>n+c*BigInt(map[i]),0n),weights:model.weights[map[model.aliasIndex]]};}
function fixed(source,aliases){
  let low=0n;const weights=[];
  for(let i=0;i<source.length;i++){const w=BigInt(source.charCodeAt(i)-96)*10n**BigInt(source.length-i-1);if(aliases.includes(source[i]))weights.push(w);else low+=w;}
  return {low,weights};
}
function encode(text,map,alias){
  const bs=Buffer.from([...text].map(c=>{const n=table.decoded.indexOf(c);assert(n>=0);return n;}));
  const inverse=new Map(map.map((d,i)=>[String(d),String.fromCharCode(97+i)]));
  return [...BigInt('0x'+bs.toString('hex')).toString()].map(c=>c==='0'?alias:inverse.get(c)).join('');
}
function controls(){
  // Enumerate all one/two-byte accepted numbers and the least three-byte one.
  const values=[...allowed];for(const a of allowed)for(const b of allowed)values.push(a*256+b);values.push(allowed[0]*65793);values.sort((a,b)=>a-b);
  let j=0;for(let n=0;n<65536;n++){while(values[j]<n)j++;assert.equal(successor(BigInt(n)),BigInt(values[j]));}
  let brute=0,planted=0;
  const maps=[[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]];
  for(const alias of 'abcdefghi')for(const map of maps){
    for(const source of [alias.repeat(5),`abc${alias}${alias}fg`,`i${alias}a${alias}b`]){
      const m=mapped(prepare(source,alias),map),expected=[];
      for(let mask=0;mask<2**m.weights.length;mask++){let n=m.low;for(let k=0;k<m.weights.length;k++)if(mask&(1<<k))n+=m.weights[k];if([...bytes(n)].every(b=>allowedSet.has(b)))expected.push(n.toString());}
      const r=search(m.low,m.weights);assert(r.complete);assert.deepEqual(r.hits.map(h=>h.decimal).sort(),expected.sort());brute++;
    }
    const text="I've been waiting for you.\nThe matrix has you!",source=encode(text,map,alias),m=mapped(prepare(source,alias),map),r=search(m.low,m.weights);
    assert(r.complete);assert(r.hits.some(h=>[...Buffer.from(h.hex,'hex')].map(b=>table.decoded[b]).join('')===text));planted++;
  }
  for(const aliases of ['ab','bg','fi']){
    const source=encode('last words before archichoice',maps[0],aliases[0]),m=fixed(source,aliases),r=search(m.low,m.weights);assert(r.complete);assert(r.hits.some(h=>[...Buffer.from(h.hex,'hex')].map(b=>table.decoded[b]).join('')==='last words before archichoice'));planted++;
  }
  return {successorIntegers:65536,bruteForceCases:brute,plantedRecoveries:planted};
}
function main(){
  fs.mkdirSync(out,{recursive:true});const checked=controls();
  const spec={hypothesis:'Whole original/reversed DBBI and FAED are decimal integers, with zero aliases per occurrence. Minimal bytes in either byte order must decode as ASCII printable characters or TAB/LF/CR in IBM EBCDIC 1141.',
    families:['a=1..i=9, zero to two distinct aliases','Every bijection a..i -> 1..9, one zero alias'],
    limits:'No removed characters, other transpositions, three or more zero aliases, or non-ASCII characters in the decoded text.',
    allowed,controls:checked,inputSHA256:sha(inputRaw),tableSHA256:sha(tableRaw),sourceSHA256:sha(fs.readFileSync(__filename)),helperSHA256:sha(fs.readFileSync(path.join(__dirname,'substituted_decimal_constraints.cjs')))};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');console.log(JSON.stringify({controls:checked}));
  const summary={groups:[],cases:0,nodes:0,hits:0,partial:[],candidates:[]};
  const aliases=['',...'abcdefghi'];for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)aliases.push(String.fromCharCode(97+i,97+j));
  function save(){fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');}
  function runGroup(family,field,reverse,alias){
    const source=reverse?[...input[field]].reverse().join(''):input[field],start=Date.now();let cases=0,nodes=0,hits=0;
    function accept(map,r){cases++;nodes+=r.nodes;hits+=r.hits.length;if(!r.complete)summary.partial.push({family,field,reverse,alias,mapping:map.join(''),nodes:r.nodes});for(const h of r.hits)summary.candidates.push({family,field,reverse,alias,mapping:map.join(''),...h});}
    if(family==='fixed'){const m=fixed(source,alias);accept([1,2,3,4,5,6,7,8,9],search(m.low,m.weights));}
    else {const m=prepare(source,alias);eachPermutation(map=>{const a=mapped(m,map);accept(map,search(a.low,a.weights));});}
    const group={family,field,reverse,alias,cases,nodes,hits,elapsedMs:Date.now()-start};summary.groups.push(group);summary.cases+=cases;summary.nodes+=nodes;summary.hits+=hits;save();if(family!=='fixed')console.log(JSON.stringify(group));
  }
  for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of aliases)runGroup('fixed',field,reverse,alias);
  console.log(JSON.stringify({fixedCases:summary.cases,nodes:summary.nodes,hits:summary.hits,partial:summary.partial.length}));
  for(const alias of 'abcdefghi')for(const field of ['dbbi','faed'])for(const reverse of [false,true])runGroup('substituted',field,reverse,alias);
  summary.complete=summary.partial.length===0;save();console.log(JSON.stringify({complete:summary.complete,cases:summary.cases,nodes:summary.nodes,hits:summary.hits}));
}
if(require.main===module)main();module.exports={successor,search,fixed,mapped,encode,allowed,bytes};
