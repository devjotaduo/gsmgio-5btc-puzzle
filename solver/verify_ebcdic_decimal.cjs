'use strict';
// Independent interval rank verifier; no searcher/decimal helper imports.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','ebcdic_decimal_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw);
const tableRaw=fs.readFileSync(path.join(out,'encoding.json')),table=JSON.parse(tableRaw.toString('utf8').replace(/^\uFEFF/,''));
const allowed=[];for(let i=0;i<256;i++){const c=table.decoded[i].codePointAt(0);if(c>=32&&c<=126||c===9||c===10||c===13)allowed.push(i);}
const present=new Set(allowed),powers=[1n],shorter=[0n,0n];assert(!present.has(0));
for(let i=1;i<=300;i++){powers[i]=powers[i-1]*BigInt(allowed.length);shorter[i+1]=shorter[i]+powers[i];}
function rank(n){
  if(n<0n)return 0n;
  let h=n.toString(16);if(h.length%2)h='0'+h;const bs=Buffer.from(h,'hex');let total=shorter[bs.length];
  for(let i=0;i<bs.length;i++){
    let k=0;while(k<allowed.length&&allowed[k]<bs[i])k++;
    total+=BigInt(k)*powers[bs.length-i-1];if(!present.has(bs[i]))return total;
  }
  return total+1n;
}
function permutations(callback,prefix=[],used=0){if(prefix.length===9){callback(prefix);return;}for(let i=1;i<=9;i++)if(!(used&(1<<i))){prefix.push(i);permutations(callback,prefix,used|1<<i);prefix.pop();}}
function build(source,aliases){
  const coefficients=[...'abcdefghi'].map(c=>aliases.includes(c)?0n:BigInt([...source].map(s=>s===c?'1':'0').join('')));
  const places=[];for(let i=0;i<source.length;i++)if(aliases.includes(source[i]))places.push({index:source.charCodeAt(i)-97,place:10n**BigInt(source.length-i-1)});
  return {coefficients,places};
}
function verify(m,map){
  const ws=m.places.map(p=>p.place*BigInt(map[p.index]));
  const lo=m.coefficients.reduce((n,c,i)=>n+c*BigInt(map[i]),0n),span=ws.reduce((n,c)=>n+c,0n);let nodes=0;const hits=[];
  function visit(i,n,width){
    nodes++;if(rank(n+width)===rank(n-1n))return;
    if(i===ws.length){assert.equal(width,0n);hits.push(n.toString());return;}
    visit(i+1,n+ws[i],width-ws[i]);visit(i+1,n,width-ws[i]);
  }
  visit(0,lo,span);return {nodes,hits};
}
function main(){
  const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
  assert(saved.complete);assert.equal(saved.partial.length,0);assert.equal(spec.inputSHA256,sha(inputRaw));assert.equal(spec.tableSHA256,sha(tableRaw));
  assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(__dirname,'ebcdic_decimal.cjs'))));assert.equal(spec.helperSHA256,sha(fs.readFileSync(path.join(__dirname,'substituted_decimal_constraints.cjs'))));assert.deepEqual(spec.allowed,allowed);
  let cumulative=0n;for(let n=0;n<65536;n++){const bs=n<256?[n]:[n>>8,n&255];if(bs.every(b=>present.has(b)))cumulative++;assert.equal(rank(BigInt(n)),cumulative);}
  for(let k=1;k<=260;k++)assert.equal(rank(256n**BigInt(k)-1n),shorter[k+1]);
  const aliases=['',...'abcdefghi'];for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)aliases.push(String.fromCharCode(97+i,97+j));
  const expectedIds=[];for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const alias of aliases)expectedIds.push(['fixed',field,reverse,alias].join('/'));
  for(const alias of 'abcdefghi')for(const field of ['dbbi','faed'])for(const reverse of [false,true])expectedIds.push(['substituted',field,reverse,alias].join('/'));
  assert.deepEqual(saved.groups.map(g=>[g.family,g.field,g.reverse,g.alias].join('/')).sort(),expectedIds.sort());
  const expected=new Map();for(const c of saved.candidates){const key=[c.family,c.field,c.reverse,c.alias,c.mapping].join('/');if(!expected.has(key))expected.set(key,[]);expected.get(key).push(c.decimal);assert.equal(BigInt('0x'+c.hex).toString(),c.decimal);assert([...Buffer.from(c.hex,'hex')].every(b=>present.has(b)));}
  const result={complete:false,controls:{rankIntegers:65536,largeBoundaries:260},cases:0,nodes:0,hits:0,groups:[],verifierSHA256:sha(fs.readFileSync(__filename)),summarySHA256:sha(fs.readFileSync(path.join(out,'summary.json')))};
  for(const g of saved.groups){
    const source=g.reverse?[...input[g.field]].reverse().join(''):input[g.field],m=build(source,g.alias),started=Date.now();let cases=0,nodes=0,hits=0;
    function one(map){const r=verify(m,map),key=[g.family,g.field,g.reverse,g.alias,map.join('')].join('/');assert.deepEqual(r.hits.sort(),(expected.get(key)||[]).sort());cases++;nodes+=r.nodes;hits+=r.hits.length;}
    if(g.family==='fixed')one([1,2,3,4,5,6,7,8,9]);else permutations(one);
    assert.equal(cases,g.cases);assert.equal(nodes,g.nodes);assert.equal(hits,g.hits);
    const verified={...g,elapsedMs:Date.now()-started};result.groups.push(verified);result.cases+=cases;result.nodes+=nodes;result.hits+=hits;
    fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');if(g.family!=='fixed')console.log(JSON.stringify(verified));
  }
  assert.equal(result.cases,saved.cases);assert.equal(result.nodes,saved.nodes);assert.equal(result.hits,saved.hits);result.complete=true;
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({complete:true,cases:result.cases,nodes:result.nodes,hits:result.hits}));
}
if(require.main===module)main();module.exports={rank};
