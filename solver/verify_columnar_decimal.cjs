/* Independent columnar model reconstruction and exact interval counting.
 * No solver/cipher helper imports. Sorts all grid positions by tuples rather
 * than reading columns. Verifies the entire declared permutation collection.
 * node solver/verify_columnar_decimal.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','feedback_decimal_2026-09-15','columnar');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(sha(inputBytes),spec.inputSHA256);assert.equal(sha(fs.readFileSync(path.join(root,'solver','columnar_decimal_constraints.cjs'))),spec.sourceSHA256);
const lists=new Map(spec.lists.map(l=>[l.name,l.values])),keys=new Map(),provenances=new Set();
const earlier=JSON.parse(fs.readFileSync(path.join(root,'_work','decimal_keystream_2026-09-15','carry_color','spec.json')));
assert.deepEqual(spec.lists.slice(0,43),earlier.lists);
for(const word of ['matrixsumlist','lastwordsbeforearchichoice','thispassword'])assert.deepEqual(lists.get(`literal/${word}`),[...word].map(c=>c.charCodeAt(0)-96));
for(const k of spec.keys) {
  assert(!keys.has(k.id));assert.equal(k.id,k.values.join(','));keys.set(k.id,k.values);
  for(const p of k.provenance) {
    const id=JSON.stringify(p);assert(!provenances.has(id));provenances.add(id);
    assert(lists.has(p.list)&&['integers','decimal-digits'].includes(p.representation)&&typeof p.reverse==='boolean');
    const a=p.representation==='integers'?lists.get(p.list).slice():[...lists.get(p.list).join('')].map(Number);
    if(p.reverse)a.reverse();assert.deepEqual(a,k.values);
  }
}
assert.equal(provenances.size,46*4);
function permutation(n,key,m) {
  const tuples=Array.from({length:n},(_,i)=>{
    const col=i%key.length,row=Math.floor(i/key.length),rank=(m.descending?-1:1)*key[col];
    return {i,tuple:m.kind==='myszkowski'?[rank,row,col]:[rank,m.kind==='columnar-right'?-col:col,row]};
  });
  tuples.sort((a,b)=>{for(let j=0;j<3;j++){if(a.tuple[j]<b.tuple[j])return -1;if(a.tuple[j]>b.tuple[j])return 1;}return 0;});
  const r=tuples.map(x=>x.i),p=Array(n);
  for(let i=0;i<n;i++) {
    const before=m.inverse?r[i]:i,after=m.inverse?i:r[i];
    p[m.reverseOutput?n-before-1:before]=m.reverseInput?n-after-1:after;
  }
  assert.equal(new Set(p).size,n);return p;
}
const simple={kind:'columnar-left',descending:false,inverse:false,reverseInput:false,reverseOutput:false};
assert.equal(permutation('UNFILLEDBLOCK'.length,[3,1,2],simple).map(i=>'UNFILLEDBLOCK'[i]).join(''),'NLDOFLBCUIELK');
const mysz={...simple,kind:'myszkowski'},plain='Incomplete columnar with pattern word key and letters under same number taken off by row from top to bottom'.replace(/\W/g,'').toUpperCase();
assert.equal(permutation(plain.length,[2,1,3,1,3,1],mysz).map(i=>plain[i]).join(''),'NOPEE OUNRI HATRW RKYNL TESNE SMNME TKNFB RWRMO TBTOI LLWTO ATDER OOTOC MTCMA TPEND EDERU RAUBA EFYFO POTM'.replace(/ /g,''));
const modelsBytes=fs.readFileSync(path.join(out,'models.jsonl')),models=modelsBytes.toString('utf8').trim().split('\n').map(JSON.parse),byId=new Map(),inventory={};
for(const field of ['dbbi','faed']) {
  const n=input[field].length,expected=new Set();let proposed=0;
  for(const key of keys.values())for(const kind of ['columnar-left','columnar-right','myszkowski'])for(const descending of [false,true])for(const inverse of [false,true])for(const reverseInput of [false,true])for(const reverseOutput of [false,true]) {
    const p=permutation(n,key,{kind,descending,inverse,reverseInput,reverseOutput});expected.add(p.join(','));proposed++;
  }
  const observed=new Set();
  for(const r of models.filter(r=>r.field===field)) {
    assert(!byId.has(r.id));const m=r.model;assert(keys.has(m.key));
    assert(['columnar-left','columnar-right','myszkowski'].includes(m.kind));for(const b of ['descending','inverse','reverseInput','reverseOutput'])assert.equal(typeof m[b],'boolean');
    const p=permutation(n,keys.get(m.key),m),signature=p.join(',');assert.equal(sha(signature),r.permutationSHA256);
    assert(expected.has(signature)&&!observed.has(signature));observed.add(signature);
    byId.set(r.id,{...r,source:p.map(i=>input[field][i]).join('')});
  }
  assert.equal(observed.size,expected.size);assert.equal(observed.size,saved.permutations[field].unique);assert.equal(proposed,saved.permutations[field].proposed);
  inventory[field]={proposed,unique:observed.size};console.log(JSON.stringify({inventory:field,...inventory[field]}));
}
const ten=[1n],p128=[1n];for(let i=1;i<=600;i++){ten.push(ten[i-1]*10n);p128.push(p128[i-1]*128n);}
function count(n) {
  if(n<0n)return 0n;let h=n.toString(16);if(h.length%2)h='0'+h;
  const b=Buffer.from(h,'hex');let total=0n;
  for(let i=0;i<b.length;i++){total+=BigInt(Math.min(b[i],128))*p128[b.length-i-1];if(b[i]>=128)return total;}
  return total+1n;
}
let total=0n;for(let n=0;n<65536;n++){if((n&255)<128&&(n>>8)<128)total++;assert.equal(count(BigInt(n)),total);}
for(let i=1;i<=300;i++)assert.equal(count(256n**BigInt(i)-1n),128n**BigInt(i));
const caseBytes=fs.readFileSync(path.join(out,'cases.jsonl')),records=caseBytes.toString('utf8').trim().split('\n').map(JSON.parse),ids=new Set();
let certificates=0,nodes=0;
for(const r of records) {
  assert(byId.has(r.modelId));assert.match(r.alias,/^[a-i]$/);assert(r.complete&&r.pending.length===0&&r.hits.length===0);
  const id=`${r.modelId}/${r.alias}`;assert(!ids.has(id));ids.add(id);
  const s=byId.get(r.modelId).source,n=s.length,low=BigInt([...s].map(c=>c===r.alias?0:c.charCodeAt(0)-96).join(''));
  const weights=[...s].flatMap((c,i)=>c===r.alias?[BigInt(c.charCodeAt(0)-96)*ten[n-i-1]]:[]),tails=Array(weights.length+1).fill(0n);
  for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];assert.equal(r.ambiguous,weights.length);
  const masks=r.certificates.slice().sort();let coverage=0n;
  for(let j=0;j<masks.length;j++) {
    const m=masks[j];assert.match(m,/^[01]*$/);assert(m.length<=weights.length);if(j)assert(!m.startsWith(masks[j-1]));
    let lo=low;for(let i=0;i<m.length;i++)if(m[i]==='1')lo+=weights[i];const hi=lo+tails[m.length];
    assert.equal(count(hi)-count(lo-1n),0n,`${id}/${m}`);coverage+=1n<<BigInt(weights.length-m.length);certificates++;
  }
  assert.equal(coverage,1n<<BigInt(weights.length));nodes+=r.nodes;
}
assert.equal(ids.size,byId.size*9);assert.equal(ids.size,saved.cases);assert.equal(nodes,saved.nodes);assert.equal(certificates,saved.certificates);
assert.equal(saved.partial.length,0);assert.equal(saved.candidates,0);assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))),[]);
assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out,'aes.json'))),{passwords:[],attempts:0,padding:[]});
const result={cases:ids.size,certificates,nodes,allExcluded:true,allExpectedModelsPresent:true,inventory,
  controls:{integerCounts:65536,largeWidths:300,acaColumnar:true,acaMyszkowski:true},
  caveat:'Independent permutation generation and interval counting; the 43 numeric list definitions are cross-checked with the previous serialized experiment, not independently justified as the intended keys.',
  modelsSHA256:sha(modelsBytes),casesSHA256:sha(caseBytes),verifierSHA256:sha(fs.readFileSync(__filename))};
fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
