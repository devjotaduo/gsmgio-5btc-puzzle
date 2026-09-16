/* Matrix lists as column ordering, followed by decimal -> ASCII bytes.
 * Ordinary incomplete columnar (both tie orders) and Myszkowski.
 * Every occurrence of ONE selected a..i symbol may independently be zero.
 * node solver/columnar_decimal_constraints.cjs
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {search,baseLists,open}=require('./decimal_keystream_constraints.cjs');
const {colorLists}=require('./decimal_carry_color.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','feedback_decimal_2026-09-15','columnar');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function route(length,key,kind,descending=false) {
  assert(length>0&&key.length>0&&key.every(Number.isSafeInteger));
  const cols=Array.from({length:key.length},(_,i)=>i).sort((a,b)=>((descending?-1:1)*(key[a]-key[b]))||(kind==='columnar-right'?b-a:a-b));
  const order=[];
  if(kind==='myszkowski') {
    let at=0;
    while(at<cols.length) {
      const group=[];do{group.push(cols[at++]);}while(at<cols.length&&key[cols[at]]===key[group[0]]);
      for(let row=0;row*key.length<length;row++)for(const col of group)if(row*key.length+col<length)order.push(row*key.length+col);
    }
  } else {
    assert(['columnar-left','columnar-right'].includes(kind));
    for(const col of cols)for(let i=col;i<length;i+=key.length)order.push(i);
  }
  assert.equal(order.length,length);assert.equal(new Set(order).size,length);return order;
}
function permutation(length,key,model) {
  let p=route(length,key,model.kind,model.descending);
  if(model.inverse){const inv=Array(length);p.forEach((v,i)=>{inv[v]=i;});p=inv;}
  if(model.reverseInput)p=p.map(v=>length-v-1);
  if(model.reverseOutput)p.reverse();return p;
}
function keys() {
  const lists=[...baseLists(),...colorLists().lists];
  for(const word of ['matrixsumlist','lastwordsbeforearchichoice','thispassword'])lists.push({name:`literal/${word}`,values:[...word].map(c=>c.charCodeAt(0)-96),reason:'Decoded instruction next to the unknown fields, used as a literal trial transposition key.'});
  const result=new Map();
  for(const list of lists)for(const representation of ['integers','decimal-digits'])for(const reverse of [false,true]) {
    const v=representation==='integers'?list.values.slice():[...list.values.join('')].map(Number);if(reverse)v.reverse();
    const id=v.join(',');if(!result.has(id))result.set(id,{id,values:v,provenance:[]});result.get(id).provenance.push({list:list.name,representation,reverse});
  }
  return {lists,keys:[...result.values()]};
}
function domains(s,alias) {return [...s].map(c=>c===alias?[0,c.charCodeAt(0)-96]:[c.charCodeAt(0)-96]);}
function controls() {
  const plain='UNFILLEDBLOCK',key=[3,1,2];assert.equal(route(plain.length,key,'columnar-left').map(i=>plain[i]).join(''),'NLDOFLBCUIELK');
  const p='Incomplete columnar with pattern word key and letters under same number taken off by row from top to bottom'.replace(/\W/g,'').toUpperCase();
  const c='NOPEE OUNRI HATRW RKYNL TESNE SMNME TKNFB RWRMO TBTOI LLWTO ATDER OOTOC MTCMA TPEND EDERU RAUBA EFYFO POTM'.replace(/ /g,'');
  assert.equal(route(p.length,[2,1,3,1,3,1],'myszkowski').map(i=>p[i]).join(''),c);
  let inversions=0,planted=0;
  for(const k of [[3,1,2],[2,1,3,1,3,1],[6,10,8,7,6,6,5,4,9,9,7,8,7,9]])for(const kind of ['columnar-left','columnar-right','myszkowski'])for(const descending of [false,true]) {
    for(const n of [1,13,91,570]) {
      const r=route(n,k,kind,descending),inv=permutation(n,k,{kind,descending,inverse:true,reverseInput:false,reverseOutput:false});
      assert.deepEqual(inv.map(i=>r[i]),Array.from({length:n},(_,i)=>i));inversions++;
    }
    for(const alias of ['b','g','i']) {
      const text='matrixsumlistthispassword',digits=BigInt('0x'+Buffer.from(text).toString('hex')).toString();
      const letters=[...digits].map(d=>d==='0'?alias:String.fromCharCode(96+Number(d))).join('');
      const r=route(letters.length,k,kind,descending),cipher=r.map(i=>letters[i]).join('');
      const inv=permutation(letters.length,k,{kind,descending,inverse:true,reverseInput:false,reverseOutput:false}),back=inv.map(i=>cipher[i]).join('');assert.equal(back,letters);
      const result=search(domains(back,alias),{maxMs:5000});assert(result.complete);assert(result.hits.some(h=>h.hex===Buffer.from(text).toString('hex')));planted++;
    }
  }
  return {acaColumnar:true,acaMyszkowski:true,inversions,planted};
}
function candidatesAES(candidates) {
  const passwords=new Map(),padding=[];
  for(const c of candidates)for(const form of ['direct','sha256-hex']) {
    const body=Buffer.from(c.hex,'hex'),pw=form==='direct'?body:Buffer.from(sha(body)),passwordHex=pw.toString('hex');
    if(!passwords.has(passwordHex))passwords.set(passwordHex,{passwordHex,form,preimageHex:c.hex});
  }
  let attempts=0;
  for(const p of passwords.values())for(const [name,blob] of Object.entries(input.blobs))for(const digest of ['sha256','md5']) {
    attempts++;const body=open(Buffer.from(p.passwordHex,'hex'),blob,digest);
    if(body)padding.push({passwordHex:p.passwordHex,blob:name,digest,plaintextHex:body.toString('hex'),printable:[...body].filter(v=>v>=32&&v<=126||[9,10,13].includes(v)).length/body.length});
  }
  return {passwords:[...passwords.values()],attempts,padding};
}
function main() {
  const checked=controls(),{lists,keys:allKeys}=keys(),limits={maxNodes:200000,maxMs:1000};
  console.log(JSON.stringify({controls:checked}));fs.mkdirSync(out,{recursive:true});
  const spec={hypothesis:'Use matrix sum/index lists or adjacent decoded labels as a transposition key; undo/apply one columnar or Myszkowski permutation, then a=1..i=9 with any ONE alias also independently zero; whole decimal integer -> minimum big-endian bytes <128.',
    caveat:'No evidence selects these ciphers. Fixed declared keys only, not all column permutations, not double transposition. Input and output reversals are separate. No padding inserted or discarded.',
    lists,keys:allKeys,limits,controls:checked,sourceSHA256:sha(fs.readFileSync(__filename)),inputSHA256:sha(inputBytes),
    sourceURLs:['https://www.cryptogram.org/downloads/aca.info/ciphers/IncompleteColTransposition.pdf','https://www.cryptogram.org/downloads/aca.info/ciphers/Myszkowski.pdf']};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');
  const logfile=path.join(out,'cases.jsonl'),modelsfile=path.join(out,'models.jsonl');fs.writeFileSync(logfile,'');fs.writeFileSync(modelsfile,'');
  let cases=0,nodes=0,certificates=0;const candidates=[],partial=[],permutations={};
  for(const field of ['dbbi','faed']) {
    const n=input[field].length,seen=new Set();let modelId=0,proposed=0;
    for(const k of allKeys)for(const kind of ['columnar-left','columnar-right','myszkowski'])for(const descending of [false,true])for(const inverse of [false,true])for(const reverseInput of [false,true])for(const reverseOutput of [false,true]) {
      proposed++;const model={key:k.id,kind,descending,inverse,reverseInput,reverseOutput},perm=permutation(n,k.values,model),signature=perm.join(',');
      if(seen.has(signature))continue;seen.add(signature);const id=`${field}-${modelId++}`;
      fs.appendFileSync(modelsfile,JSON.stringify({id,field,model,permutationSHA256:sha(signature)})+'\n');
      const source=perm.map(i=>input[field][i]).join('');
      for(const alias of 'abcdefghi') {
        const r=search(domains(source,alias),limits);cases++;nodes+=r.nodes;certificates+=r.certificates.length;
        fs.appendFileSync(logfile,JSON.stringify({modelId:id,alias,...r})+'\n');
        if(!r.complete)partial.push({modelId:id,alias,nodes:r.nodes});
        for(const h of r.hits)candidates.push({modelId:id,alias,...h});
      }
    }
    permutations[field]={proposed,unique:seen.size};console.log(JSON.stringify({field,permutations:permutations[field],cases,nodes,candidates:candidates.length,partial:partial.length}));
  }
  const aes=candidatesAES(candidates);fs.writeFileSync(path.join(out,'candidates.json'),JSON.stringify(candidates,null,2)+'\n');fs.writeFileSync(path.join(out,'aes.json'),JSON.stringify(aes,null,2)+'\n');
  const summary={lists:lists.length,keys:allKeys.length,permutations,cases,complete:cases-partial.length,nodes,certificates,candidates:candidates.length,partial,passwords:aes.passwords.length,aesAttempts:aes.attempts,padding:aes.padding.length,controls:checked};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={route,permutation,keys,controls};
