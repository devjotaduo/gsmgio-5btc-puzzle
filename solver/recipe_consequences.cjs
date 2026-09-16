/* Three finite consequences of X's recipe, declared before testing AES.
 * node solver/recipe_consequences.cjs --prepare
 * node solver/recipe_consequences.cjs --test
 * No external calls. Only original puzzle ciphertexts are used.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','recipe_audit_2026-09-11');
const read=f=>JSON.parse(fs.readFileSync(path.join(out,f),'utf8'));
const save=(f,x)=>fs.writeFileSync(path.join(out,f),JSON.stringify(x,null,2)+'\n');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json'));
const input=JSON.parse(inputBytes),baseline=read('baseline.json'),params=read('parameters.json');
const sha=x=>crypto.createHash('sha256').update(x).digest();
const mode=process.argv[2];assert(['--prepare','--test'].includes(mode),'Choose --prepare or --test');
function prepare() {
  const selected=new Set(params.blueRows),columns=params.yellowColumns,values=new Set(params.primeBlueValues);
  assert.deepEqual(columns,[2,6,13,14]);assert.deepEqual([...values],[1,2,4,8]);
  const rows=Array.from({length:38},(_,r)=>{
    const zeroed=columns.map((c,i)=>({column:c,value:input.faed.charCodeAt(r*15+c-1)-96,bit:8>>i})).filter(x=>selected.has(r+1)&&values.has(x.value));
    return {row:r+1,selected:selected.has(r+1),zeroed,
      valueNibble:zeroed.reduce((n,x)=>n|x.value,0),columnNibble:zeroed.reduce((n,x)=>n|x.bit,0)};
  });
  const models=[
    {id:'H1',formula:'For each FAED row, bitwise OR of values erased by the original blue rule. Values are exactly powers 1,2,4,8. Encode as a hex digit.',prediction:'Every digit is 0..f without modulus or fitted alphabet.',limitations:'Uses the original, unconfirmed mask. OR is inferred from set hex. Non-selected positions intentionally omitted by the mask.'},
    {id:'H2',formula:'In each FAED row, set bit 8,4,2,1 when original blue rule erases the respective ascending column 2,6,13,14.',prediction:'Four spatial slots produce one hex digit without a token substitution.',limitations:'The columns and erasure rule come from X. Reading four slots as bits is an inferred operation; no permutations searched.'},
    {id:'H3',formula:'Apply both published zeroing operations together: blue-filtered FAED row sum XOR yellow-filtered DBBI node sum. Preserve raw bytes and the original mod26 letter form.',prediction:'The unreported fourth state equals rawBase XOR rawBlue XOR rawYellow for every row.',limitations:'This algebraic identity is conditional on X, not independent evidence of a message. The fourth letter string was inspected during the audit, before AES tests.'},
  ];
  const materials=[];
  const add=(model,label,bytes)=>materials.push({model,label,hex:bytes.toString('hex')});
  for (const [model,field] of [['H1','valueNibble'],['H2','columnNibble']]) for(const selectOnly of [false,true]) {
    const list=(selectOnly?rows.filter(x=>x.selected):rows).map(x=>x[field]);
    const hex=list.map(n=>n.toString(16)).join('');assert.equal(hex.length%2,0);
    const scope=selectOnly?'selected14':'full38';
    add(model,`${model}/${scope}/hex-text`,Buffer.from(hex));
    add(model,`${model}/${scope}/hex-decoded-bytes`,Buffer.from(hex,'hex'));
  }
  const fourth=baseline.blue.sums.map((r,i)=>r^baseline.yellow.key[i%14]);
  fourth.forEach((n,i)=>assert.equal(n,baseline.base.raw[i]^baseline.blue.raw[i]^baseline.yellow.raw[i]));
  const fourthText=String.fromCharCode(...fourth.map(n=>n%26+97));
  add('H3','H3/raw-bytes',Buffer.from(fourth));
  add('H3','H3/hex-text',Buffer.from(Buffer.from(fourth).toString('hex')));
  add('H3','H3/mod26-lowercase',Buffer.from(fourthText));
  const phaseText=input.phase32_text.replace(/[^A-Za-z]/g,'').toLowerCase();
  const start=phaseText.indexOf('reinsertingtheprimebasics'),end=phaseText.indexOf('select',start);
  assert(start>=0&&end>start);
  const words=[
    {id:'puzzle_before_SELECT',text:phaseText.slice(start,end),status:'Preferred local reading; word boundaries in the README are editorial. Starts at the semantically parallel reinserting clause, ends immediately before SELECT.',source:'Original phase 3.2 letters, independently checked in prior session'},
    {id:'draft_before_Neo_moves_to_door',text:'sheisgoingtodieandthereisnothingyoucandotostopit',status:'Alternative: final clause of the Architect speech before the stage direction where Neo goes to the left door. Not proven to be what the puzzle means.',source:'2001-10-27 screenplay, printed p.122A, PDF page130; action on printed p.123/PDF131'},
  ];
  assert.equal(words[0].text,'reinsertingtheprimebasicsafterwhichyouwillberequiredto');
  const key=baseline.base.key;
  const lists=[{id:'graph-node-sums/connected-decimal',text:key.join('')},{id:'graph-node-sums/comma-decimal',text:key.join(',')}];
  const passwords=new Map();
  function password(model,label,preimage) {
    const passwordHex=Buffer.from(sha(preimage).toString('hex')).toString('hex');
    const record={model,label,preimageHex:preimage.toString('hex'),passwordHex};
    if(passwords.has(passwordHex)) passwords.get(passwordHex).aliases.push({model,label});
    else passwords.set(passwordHex,{...record,aliases:[]});
  }
  for(const m of materials) {
    const bytes=Buffer.from(m.hex,'hex');
    password(m.model,`${m.label}/alone`,bytes);
    for(const list of lists) for(const last of words) password(m.model,`${m.label}+${list.id}+${last.id}`,
      Buffer.concat([bytes,Buffer.from(list.text),Buffer.from(last.text)]));
  }
  const records=[...passwords.values()];
  save('consequence_spec.json',{models,sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex'),inputsSHA256:sha(inputBytes).toString('hex'),
    passwordFormula:'SHA256(material), or SHA256(material + DBBI graph matrixsumlist + lastwords); lowercase hex digest used as password.',
    status:'All three models and both text extractions are conditional hypotheses, not confirmed operations.',
    serializations:'For hex models: text or its decoded bytes; all38 rows or all14 selected rows. H3 raw bytes, hex text, mod26 lowercase.',
    order:'material, matrixsumlist, lastwords, following the textual roadmap. No other permutations, suffix lengths, alphabets or case variants.',
    acceptance:'Verifiable complete plaintext/next-stage consequence or exact target public key (including its negation). Padding, ASCII and file magic alone are not authentication.',
    canonicalMaterials:materials,words,lists,passwords:records.length});
  save('nibble_rows.json',rows);save('fourth_rail.json',{raw:fourth,text:fourthText});
  fs.writeFileSync(path.join(out,'consequence_passwords.jsonl'),records.map(x=>JSON.stringify(x)).join('\n')+'\n');
  console.log(JSON.stringify({prepared:true,models:models.length,materials:materials.length,passwords:records.length,fourthRail:fourthText},null,2));
}
function evp(password,salt,hash) {
  let previous=Buffer.alloc(0),material=Buffer.alloc(0);
  while(material.length<48) {previous=crypto.createHash(hash).update(Buffer.concat([previous,password,salt])).digest();material=Buffer.concat([material,previous]);}
  return [material.subarray(0,32),material.subarray(32,48)];
}
function decrypt(password,blob,hash) {
  const [key,iv]=evp(password,Buffer.from(blob.salt,'hex'),hash),dec=crypto.createDecipheriv('aes-256-cbc',key,iv);
  try {return Buffer.concat([dec.update(Buffer.from(blob.ciphertext,'hex')),dec.final()]);}
  catch(error) {if(error.code==='ERR_OSSL_BAD_DECRYPT') return null;throw error;}
}
function test() {
  const spec=read('consequence_spec.json');assert.equal(spec.sourceSHA256,sha(fs.readFileSync(__filename)).toString('hex'));
  assert.equal(spec.inputsSHA256,sha(inputBytes).toString('hex'));
  const passwords=fs.readFileSync(path.join(out,'consequence_passwords.jsonl'),'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.equal(passwords.length,spec.passwords);
  const known=Buffer.from(input.phase32_control_b64,'base64');
  const knownBlob={salt:known.subarray(8,16).toString('hex'),ciphertext:known.subarray(16).toString('hex')};
  assert(decrypt(Buffer.from(input.phase32_control_password),knownBlob,'sha256').toString().startsWith("I've been waiting for you."));
  assert.equal(decrypt(Buffer.from(input.phase32_control_password),knownBlob,'md5'),null);
  const results=[],keyHits=[],seenKeys=new Set();
  function checkKey(key,label) {
    if(key.length!==32||seenKeys.has(key.toString('hex')))return;
    seenKeys.add(key.toString('hex'));const ec=crypto.createECDH('secp256k1');
    try {ec.setPrivateKey(key);} catch{return;}
    const pub=ec.getPublicKey('hex','uncompressed');
    if(pub.slice(2,66)===input.target_pubkey.slice(2,66))keyHits.push({label,key:key.toString('hex'),exact:pub===input.target_pubkey});
  }
  function checkBytes(bytes,label) {
    checkKey(sha(bytes),`SHA256(${label})`);
    for(let i=0;i+32<=bytes.length;i++) {const part=bytes.subarray(i,i+32);checkKey(part,`${label}/${i}/BE`);checkKey(Buffer.from(part).reverse(),`${label}/${i}/LE`);}
    const text=bytes.toString('latin1');for(const m of text.matchAll(/(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g))checkKey(Buffer.from(m[0],'hex'),`${label}/hex64`);
  }
  for(const row of passwords) {
    const preimage=Buffer.from(row.preimageHex,'hex'),password=Buffer.from(row.passwordHex,'hex');
    assert.equal(password.toString(),sha(preimage).toString('hex'));
    checkBytes(preimage,row.label);checkBytes(password,row.label+'/password');
    for(const [blobName,blob] of Object.entries(input.blobs))for(const hash of ['sha256','md5']) {
      const plain=decrypt(password,blob,hash);
      const result={label:row.label,model:row.model,passwordHex:row.passwordHex,blob:blobName,kdf:hash,plaintextHex:plain?.toString('hex')??null};
      if(plain) {result.asciiRatio=[...plain].filter(b=>b===9||b===10||b===13||b>=32&&b<=126).length/plain.length;checkBytes(plain,`${row.label}/${blobName}/${hash}`);}
      results.push(result);
    }
  }
  fs.writeFileSync(path.join(out,'consequence_aes.jsonl'),results.map(x=>JSON.stringify(x)).join('\n')+'\n');
  const padding=results.filter(x=>x.plaintextHex!==null);
  const summary={passwords:passwords.length,attempts:results.length,padding:padding.length,
    maxPlaintextASCII:padding.length?Math.max(...padding.map(x=>x.asciiRatio)):null,
    perModel:Object.fromEntries(['H1','H2','H3'].map(model=>[model,{passwords:passwords.filter(x=>x.model===model).length,attempts:results.filter(x=>x.model===model).length,padding:padding.filter(x=>x.model===model).length}])),
    distinctScalarChecks:seenKeys.size,keyHits,sourceSHA256:sha(fs.readFileSync(__filename)).toString('hex')};
  save('consequence_summary.json',summary);console.log(JSON.stringify(summary,null,2));
}
if(mode==='--prepare')prepare();else test();
