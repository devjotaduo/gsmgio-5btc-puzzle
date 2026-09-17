'use strict';
// New inputs: Telegram 2026-09-17, Doober's Atlas pp. 36-39, message #71413.
// The community's interpretations are hypotheses. Padding is never authentication.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {open} = require('./decimal_keystream_constraints.cjs');
const {solve} = require('./zero_decimal_constraints.cjs');
const root = path.resolve(__dirname, '..');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const prime = n => { if (n < 2) return false; for (let k=2;k*k<=n;k++) if(n%k===0)return false; return true; };
const bytesOf = n => {let h=n.toString(16);return Buffer.from(h.padStart(Math.ceil(h.length/2)*2,'0'),'hex');};

function parseHosts(source) {
  const results=[];
  function visit(offset,rank,tokens) {
    if(offset===source.length){results.push(tokens);return;}
    if(prime(rank)) {
      if(source[offset]!=='b')return;
      visit(offset+1,rank+1,[...tokens,{rank,offset,text:'b',prime:true}]);
      if(source[offset+1]==='e')visit(offset+2,rank+1,[...tokens,{rank,offset,text:'be',prime:true}]);
    } else visit(offset+1,rank+1,[...tokens,{rank,offset,text:source[offset],prime:false}]);
  }
  visit(0,1,[]);return results;
}

// Independent dynamic programming counts, without producing a parse tree.
function countParses(source) {
  const q=new Map([['0,1',1]]),lengths={};
  for(let offset=0;offset<=source.length;offset++)for(let rank=1;rank<=source.length+1;rank++) {
    const n=q.get(`${offset},${rank}`)||0;if(!n)continue;
    if(offset===source.length){lengths[rank-1]=(lengths[rank-1]||0)+n;continue;}
    const lengthsAllowed=!prime(rank)?[1]:source[offset]!=='b'?[]:source[offset+1]==='e'?[1,2]:[1];
    for(const l of lengthsAllowed){const key=`${offset+l},${rank+1}`;q.set(key,(q.get(key)||0)+n);}
  }
  return lengths;
}

function run() {
  const out=path.resolve(process.argv[2]||path.join(root,'_work/prime_host_delta_2026-09-17'));
  assert(!fs.existsSync(out),'Choose a new output directory; previous evidence is preserved.');
  fs.mkdirSync(out,{recursive:true});
  const save=(name,x)=>fs.writeFileSync(path.join(out,name),JSON.stringify(x,null,2)+'\n',{flag:'wx'});
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(raw);
  const readme=fs.readFileSync(path.join(root,'README.md'),'utf8');
  const source=readme.split(/\r?\n/).find(l=>l.startsWith('> d b b i')).slice(2).replace(/[ *]/g,'');
  assert.equal(source.slice(0,91),data.dbbi);assert.equal(source.slice(195,765),data.faed);
  const ab=source.slice(91,195);
  assert.equal(Buffer.from(ab.replaceAll('a','0').replaceAll('b','1').match(/.{8}/g).map(s=>parseInt(s,2))).toString(),'matrixsumlist');
  const parses=parseHosts(data.dbbi).map(tokens=>({length:tokens.length,tokens,
    colors:tokens.filter(t=>t.prime).map(t=>t.text==='b'?'B':'Y').join(''),
    residual:tokens.filter(t=>!t.prime).map(t=>t.text).join('')})).sort((a,b)=>a.length-b.length);
  assert.deepEqual(parses.map(p=>p.length),[83,84]);assert.deepEqual(countParses(data.dbbi),{83:1,84:1});
  for(const p of parses)assert.equal(p.tokens.map(t=>t.text).join(''),data.dbbi);
  const events=[...data.colored.map(([index,color,row,col])=>({index,color,row,col,byte:Math.floor(index/8)+1})),
    {index:163,color:'F',row:7,col:4,byte:21}].sort((a,b)=>a.index-b.index);
  assert.deepEqual(data.spiral[163],[7,4]);
  const witnesses=[];
  for(const includeFE of [false,true])for(const fColor of includeFE?['B','Y']:['excluded']) {
    const es=events.filter(e=>includeFE||e.color!=='F');
    for(let a=0;a<es.length;a++)for(let b=includeFE?a+1:es.length;b<=(includeFE?es.length-1:es.length);b++) {
      const kept=es.filter((_,i)=>i!==a&&i!==b),cs=kept.map(e=>e.color==='F'?fColor:e.color).join('');
      for(const p of parses)if(cs===p.colors)witnesses.push({length:p.length,includeFE,fColor,
        omitted:es.filter((_,i)=>i===a||i===b).map(e=>events.indexOf(e)+1),
        kept,distinctBytes:new Set(kept.map(e=>e.byte)).size});
    }
  }
  assert.deepEqual(witnesses.map(w=>[w.length,w.omitted]).sort(),[
    [83,[22,24]],[83,[23,24]],[83,[24,25]],[84,[22,25]],[84,[23,25]]].sort());
  // The Atlas' preferred witness is unique only after requiring bytes 1..23.
  // A different L=83 witness also has 23 distinct bytes (1..22 plus 24).
  assert.equal(witnesses.filter(w=>w.distinctBytes===23).length,2);
  assert.equal(witnesses.filter(w=>w.distinctBytes===23&&w.kept.every(e=>e.byte<=23)).length,1);
  const controls={parseRoundtrips:2,independentParseCounts:countParses(data.dbbi),syntheticParses:0};
  let rng=0x5b7c1;const random=()=>{rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return(rng>>>0)/4294967296;};
  for(let length=10;length<=90;length+=10) {
    const expected=Array.from({length},(_,i)=>prime(i+1)?(random()<0.5?'b':'be'):'acdfghi'[Math.floor(random()*7)]);
    const coded=expected.join(''),found=parseHosts(coded);
    assert(found.some(t=>t.map(x=>x.text).join('|')===expected.join('|')));
    const counts={};for(const t of found)counts[t.length]=(counts[t.length]||0)+1;
    assert.deepEqual(countParses(coded),counts);controls.syntheticParses++;
  }
  let randomAccepted=0;const randomSamples=20000;
  for(let trial=0;trial<randomSamples;trial++) {
    const s=[...data.dbbi];for(let k=s.length-1;k>0;k--){const j=Math.floor(random()*(k+1));[s[k],s[j]]=[s[j],s[k]];}
    if(parseHosts(s.join('')).length)randomAccepted++;
  }
  const materials=new Map(),objects=[],integerChecks=[];
  function add(b,provenance) {
    b=Buffer.isBuffer(b)?b:Buffer.from(String(b));if(!b.length)return;
    const hex=b.toString('hex');if(!materials.has(hex))materials.set(hex,{id:materials.size,hex,provenance});
  }
  function forms(s,label) {
    add(s,label+'/literal');add(s.toUpperCase(),label+'/upper');
    if(/^[a-io]+$/.test(s)){
      const digits=[...s].map(c=>c==='o'?0:c.charCodeAt(0)-96).join('');
      add(digits,label+'/decimal');add(bytesOf(BigInt(digits)),label+'/integer-bytes');
    }
  }
  function list(values,label) {
    for(const reversed of [false,true]){
      const vs=reversed?[...values].reverse():values,p=label+(reversed?'/reversed':'');
      for(const sep of ['',' ', ',', '\n'])add(vs.join(sep),p+'/separator-'+JSON.stringify(sep));
      add(JSON.stringify(vs),p+'/json');if(vs.every(v=>v>=0&&v<=255))add(Buffer.from(vs),p+'/bytes');
    }
  }
  function gridSums(values,rows,label) {
    assert.equal(values.length%rows,0);const cols=values.length/rows;
    const rs=Array.from({length:rows},(_,r)=>values.slice(r*cols,(r+1)*cols).reduce((a,b)=>a+b,0));
    const cs=Array.from({length:cols},(_,c)=>Array.from({length:rows},(_,r)=>values[r*cols+c]).reduce((a,b)=>a+b,0));
    list(rs,label+'/rows');list(cs,label+'/columns');list([...rs,...cs],label+'/rows-columns');
  }
  for(const p of parses) {
    const views={residual:p.residual,logical:p.tokens.map(t=>t.text[0]).join(''),
      logicalPrimeZero:p.tokens.map(t=>t.prime?'o':t.text).join(''),
      logicalNonprimeZero:p.tokens.map(t=>t.prime?t.text[0]:'o').join(''),
      physicalPrimeZero:p.tokens.map(t=>t.prime?'o'.repeat(t.text.length):t.text).join(''),
      physicalSuffixZero:p.tokens.map(t=>t.text==='be'?'bo':t.text).join('')};
    for(const [view,s]of Object.entries(views)){
      const label=`hosts${p.length}/${view}`;objects.push({label,s});
      for(const reverse of [false,true]) {
        const text=reverse?[...s].reverse().join(''):s,tag=label+(reverse?'/reverse':'');forms(text,tag);
        const pattern=[...text].map(c=>c==='g'?'?':c==='o'?'0':String(c.charCodeAt(0)-96)).join('');
        const constrained=solve(pattern,2000000,true);assert(constrained.complete);
        integerChecks.push({label:tag,...constrained});
        for(const hit of constrained.hits)forms(hit,tag+'/seven-bit-candidate');
      }
      // Matrices of logical positions or residual digits, NOT the old 91-symbol rectangle.
      if(['residual','logical','logicalPrimeZero'].includes(view))for(const g of [0,7]) {
        const values=[...s].map(c=>c==='o'?0:c==='g'?g:c.charCodeAt(0)-96);
        for(let rows=2;rows<values.length;rows++)if(values.length%rows===0)gridSums(values,rows,label+`/g${g}/${rows}rows`);
      }
    }
    list(p.tokens.filter(t=>t.prime).map(t=>t.rank),`hosts${p.length}/logical-ranks`);
    list(p.tokens.filter(t=>t.prime).map(t=>t.offset),`hosts${p.length}/physical-offsets`);
    list(p.tokens.filter(t=>t.prime).map(t=>t.text==='b'?1:0),`hosts${p.length}/colour-bits`);
  }
  // Coordinates distinguish the new witnesses although some have identical colour strings.
  for(const w of witnesses) {
    const label=`witness${w.length}/omit${w.omitted.join('-')}`;
    for(const origin of [0,1]){
      list(w.kept.map(e=>e.index+origin),label+`/spiral${origin}`);
      list(w.kept.flatMap(e=>[e.row+origin,e.col+origin]),label+`/coordinates${origin}`);
      list(w.kept.map(e=>(e.row+origin)+(e.col+origin)),label+`/coordinate-sums${origin}`);
      list(w.kept.map(e=>e.row*14+e.col+origin),label+`/row-major${origin}`);
    }
    list(w.kept.map(e=>e.byte),label+'/bytes');
    const matrix=Array(196).fill(0),hosts=parses.find(p=>p.length===w.length).tokens.filter(t=>t.prime);
    w.kept.forEach((e,i)=>{matrix[e.row*14+e.col]=hosts[i].rank;});gridSums(matrix,14,label+'/prime-reinsertion');
    forms(w.kept.map(e=>'gsmg.io/theseedisplanted'[e.byte-1]).join(''),label+'/represented-characters');
  }
  // #71413 observes 91+104=195. A literal matrix reading retains the binary label.
  // This is exploratory: prepend/append one zero, then place in each of three observed orders.
  const full=data.dbbi+ab;
  assert.equal(full.length,195);
  const routes={rows:Array.from({length:196},(_,i)=>[Math.floor(i/14),i%14]),
    columns:Array.from({length:196},(_,i)=>[i%14,Math.floor(i/14)]),spiral:data.spiral};
  const colour=new Map(data.colored.map(([,color,r,c])=>[r*14+c,color]));
  for(const padding of ['before','after'])for(const [route,cells]of Object.entries(routes)) {
    const text=padding==='before'?'o'+full:full+'o',grid=Array(196);
    cells.forEach(([r,c],i)=>{grid[r*14+c]=text[i];});const label=`full195/${padding}/${route}`;
    for(const selector of ['zero','one','B','Y','colour']) {
      const values=grid.filter((_,i)=>selector==='zero'?data.matrix[Math.floor(i/14)][i%14]===0:
        selector==='one'?data.matrix[Math.floor(i/14)][i%14]===1:selector==='colour'?colour.has(i):colour.get(i)===selector);
      forms(values.join(''),label+'/'+selector);forms(values.reverse().join(''),label+'/'+selector+'/reverse');
    }
    for(const g of [0,7])gridSums(grid.map(c=>c==='o'?0:c==='g'?g:c.charCodeAt(0)-96),14,label+`/g${g}`);
  }
  const contexts=['reinsertingtheprimebasicsafterwhichyouwillberequiredto','sheisgoingtodieandthereisnothingyoucandotostopit'];
  // Only small, structured witness and matrix-sum materials get contextual concatenation.
  const bare=[...materials.values()];for(const m of bare)if(/witness|\/rows|\/columns/.test(m.provenance))for(const c of contexts) {
    const b=Buffer.from(m.hex,'hex');add(Buffer.concat([b,Buffer.from(c)]),m.provenance+'/before-clause');
    add(Buffer.concat([Buffer.from(c),b]),m.provenance+'/after-clause');
  }
  const publicSources={export:'Telegram Desktop/ChatExport_2026-09-17/result.json',messageIDs:[71413,71971,71986],
    atlasPages:[13,36,37,38,39],note:'Community claims, not creator instructions. Raw export and PDF remain local.'};
  save('spec.json',{inputSHA256:sha(raw),sourceSHA256:sha(fs.readFileSync(__filename)),publicSources,
    hypothesis:'Prime-host b|be segmentation of DBBI; residues and coordinate witnesses feed page codecs, matrix sums and SHA256/AES. Separate exploratory 195+1 full annotated matrix.',
    scope:'Both exact parses. Six token views, both directions, all g=0/7 masks for seven-bit whole-decimal decoding. Direct views and seven-bit candidates as literal, uppercase, digits and integer bytes. Factor-rectangle sums with g globally 0 or 7. All five picture witnesses and their coordinates/prime reinsertion. Prepend/append zero to DBBI+104-bit label, rows/columns/spiral, select original 0/1/B/Y/colours and sum. Enumerated serializations, two declared clauses. Raw and SHA256-hex passwords, all three original blobs, EVP-SHA256 and EVP-MD5.',
    limitations:'No arbitrary digit permutation, no exhaustive binary-payload search, no arbitrary transposition/geometry/key derivation; a negative only covers the declared materials.'});
  save('parses.json',parses);save('witnesses.json',witnesses);save('objects.json',objects);save('integer_checks.json',integerChecks);
  save('null.json',{randomSamples,randomAccepted,seed:0x5b7c1,scope:'Fixed b|be prime-host grammar, any complete logical length, count-preserving shuffles. This is not a correction for historical hypothesis selection.'});
  save('materials.json',[...materials.values()]);
  const control=Buffer.from(data.phase32_control_b64,'base64');
  const ctrl=open(Buffer.from(data.phase32_control_password),{salt:control.subarray(8,16).toString('hex'),ciphertext:control.subarray(16).toString('hex')},'sha256');
  assert.equal(sha(ctrl),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');controls.phase32=true;
  save('controls.json',controls);
  console.log(JSON.stringify({phase:'generated',materials:materials.size,parses:parses.map(p=>p.length),witnesses:witnesses.length,randomAccepted,integerCandidates:integerChecks.reduce((s,c)=>s+c.hits.length,0)}));
  let attempts=0,maxPrintable=0;const paddingResults=[],semantic=[],decisions=crypto.createHash('sha256');
  for(const m of materials.values())for(const form of ['direct','sha256-hex']) {
    const b=Buffer.from(m.hex,'hex'),pw=form==='direct'?b:Buffer.from(sha(b));
    for(const [blob,record]of Object.entries(data.blobs))for(const digest of ['sha256','md5']) {
      const body=open(pw,record,digest);attempts++;
      decisions.update([m.id,form,blob,digest,body?body.toString('hex'):'-'].join('|')+'\n');
      if(body){
        const printable=[...body].filter(x=>x>=32&&x<=126||[9,10,13].includes(x)).length/body.length;
        const rec={material:m.id,form,blob,digest,hex:body.toString('hex'),printable};paddingResults.push(rec);maxPrintable=Math.max(printable,maxPrintable);
        if(printable>=0.85||body.includes(Buffer.from('Salted__'))||body.includes(Buffer.from('U2FsdGVk')))semantic.push(rec);
      }
    }
  }
  save('padding.json',paddingResults);save('semantic_candidates.json',semantic);
  const summary={parses:parses.map(p=>({logicalLength:p.length,residualLength:p.residual.length,blue:p.colors.split('B').length-1,yellow:p.colors.split('Y').length-1})),
    witnesses:witnesses.map(w=>({length:w.length,omitted:w.omitted,distinctBytes:w.distinctBytes})),
    materials:materials.size,passwordCases:materials.size*2,attempts,padding:paddingResults.length,maxPrintable,semanticCandidates:semantic.length,
    integerModels:integerChecks.length,integerModelsComplete:integerChecks.filter(x=>x.complete).length,integerCandidates:integerChecks.reduce((s,c)=>s+c.hits.length,0),
    fixedGrammarNull:{randomSamples,randomAccepted},decisionsSHA256:decisions.digest('hex'),
    status:'No authenticated solution implied. See independent_verification.json for cross-library checks and private-key validation.'};
  save('summary.json',summary);console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)run();
module.exports={parseHosts,countParses,prime};
