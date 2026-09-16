/* Independent full-grid key construction and arithmetic interval audit.
 * No imports from the searcher or its cipher/successor helpers.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),zlib=require('node:zlib'),readline=require('node:readline'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','color_carry_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const ten=[1n],p128=[1n];for(let i=1;i<=600;i++){ten.push(ten[i-1]*10n);p128.push(p128[i-1]*128n);}
function count(n) {
  if(n<0n)return 0n;let hex=n.toString(16);if(hex.length%2)hex='0'+hex;
  const bytes=Buffer.from(hex,'hex');let result=0n;
  for(let i=0;i<bytes.length;i++){result+=BigInt(Math.min(bytes[i],128))*p128[bytes.length-i-1];if(bytes[i]>=128)return result;}
  return result+1n;
}
function keys() {
  const colors=input.matrix.map(row=>row.map(bit=>bit?'black':'white'));
  for(const [,color,r,c]of input.colored)colors[r][c]=color==='B'?'blue':'yellow';
  const found=new Map();let constructions=0;
  for(const black of [0,1])for(const white of [0,1])for(let blue=0;blue<10;blue++)for(let yellow=0;yellow<10;yellow++) {
    const values={black,white,blue,yellow},matrix=colors.map(row=>row.map(c=>values[c]));
    for(const axis of ['rows','columns']) {
      const sums=axis==='rows'?matrix.map(row=>row.reduce((s,n)=>s+n,0)):Array.from({length:14},(_,c)=>matrix.reduce((s,row)=>s+row[c],0));
      for(const reverse of [false,true]) {
        const list=reverse?sums.slice().reverse():sums;
        for(let shift=0;shift<14;shift++) {
          const values=list.slice(shift).concat(list.slice(0,shift)).map(n=>n%10),id=values.join('');constructions++;
          if(!found.has(id))found.set(id,{id,values,representative:{black,white,blue,yellow,axis,reverse,shift,mode:'beaufort'}});
        }
      }
    }
  }
  return {constructions,keys:found};
}
function domains(source) {
  return [...'abcdefghi'].map(alias=>{
    const digits=[...source].map(c=>' abcdefghi'.indexOf(c)),weights=[];
    for(let i=0;i<source.length;i++)if(source[i]===alias){weights.push(BigInt(digits[i])*ten[source.length-i-1]);digits[i]=0;}
    const tails=Array(weights.length+1).fill(0n);for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
    return {low:BigInt(digits.join('')),weights,tails};
  });
}
const floor=(x,m)=>x<0n?-((-x+m-1n)/m):x/m;
function pieces(low,high,K,mode,family,M) {
  let a,b;
  if(mode==='add'){a=low+K;b=high+K;}else if(mode==='subtract'){a=low-K;b=high-K;}else{a=K-high;b=K-low;}
  if(family==='nonnegative')return b<0n?[]:[[a<0n?0n:a,b]];
  const result=[];
  for(let q=floor(a,M);q<=floor(b,M);q++) {
    const lo=a>q*M?a:q*M,hi=b<(q+1n)*M-1n?b:(q+1n)*M-1n;
    result.push([lo-q*M,hi-q*M]);
  }
  return result;
}
async function main() {
  const started=Date.now(),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
  assert.equal(spec.inputSHA256,sha(inputBytes));assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(__dirname,'color_residue_carry.cjs'))));
  for(const [file,hash]of Object.entries(spec.helpers))assert.equal(hash,sha(fs.readFileSync(path.join(__dirname,file))));
  const inventory=keys(),stored=JSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(out,'keys.json.gz'))));
  assert.deepEqual([...inventory.keys.values()],stored);assert.equal(inventory.constructions,spec.keyConstructions);assert.equal(inventory.keys.size,spec.keys);
  assert.equal(sha([...inventory.keys.keys()].join('\n')),spec.keyIDsSHA256);
  assert.deepEqual(spec.families,['modulo','nonnegative']);assert.deepEqual(spec.modes,['add','subtract','beaufort']);
  let brute=0n;for(let n=0;n<65536;n++){if((n&255)<128&&(n>>8)<128)brute++;assert.equal(count(BigInt(n)),brute);}
  for(let i=1;i<=300;i++)assert.equal(count(256n**BigInt(i)-1n),128n**BigInt(i));
  // Exhaustively check the interval image, including negative endpoints and
  // wrap boundaries, independently of certificate data.
  let intervalControls=0;
  for(const M of [10n,100n])for(let a=0n;a<10n;a++)for(let b=a;b<10n;b++)for(const K of [0n,2n,9n,99n])for(const mode of spec.modes)for(const family of spec.families) {
    const expected=new Set();for(let C=a;C<=b;C++){let P=mode==='add'?C+K:mode==='subtract'?C-K:K-C;if(family==='modulo')P=(P%M+M)%M;if(P>=0n)expected.add(P.toString());}
    const observed=new Set();for(const [lo,hi]of pieces(a,b,K,mode,family,M))for(let n=lo;n<=hi;n++)observed.add(n.toString());
    assert.deepEqual([...observed].sort(),[...expected].sort());intervalControls++;
  }
  const expected=new Set(),sources=new Map(),numericKeys=new Map();
  for(const field of ['dbbi','faed']) {
    const length=input[field].length;
    for(const reverse of [false,true])sources.set(field+'/'+reverse,domains(reverse?[...input[field]].reverse().join(''):input[field]));
    for(const key of inventory.keys.values())numericKeys.set(field+'/'+key.id,BigInt(key.id.repeat(Math.ceil(length/14)).slice(0,length)));
    for(const reverse of [false,true])for(const key of inventory.keys.keys())for(const family of spec.families)for(const mode of spec.modes)expected.add([field,reverse,key,family,mode].join('/'));
  }
  console.log(JSON.stringify({stage:'inventory',keys:inventory.keys.size,expectedRecords:expected.size,intervalControls,seconds:(Date.now()-started)/1000}));
  const stream=fs.createReadStream(path.join(out,'cases.jsonl.gz')).pipe(zlib.createGunzip()),commit=crypto.createHash('sha256');stream.on('data',b=>commit.update(b));
  const lines=readline.createInterface({input:stream,crlfDelay:Infinity}),hits=[];
  let records=0,cases=0,nodes=0,certificates=0,partial=0,lastProgress=Date.now();const countsByFamily={};
  for await(const line of lines) {
    const record=JSON.parse(line),{field,reverse,key,family,mode}=record;
    assert(expected.delete([field,reverse,key,family,mode].join('/')),'Unexpected or repeated model');
    const ds=sources.get(field+'/'+reverse),K=numericKeys.get(field+'/'+key),M=ten[input[field].length];
    assert.deepEqual(record.results.map(r=>r.alias),[...'abcdefghi']);
    for(let a=0;a<9;a++) {
      const r=record.results[a],d=ds[a];assert.equal(r.ambiguous,d.weights.length);
      const paths=[...r.certificates.map(mask=>({mask,type:'excluded'})),...r.hits.map(hit=>({mask:hit.mask,type:'hit',hit})),...r.pending.map(mask=>({mask,type:'pending'}))];
      paths.sort((a,b)=>a.mask<b.mask?-1:a.mask>b.mask?1:0);let cover=0n;
      for(let j=0;j<paths.length;j++) {
        const p=paths[j];assert.match(p.mask,/^[01]*$/);assert(p.mask.length<=d.weights.length);if(j)assert(!p.mask.startsWith(paths[j-1].mask));
        let lo=d.low;for(let bit=0;bit<p.mask.length;bit++)if(p.mask[bit]==='1')lo+=d.weights[bit];const hi=lo+d.tails[p.mask.length];
        const intervals=pieces(lo,hi,K,mode,family,M);
        if(p.type==='excluded'){for(const [x,y]of intervals)assert.equal(count(y)-count(x-1n),0n);certificates++;}
        if(p.type==='hit') {
          assert.equal(p.mask.length,d.weights.length);assert.equal(intervals.length,1);assert.equal(intervals[0][0],intervals[0][1]);const n=intervals[0][0];
          assert.equal(count(n)-count(n-1n),1n);assert.equal(n.toString(),p.hit.decimal);let hex=n.toString(16);if(hex.length%2)hex='0'+hex;assert.equal(hex,p.hit.hex);
          hits.push({field,reverse,key,family,mode,alias:r.alias,...p.hit});
        }
        cover+=1n<<BigInt(d.weights.length-p.mask.length);
      }
      assert.equal(cover,1n<<BigInt(d.weights.length));assert.equal(r.complete,r.pending.length===0);if(!r.complete)partial++;
      cases++;nodes+=r.nodes;const id=family+'/'+field;countsByFamily[id]??={cases:0,hits:0};countsByFamily[id].cases++;countsByFamily[id].hits+=r.hits.length;
    }
    records++;
    if(Date.now()-lastProgress>=10000){console.log(JSON.stringify({records,cases,hits:hits.length,remaining:expected.size,seconds:(Date.now()-started)/1000}));lastProgress=Date.now();}
  }
  assert.equal(expected.size,0);assert.equal(records,summary.records);assert.equal(cases,summary.cases);assert.equal(nodes,summary.nodes);assert.equal(certificates,summary.certificates);assert.equal(partial,summary.partial.length);assert.equal(cases-partial,summary.complete);
  assert.deepEqual(hits,JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))));assert.equal(hits.length,summary.candidates);const casesSHA256=commit.digest('hex');assert.equal(casesSHA256,summary.casesSHA256);
  const oracle=JSON.parse(fs.readFileSync(path.join(out,'oracles.json'))),materials=new Set(),passwords=new Set(),scalars=new Set();
  for(const hit of hits)for(const rev of [false,true]){const b=Buffer.from(hit.hex,'hex');if(rev)b.reverse();materials.add(b.toString('hex'));}
  for(const hex of materials){const b=Buffer.from(hex,'hex'),h=sha(b);passwords.add(hex);passwords.add(Buffer.from(h).toString('hex'));scalars.add(h);for(let i=0;i+32<=b.length;i++)scalars.add(b.subarray(i,i+32).toString('hex'));}
  assert.deepEqual([...materials].sort(),oracle.materials.map(m=>m.hex).sort());assert.deepEqual([...passwords].sort(),oracle.passwords.map(p=>p.hex).sort());assert.deepEqual([...scalars].sort(),oracle.scalars.slice().sort());
  assert.equal(materials.size,summary.materials);assert.equal(passwords.size,summary.passwords);assert.equal(oracle.aesAttempts,passwords.size*6);
  const result={verifiedAt:new Date().toISOString(),keyConstructions:inventory.constructions,keys:inventory.keys.size,records,cases,nodes,certificates,hits:hits.length,partial,countsByFamily,
    allDeclaredModelsPresent:true,allMasksCovered:partial===0,materialsChecked:materials.size,passwordsChecked:passwords.size,scalarInputsChecked:scalars.size,
    scope:'Weighted grid reconstruction, all keys/model combinations, arithmetic images by quotient splitting, exact seven-bit interval counts, all mask paths and oracle input reconstruction. Separate independent libraries verify AES and curve points.',
    controls:{integerCounts:65536,largeWidths:300,intervalImages:intervalControls},casesSHA256,verifierSHA256:sha(fs.readFileSync(__filename)),elapsedMs:Date.now()-started};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}
if(require.main===module)main().catch(e=>{console.error(e);process.exitCode=1;});
