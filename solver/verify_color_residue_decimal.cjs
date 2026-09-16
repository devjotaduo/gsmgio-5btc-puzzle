/* Reconstruct actual weighted grids and every operator. Count seven-bit
 * integers in the certificates without importing the searcher's code.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),zlib=require('node:zlib');
const readline=require('node:readline'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','color_residue_2026-09-16');
const inputBytes=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputBytes);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const power10=[1n],power128=[1n];for(let i=1;i<=600;i++){power10.push(power10[i-1]*10n);power128.push(power128[i-1]*128n);}
function count(n) {
  if(n<0n)return 0n;let hex=n.toString(16);if(hex.length%2)hex='0'+hex;
  const bytes=Buffer.from(hex,'hex');let sum=0n;
  for(let i=0;i<bytes.length;i++){sum+=BigInt(Math.min(bytes[i],128))*power128[bytes.length-i-1];if(bytes[i]>=128)return sum;}
  return sum+1n;
}
function inventory() {
  const colors=Array.from({length:14},(_,r)=>input.matrix[r].map(v=>v?'black':'white'));
  for(const [,color,r,c]of input.colored)colors[r][c]=color==='B'?'blue':'yellow';
  const keys=new Set(),ops=new Map();let constructions=0;
  for(const black of [0,1])for(const white of [0,1])for(let blue=0;blue<=9;blue++)for(let yellow=0;yellow<=9;yellow++) {
    const values={black,white,blue,yellow},matrix=colors.map(row=>row.map(color=>values[color]));
    for(const axis of ['rows','columns']) {
      const sums=axis==='rows'?matrix.map(row=>row.reduce((a,b)=>a+b,0)):
        Array.from({length:14},(_,c)=>matrix.reduce((s,row)=>s+row[c],0));
      for(const reverse of [false,true]) {
        const ordered=reverse?sums.slice().reverse():sums;
        for(let shift=0;shift<14;shift++) {
          const rotated=ordered.slice(shift).concat(ordered.slice(0,shift)),key=rotated.map(v=>v%10);constructions++;keys.add(key.join(''));
          for(const mode of ['add','subtract','beaufort']) {
            const sign=mode==='beaufort'?-1:1,offset=key.map(v=>mode==='subtract'?(10-v)%10:v),id=sign+':'+offset.join('');
            if(!ops.has(id))ops.set(id,{id,sign,offset,representative:{black,white,blue,yellow,axis,reverse,shift,mode}});
          }
        }
      }
    }
  }
  return {constructions,keys:keys.size,ops};
}
async function main() {
  const started=Date.now(),spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),summary=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
  assert.equal(spec.inputSHA256,sha(inputBytes));assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(__dirname,'color_residue_decimal.cjs'))));
  for(const [file,hash]of Object.entries(spec.helpers))assert.equal(hash,sha(fs.readFileSync(path.join(__dirname,file))));
  const inv=inventory(),storedOps=JSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(out,'operators.json.gz'))));
  assert.deepEqual(storedOps,[...inv.ops.values()]);assert.equal(inv.constructions,spec.keyConstructions);assert.equal(inv.keys,spec.keys);assert.equal(inv.ops.size,spec.operators);
  assert.equal(sha([...inv.ops.keys()].join('\n')),spec.operatorIDsSHA256);
  // Independently check all coefficient vectors too.
  for(const axis of ['rows','columns'])for(let k=0;k<14;k++) {
    const counts=[0,0,0,0];
    for(let j=0;j<14;j++){const r=axis==='rows'?k:j,c=axis==='rows'?j:k,co=input.colored.find(([,col,rr,cc])=>rr===r&&cc===c)?.[1];counts[co==='B'?0:co==='Y'?1:input.matrix[r][c]?2:3]++;}
    assert.deepEqual(counts,spec.coefficients[axis][k]);
  }
  let brute=0n;for(let n=0;n<65536;n++){if((n&255)<128&&(n>>8)<128)brute++;assert.equal(count(BigInt(n)),brute);}
  for(let n=1;n<=300;n++)assert.equal(count(256n**BigInt(n)-1n),128n**BigInt(n));
  console.log(JSON.stringify({stage:'inventory',operators:inv.ops.size,keys:inv.keys,seconds:(Date.now()-started)/1000}));
  const expected=new Set();for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const id of inv.ops.keys())expected.add([field,reverse,id].join('/'));
  const stream=fs.createReadStream(path.join(out,'cases.jsonl.gz')).pipe(zlib.createGunzip()),transcript=crypto.createHash('sha256');stream.on('data',b=>transcript.update(b));
  const lines=readline.createInterface({input:stream,crlfDelay:Infinity});
  let records=0,cases=0,nodes=0,certificates=0,partial=0,lastProgress=Date.now();const hits=[];
  for await(const line of lines) {
    const record=JSON.parse(line),op=inv.ops.get(record.operator);assert(op);
    assert(['dbbi','faed'].includes(record.field)&&typeof record.reverse==='boolean');assert(expected.delete([record.field,record.reverse,record.operator].join('/')));
    const source=record.reverse?[...input[record.field]].reverse().join(''):input[record.field];
    const normal=Array.from(source,(c,i)=>(op.sign*(' abcdefghi'.indexOf(c))+op.offset[i%14]+20)%10);
    assert.deepEqual(record.results.map(r=>r.alias),[...'abcdefghi']);
    for(const r of record.results) {
      const minimum=normal.slice(),weights=[];
      for(let i=0;i<source.length;i++)if(source[i]===r.alias) {
        const a=normal[i],b=op.offset[i%14];minimum[i]=a<b?a:b;
        weights.push(BigInt(Math.abs(a-b))*power10[source.length-i-1]);
      }
      const low=BigInt(minimum.join('')),tails=Array(weights.length+1).fill(0n);
      for(let i=weights.length-1;i>=0;i--)tails[i]=tails[i+1]+weights[i];
      assert.equal(weights.length,r.ambiguous);
      const partition=[...r.certificates.map(mask=>({mask,type:'excluded'})),...r.hits.map(hit=>({mask:hit.mask,type:'hit',hit})),...r.pending.map(mask=>({mask,type:'pending'}))];
      partition.sort((a,b)=>a.mask<b.mask?-1:a.mask>b.mask?1:0);let covered=0n;
      for(let j=0;j<partition.length;j++) {
        const item=partition[j],mask=item.mask;assert.match(mask,/^[01]*$/);assert(mask.length<=weights.length);if(j)assert(!mask.startsWith(partition[j-1].mask));
        let lo=low;for(let i=0;i<mask.length;i++)if(mask[i]==='1')lo+=weights[i];const hi=lo+tails[mask.length];
        if(item.type==='excluded'){assert.equal(count(hi)-count(lo-1n),0n);certificates++;}
        if(item.type==='hit') {
          assert.equal(mask.length,weights.length);assert.equal(lo.toString(),item.hit.decimal);assert.equal(count(lo)-count(lo-1n),1n);
          let hex=lo.toString(16);if(hex.length%2)hex='0'+hex;assert.equal(hex,item.hit.hex);
          hits.push({field:record.field,reverse:record.reverse,operator:record.operator,alias:r.alias,...item.hit});
        }
        covered+=1n<<BigInt(weights.length-mask.length);
      }
      assert.equal(covered,1n<<BigInt(weights.length));assert.equal(r.complete,r.pending.length===0);if(!r.complete)partial++;nodes+=r.nodes;cases++;
    }
    records++;
    if(Date.now()-lastProgress>=10000){console.log(JSON.stringify({records,cases,hits:hits.length,remaining:expected.size,seconds:(Date.now()-started)/1000}));lastProgress=Date.now();}
  }
  assert.equal(expected.size,0);assert.equal(records,summary.records);assert.equal(cases,summary.cases);assert.equal(nodes,summary.nodes);assert.equal(certificates,summary.certificates);assert.equal(partial,summary.partial.length);
  assert.equal(cases-partial,summary.complete);assert.equal(hits.length,summary.candidates);assert.deepEqual(hits,JSON.parse(fs.readFileSync(path.join(out,'candidates.json'))));
  const logSHA=transcript.digest('hex');assert.equal(logSHA,summary.casesSHA256);
  const oracle=JSON.parse(fs.readFileSync(path.join(out,'oracles.json'))),materials=new Set(),passwords=new Set(),scalars=new Set();
  for(const hit of hits)for(const reverse of [false,true]){const b=Buffer.from(hit.hex,'hex');if(reverse)b.reverse();materials.add(b.toString('hex'));}
  for(const hex of materials){const b=Buffer.from(hex,'hex'),h=sha(b);passwords.add(hex);passwords.add(Buffer.from(h).toString('hex'));scalars.add(h);for(let i=0;i+32<=b.length;i++)scalars.add(b.subarray(i,i+32).toString('hex'));}
  assert.deepEqual([...materials].sort(),oracle.materials.map(m=>m.hex).sort());assert.deepEqual([...passwords].sort(),oracle.passwords.map(p=>p.hex).sort());assert.deepEqual([...scalars].sort(),oracle.scalars.slice().sort());
  assert.equal(materials.size,summary.materials);assert.equal(passwords.size,summary.passwords);assert.equal(oracle.aesAttempts,passwords.size*Object.keys(input.blobs).length*2);
  const result={verifiedAt:new Date().toISOString(),keyConstructions:inv.constructions,keys:inv.keys,operators:inv.ops.size,records,cases,nodes,certificates,hits:hits.length,partial,allDeclaredModelsPresent:true,allMasksCovered:partial===0,
    materialsChecked:materials.size,passwordsChecked:passwords.size,scalarInputsChecked:scalars.size,
    scope:'Independent weighted grids, complete operator inventory, digit domains, exact interval counting, coverage of all masks and reconstruction of every candidate/oracle input. AES decryptions and curve points require the separate library verification.',
    controls:{integerCounts:65536,largeWidths:300},casesSHA256:logSHA,verifierSHA256:sha(fs.readFileSync(__filename)),elapsedMs:Date.now()-started};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}
if(require.main===module)main().catch(e=>{console.error(e);process.exitCode=1;});
