'use strict';
// Reconstruct intervals and count UTF-8 integers, without the search recurrence.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const readline=require('node:readline');
const {countUtf8}=require('./verify_utf8_decimal.cjs');
const root=path.resolve(__dirname,'..'),folder=path.join(root,'_work/zero_cells_prime_sums_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex'),mod=(x,m)=>(x%m+m)%m;
async function main(){
  assert(!fs.existsSync(path.join(folder,'stream_verification.json')),'Inspect existing verifier result before rerun');
  const read=name=>JSON.parse(fs.readFileSync(path.join(folder,name+'.json'))),spec=read('stream_spec'),summary=read('stream_summary'),previous=read('verification');
  assert(previous.complete);const matrices=read('matrices');
  assert.equal(sha(fs.readFileSync(path.join(folder,'matrices.json'))),spec.matricesSHA256);assert.equal(previous.hashes.matrices,spec.matricesSHA256);
  assert.equal(sha(fs.readFileSync(path.join(folder,'stream_spec.json'))),summary.specSHA256);
  assert.equal(sha(fs.readFileSync(path.join(__dirname,'zero_cells_prime_stream.cjs'))),spec.sourceSHA256);
  for(const [name,h]of Object.entries(spec.dependencies))assert.equal(sha(fs.readFileSync(path.join(__dirname,name))),h);
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw);assert.equal(sha(raw),spec.inputSHA256);
  const reconstructedLists=[];
  for(const m of matrices)for(const axis of ['rows','columns']){
    const sums=Array(14).fill(0);for(let r=0;r<14;r++)for(let c=0;c<14;c++)sums[axis==='rows'?r:c]+=m.matrix[r][c];
    assert.deepEqual(sums,m[axis]);reconstructedLists.push({name:m.id+'/'+axis,values:sums});
  }
  assert.deepEqual(reconstructedLists,spec.lists);
  const expectedKeys=new Map();
  for(const list of reconstructedLists)for(const decimal of [false,true]){
    const ds=decimal?[...list.values.join('')].map(Number):list.values.map(v=>v%10);
    for(const rev of [false,true])for(let shift=0;shift<ds.length;shift++){
      const rotated=Array.from({length:ds.length},(_,j)=>ds[rev?ds.length-1-(j+shift)%ds.length:(j+shift)%ds.length]);
      expectedKeys.set(rotated.join(''),rotated);
    }
  }
  assert.deepEqual([...expectedKeys.keys()].sort(),spec.keys.map(k=>k.id).sort());
  for(const k of spec.keys)assert.deepEqual(expectedKeys.get(k.id),k.values);
  // Small direct controls of the independent count, including non-ASCII UTF-8.
  let controls=0;
  for(const order of ['big','little'])for(const low of [0,125,192,255,0x7ff0,0xbfc0,0xc280,0xe080]){
    const high=low+40;let expected=0n;
    for(let n=low;n<=high;n++){let h=n.toString(16);if(h.length%2)h='0'+h;const b=Buffer.from(h,'hex');if(order==='little')b.reverse();try{new TextDecoder('utf-8',{fatal:true}).decode(b);expected++;}catch{}}
    assert.equal(countUtf8(BigInt(high),order)-countUtf8(BigInt(low)-1n,order),expected);controls++;
  }
  let total=0,nodes=0,certs=0,intervals=0,hits=0;const ids=new Set(),candidates=[],partials=[],streamHash=crypto.createHash('sha256');
  const stream=fs.createReadStream(path.join(folder,'stream_cases.jsonl'));stream.on('data',b=>streamHash.update(b));
  const lines=readline.createInterface({input:stream,crlfDelay:Infinity});
  const sources=[input.faed,[...input.faed].reverse().join('')],length=input.faed.length,M=10n**BigInt(length);
  let previousId='',ds,K;
  for await(const line of lines){
    const c=JSON.parse(line);assert.equal(c.id,total);assert(typeof c.reverse==='boolean');assert(['digits','carry'].includes(c.family));assert(['subtract','add','beaufort'].includes(c.mode));assert(['big','little'].includes(c.order));
    assert(Number.isSafeInteger(c.key)&&c.key>=0&&c.key<spec.keys.length);
    const id=[c.reverse,c.key,c.family,c.mode,c.order].join('/');assert(!ids.has(id));ids.add(id);
    const group=[c.reverse,c.key,c.family,c.mode].join('/'),source=sources[Number(c.reverse)],key=spec.keys[c.key].values;
    if(group!==previousId){
      K=BigInt(Array.from({length},(_,i)=>key[i%key.length]).join(''));
      ds=[...source].map((ch,i)=>{const a=ch==='g'?[0,7]:[ch.charCodeAt(0)-96];return c.family==='carry'?a:a.map(v=>Number(mod(BigInt(c.mode==='subtract'?v-key[i%key.length]:c.mode==='add'?v+key[i%key.length]:key[i%key.length]-v),10n))).sort((a,b)=>a-b);});
      previousId=group;
    }
    const ambiguous=ds.filter(s=>s.length===2).length;assert.equal(ambiguous,c.ambiguous);
    function endpoint(mask,high){let at=0;return BigInt(ds.map(s=>{if(s.length===1)return s[0];const bit=at<mask.length?Number(mask[at]):Number(high);at++;return s[bit];}).join(''));}
    function ranges(lo,hi){
      if(c.family==='digits')return [[lo,hi]];
      const a=c.mode==='subtract'?lo-K:c.mode==='add'?lo+K:K-hi,b=c.mode==='subtract'?hi-K:c.mode==='add'?hi+K:K-lo;
      const result=[],first=(a-mod(a,M))/M,last=(b-mod(b,M))/M;
      for(let q=first;q<=last;q++){const left=a>q*M?a:q*M,right=b<(q+1n)*M-1n?b:(q+1n)*M-1n;result.push([left-q*M,right-q*M]);}
      return result;
    }
    const prefixes=[];let covered=0n;
    for(const mask of c.certificates){
      assert(/^[01]*$/.test(mask)&&mask.length<=ambiguous);const low=endpoint(mask,false),high=endpoint(mask,true);
      for(const [a,b]of ranges(low,high)){assert.equal(countUtf8(b,c.order)-countUtf8(a-1n,c.order),0n);intervals++;}
      covered+=1n<<BigInt(ambiguous-mask.length);prefixes.push(mask);certs++;
    }
    for(const h of c.hits){
      assert(/^[01]*$/.test(h.mask)&&h.mask.length===ambiguous);const n=ranges(endpoint(h.mask,false),endpoint(h.mask,true));assert.equal(n.length,1);assert.equal(n[0][0],n[0][1]);assert.equal(String(n[0][0]),h.decimal);
      let hex=n[0][0].toString(16);if(hex.length%2)hex='0'+hex;const bytes=Buffer.from(hex,'hex');if(c.order==='little')bytes.reverse();assert.equal(bytes.toString('hex'),h.hex);assert.equal(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes),h.text);
      candidates.push({case:c.id,...h});prefixes.push(h.mask);covered++;hits++;
    }
    for(const mask of c.pending){assert(/^[01]*$/.test(mask)&&mask.length<=ambiguous);prefixes.push(mask);covered+=1n<<BigInt(ambiguous-mask.length);}
    if(c.pending.length)partials.push(c.id);assert.equal(c.complete,c.pending.length===0);
    prefixes.sort();for(let i=1;i<prefixes.length;i++)assert(!prefixes[i].startsWith(prefixes[i-1]));assert.equal(covered,1n<<BigInt(ambiguous));
    nodes+=c.nodes;total++;if(total%20000===0)console.log(JSON.stringify({verifiedCases:total,certificates:certs,intervals,hits}));
  }
  assert.equal(streamHash.digest('hex'),summary.casesSHA256);assert.equal(total,spec.keys.length*24);assert.equal(total,summary.cases);assert.equal(nodes,summary.nodes);assert.equal(certs,summary.certificates);assert.equal(expectedKeys.size,summary.keys);
  assert.deepEqual(candidates,summary.candidates);assert.deepEqual(partials,summary.partial);assert.equal(summary.complete,partials.length===0);
  const result={complete:summary.complete,cases:total,keys:expectedKeys.size,certificates:certs,intervals,hits,partial:partials.length,controls,allMasksAccounted:true,allExcluded:!hits&&!partials.length,method:'Independent reconstruction of all cyclic keys and mask endpoints; UTF8 scalar-template interval counting, independent of producer successor automaton. Positive leaves decoded strictly; prefix-free coverage includes any pending nodes.',hashes:Object.fromEntries(['stream_spec','stream_summary','verification'].map(f=>[f,sha(fs.readFileSync(path.join(folder,f+'.json')))])),casesSHA256:summary.casesSHA256,sourceSHA256:sha(fs.readFileSync(__filename)),counterSHA256:sha(fs.readFileSync(path.join(__dirname,'verify_utf8_decimal.cjs')))};
  fs.writeFileSync(path.join(folder,'stream_verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}
if(require.main===module)main().catch(e=>{console.error(e);process.exitCode=1;});
