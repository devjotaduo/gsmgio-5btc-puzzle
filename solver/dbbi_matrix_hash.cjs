/* DBBI's 64-token equality pattern as a constraint on SHA256 preimages.
 * Explicit finite family of colour-weighted matrix sum lists.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/dbbi_matrix_hash_2026-09-16');
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function prime(n){for(let i=2;i*i<=n;i++)if(n%i===0)return false;return n>=2;}
function factors(n){const result=[];for(let p=2;p*p<=n;p++){let exponent=0;while(n%p===0){n/=p;exponent++;}if(exponent)result.push({prime:p,exponent});}if(n>1)result.push({prime:n,exponent:1});return result;}
function parse(source,prefixes){
  const result=[];
  for(let i=0;i<source.length;){const size=prefixes.includes(source[i])?2:1;if(i+size>source.length)return null;result.push(source.slice(i,i+size));i+=size;}
  return result;
}
function pattern(sequence){const table=new Map();return [...sequence].map(v=>{if(!table.has(v))table.set(v,table.size);return table.get(v);});}
function matches(target,hex){
  if(target.length!==hex.length)return false;
  const forward=new Int8Array(16).fill(-1),back=new Int8Array(16).fill(-1);
  for(let i=0;i<target.length;i++){
    const t=target[i],v=parseInt(hex[i],16);
    if(forward[t]===-1){if(back[v]!==-1)return false;forward[t]=v;back[v]=t;}
    else if(forward[t]!==v)return false;
  }
  return true;
}
function coefficients(data){
  const colors=new Map(data.colored.map(([,color,r,c])=>[r*14+c,color]));
  return ['bits','zero'].flatMap(background=>['rows','columns'].map(direction=>({background,direction,
    values:Array.from({length:14},(_,line)=>{
      const coeff=[0,0,0];for(let j=0;j<14;j++){
        const[r,c]=direction==='rows'?[line,j]:[j,line],color=colors.get(r*14+c);
        if(color==='B')coeff[0]++;else if(color==='Y')coeff[1]++;else if(background==='bits')coeff[2]+=data.matrix[r][c];
      }return coeff;
    })})));
}
function layouts(rows,columns){return [
  ['rows',rows],['columns',columns],['rows-columns',[...rows,...columns]],
  ['columns-rows',[...columns,...rows]],['interleaved',rows.flatMap((v,i)=>[v,columns[i]])],
  ['total',[rows.reduce((a,b)=>a+b,0)]],
];}
function representations(values){
  const result=[['decimal-concat',Buffer.from(values.join(''))],['decimal-csv',Buffer.from(values.join(','))],
    ['decimal-space',Buffer.from(values.join(' '))],['decimal-lines',Buffer.from(values.join('\n'))],
    ['json-compact',Buffer.from(JSON.stringify(values))],['json-spaced',Buffer.from('['+values.join(', ')+']')]];
  if(values.every(v=>v<=255))result.push(['bytes',Buffer.from(values)]);
  for(const size of [2,4])if(values.every(v=>v<2**(8*size)))for(const endian of ['BE','LE']){
    const b=Buffer.alloc(size*values.length);values.forEach((v,i)=>b['writeUInt'+(size*8)+endian](v,size*i));
    result.push([`uint${size*8}-${endian}`,b]);
  }
  return result;
}
function controls(){
  const h=digest(Buffer.from('abc'));assert.equal(h,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(new Set(h).size,16);assert(matches(pattern(h),h));
  assert(matches(pattern([...h].reverse()),[...h].reverse().join('')));
  const changed=(h[0]==='0'?'1':'0')+h.slice(1);assert(!matches(pattern(h),changed));
  for(const values of [[0,1,127,255],[256,193,577],[140115,181]])for(const[name,b]of representations(values)){
    if(name==='bytes')assert.deepEqual([...b],values);
    if(name.startsWith('uint')){const[,bits,endian]=name.match(/^uint(\d+)-(BE|LE)$/);assert.deepEqual(values.map((_,i)=>b['readUInt'+bits+endian](i*Number(bits)/8)),values);}
  }
  return {sha256ABC:true,patternPositive:2,patternNegative:1,binaryRoundTrips:true};
}
function main(){
  fs.mkdirSync(out,{recursive:true});const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(raw);
  const save=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
  const inventory=[],targets=[];
  for(let a=0;a<9;a++)for(let b=a+1;b<9;b++)for(const reverseInput of[false,true]){
    const prefixes=String.fromCharCode(97+a,97+b),source=reverseInput?[...data.dbbi].reverse().join(''):data.dbbi,tokens=parse(source,prefixes);
    const item={prefixes,reverseInput,tokens:tokens?.length??null,types:tokens?new Set(tokens).size:null};inventory.push(item);
    if(tokens?.length===64&&new Set(tokens).size===16)for(const reverseTokens of[false,true]){
      const ordered=reverseTokens?tokens.slice().reverse():tokens;
      targets.push({...item,reverseTokens,sequence:ordered,pattern:pattern(ordered)});
    }
  }
  assert.equal(targets.length,2);
  const primes=Array.from({length:197},(_,i)=>i).filter(prime),domain=[0,1,...primes];
  const blueFactors=factors(0x3f48cc),yellowFactors=factors(0xfff200),weightMap=new Map();
  function add(blue,yellow,origin){const id=`${blue},${yellow}`;if(!weightMap.has(id))weightMap.set(id,{blue,yellow,origins:[]});weightMap.get(id).origins.push(origin);}
  for(const blue of domain)for(const yellow of domain)add(blue,yellow,'0,1 or prime <=196');
  for(const b of blueFactors)for(const y of yellowFactors)add(b.prime,y.prime,'prime divisor of the respective RGB integer');
  const weights=[...weightMap.values()],coeff=coefficients(data);
  save('spec.json',{createdAt:new Date().toISOString(),inputSHA256:digest(raw),sourceSHA256:digest(fs.readFileSync(__filename)),
    hypothesis:'DBBI greedily parsed with two escape letters encodes SHA256(matrix sum list) hexadecimal under an unknown bijection of 16 token types to hexadecimal digits.',
    scope:'Both input directions, all 36 two-prefix sets, then either token order; only 64-token/16-type parses. Fixed colour values drawn from 0,1, primes <=196, plus prime divisors of the respective RGB integers. Original-bit or zero uncoloured background. Six list layouts, forward/reverse, eleven declared textual/binary representations when exact without truncation.',
    limits:'The finite weight domain and serializations are hypotheses, not instructions confirmed by the creator. No arbitrary integer weights, extra phrases, other digests, homophones or altered tokenization.',
    primes,domain,blueRGB:{hex:'3f48cc',value:0x3f48cc,factors:blueFactors},yellowRGB:{hex:'fff200',value:0xfff200,factors:yellowFactors},
    weights,coefficients:coeff,tokenInventory:inventory,targets,
    layoutNames:['rows','columns','rows-columns','columns-rows','interleaved','total'],
    representationOrder:['decimal-concat','decimal-csv','decimal-space','decimal-lines','json-compact','json-spaced','bytes','uint16-BE','uint16-LE','uint32-BE','uint32-LE'],
    transcriptFormat:'layout:forward|reverse:representation<TAB>preimage_hex<TAB>sha256_hex<TAB>target_match_bitmask<LF>',
    counting:'Counts are construction/serialization evaluations, not necessarily distinct preimages.'});
  const checked=controls(),groups=[],hits=[];let hashEvaluations=0;
  for(const weight of weights)for(const background of['bits','zero']){
    const r=coeff.find(c=>c.background===background&&c.direction==='rows'),c=coeff.find(c=>c.background===background&&c.direction==='columns');
    const apply=xs=>xs.map(([b,y,k])=>b*weight.blue+y*weight.yellow+k),rows=apply(r.values),columns=apply(c.values);
    assert.equal(rows.reduce((a,b)=>a+b,0),columns.reduce((a,b)=>a+b,0));
    const trace=crypto.createHash('sha256');let evaluations=0;
    for(const[layout,values]of layouts(rows,columns))for(const reverse of[false,true]){
      for(const[representation,preimage]of representations(reverse?values.slice().reverse():values)){
        const h=digest(preimage);let mask=0;targets.forEach((t,i)=>{if(matches(t.pattern,h))mask|=1<<i;});
        const label=`${layout}:${reverse?'reverse':'forward'}:${representation}`;
        trace.update(`${label}\t${preimage.toString('hex')}\t${h}\t${mask}\n`);evaluations++;hashEvaluations++;
        if(mask)hits.push({blue:weight.blue,yellow:weight.yellow,background,layout,reverse,representation,
          preimageHex:preimage.toString('hex'),sha256:h,targetMask:mask});
      }
    }
    groups.push({blue:weight.blue,yellow:weight.yellow,background,evaluations,transcriptSHA256:trace.digest('hex')});
  }
  save('groups.json',groups);save('hits.json',hits);
  const summary={controls:checked,tokenParsesExamined:inventory.length,targets:targets.length,weightPairs:weights.length,
    groups:groups.length,hashEvaluations,patternComparisons:hashEvaluations*targets.length,exactPatternHits:hits.length,
    groupsSHA256:digest(fs.readFileSync(path.join(out,'groups.json'))),aesTrials:0,finalPasswordFound:false};
  save('summary.json',summary);console.log(JSON.stringify(summary,null,2));
  if(hits.length)console.log('Exact pattern hits saved. They require independent verification and original AES/key tests before any solution claim.');
}
if(require.main===module)main();
