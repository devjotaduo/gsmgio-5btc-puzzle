'use strict';
// Exact decimal-prefix search under a digit bijection, with optional zero aliases.
// Uses irreversible zlib-prefix errors as pruning. Bounded runs save every pending state.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),zlib=require('node:zlib');
const {inflateWhole}=require('./compressed_payload_constraints.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_zlib_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function bytes(n){let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.from(h,'hex');}
function model(source,aliases){
  const powers=[1n];for(let i=0;i<source.length;i++)powers.push(powers.at(-1)*10n);
  const weights=Array.from({length:source.length+1},()=>Array(9).fill(0n));
  for(let p=source.length-1;p>=0;p--){weights[p]=[...weights[p+1]];weights[p][source.charCodeAt(p)-97]+=powers[source.length-p-1];}
  function bounds(prefix,mapping){
    const p=prefix.length,base=BigInt(prefix||'0')*powers[source.length-p],free=[];for(let d=1;d<=9;d++)if(!mapping.includes(String(d)))free.push(d);
    function suffix(min){let n=0n;const unassigned=[];for(let i=0;i<9;i++){const w=min&&aliases.includes(String.fromCharCode(97+i))?0n:weights[p][i];if(mapping[i]==='0')unassigned.push(w);else n+=BigInt(mapping[i])*w;}
      unassigned.sort((a,b)=>a===b?0:a>b?-1:1);const ds=min?free:[...free].reverse();for(let i=0;i<ds.length;i++)n+=BigInt(ds[i])*unassigned[i];return n;}
    return {lower:base+suffix(true),upper:base+suffix(false)};
  }
  function children(prefix,mapping){const c=source[prefix.length],idx=c.charCodeAt(0)-97,options=[];if(aliases.includes(c))options.push(0);if(mapping[idx]!=='0')options.push(Number(mapping[idx]));else for(let d=1;d<=9;d++)if(!mapping.includes(String(d)))options.push(d);
    return options.map(d=>{let p=prefix+d,m=[...mapping];if(d)m[idx]=String(d);while(p.length<source.length&&!aliases.includes(source[p.length])&&m[source.charCodeAt(p.length)-97]!=='0')p+=m[source.charCodeAt(p.length)-97];return {prefix:p,mapping:m.join('')};});}
  return {bounds,children};
}
function search(source,aliases,range,{maxNodes=100000,maxMs=15000,maxOutputLength=1048576}={}){
  assert(!(parseInt(range.magic.slice(2),16)&32),'Only streams without a preset dictionary');
  const M=model(source,aliases),stack=[{prefix:'',mapping:'000000000'}],certificates=[],hits=[],deferred=[],start=Date.now();let nodes=0,limitReason=null;
  while(stack.length){
    if(nodes>=maxNodes||Date.now()-start>=maxMs){limitReason=nodes>=maxNodes?'node_limit':'time_limit';break;}
    const state=stack.pop(),b=M.bounds(state.prefix,state.mapping);nodes++;let lower=b.lower>BigInt(range.lower)?b.lower:BigInt(range.lower),upper=b.upper<BigInt(range.upper)?b.upper:BigInt(range.upper);
    if(lower>upper){certificates.push({...state,reason:'range_disjoint'});continue;}
    const a=bytes(lower),bbytes=bytes(upper);assert.equal(a.length,range.bytes);assert.equal(bbytes.length,range.bytes);let count=0;while(count<a.length&&a[count]===bbytes[count])count++;const prefix=a.subarray(0,count),decoded=inflateWhole(prefix,'zlib',{maxOutputLength});
    let reason=null;
    if(decoded.status==='invalid')reason='invalid_prefix';
    else if(['valid','trailing'].includes(decoded.status)&&decoded.consumed<range.bytes)reason='stream_ends_before_input';
    else if(state.prefix.length===source.length&&decoded.status==='incomplete')reason='truncated_stream';
    if(reason){certificates.push({...state,reason,lower:String(lower),upper:String(upper),prefixHex:prefix.toString('hex'),decoderReason:decoded.reason??null,consumed:decoded.consumed??null});continue;}
    if(['limit','needs_dictionary'].includes(decoded.status)){deferred.push({...state,reason:decoded.status});continue;}
    if(state.prefix.length===source.length){assert.equal(decoded.status,'valid');assert.equal(decoded.consumed,range.bytes);hits.push({...state,compressedHex:prefix.toString('hex'),outputHex:decoded.output.toString('hex')});continue;}
    const children=M.children(state.prefix,state.mapping);assert(children.length);for(let i=children.length-1;i>=0;i--)stack.push(children[i]);
  }
  const pending=[...stack.map(s=>({...s,reason:limitReason})),...deferred];return {complete:pending.length===0,nodes,elapsedMs:Date.now()-start,certificates,hits,pending};
}
function controls(){
  let planted=0;
  for(const text of ['MATRIXSUMLIST','yellowblueprimesmatrixsumlistlastwordsbeforearchichoice'.repeat(3)])for(const map of ['123456789','987654321'])for(const aliases of ['g','bd']){
    const raw=Buffer.from(text),packed=zlib.deflateSync(raw),n=BigInt('0x'+packed.toString('hex'));let k=0;const source=[...String(n)].map(d=>d==='0'?aliases[k++%aliases.length]:String.fromCharCode(97+map.indexOf(d))).join(''),r=search(source,aliases,{magic:packed.subarray(0,2).toString('hex'),bytes:packed.length,lower:String(n),upper:String(n)},{maxNodes:10000,maxMs:5000});assert(r.complete&&r.hits.some(h=>h.outputHex===raw.toString('hex')));planted++;
  }
  return {planted};
}
function main(){
  assert.equal(process.argv[2],'pilot','Use pilot for the declared four no-zero models');fs.mkdirSync(out,{recursive:true});const headerRaw=fs.readFileSync(path.join(root,'_work','substituted_format_headers_2026-09-16','cases.json')),header=JSON.parse(headerRaw),inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),options={maxNodes:100000,maxMs:15000,maxOutputLength:1048576};
  assert(!fs.existsSync(path.join(out,'pilot_cases.jsonl')),'Existing campaign: inspect before rerunning');const spec={mode:'pilot',scope:'All no-zero-alias models, all digit bijections, both fields and source directions. Header-compatible zlib ranges without FDICT only. Bounded per range; pending states retained. Full minimal big-endian byte stream required.',options,controls:controls(),inputSHA256:sha(inputRaw),headerCasesSHA256:sha(headerRaw),sourceSHA256:sha(fs.readFileSync(__filename)),helperSHA256:sha(fs.readFileSync(path.join(__dirname,'compressed_payload_constraints.cjs')))};fs.writeFileSync(path.join(out,'pilot_spec.json'),JSON.stringify(spec,null,2)+'\n');
  let count=0,nodes=0,incomplete=0,hits=0;
  for(const c of header.filter(c=>c.format==='zlib'&&c.aliases===''))for(const [index,r]of c.results.entries()){
    if(!r.compatible||(parseInt(r.magic.slice(2),16)&32))continue;const source=c.reverse?[...input[c.field]].reverse().join(''):input[c.field],range={bytes:r.bytes,magic:r.magic,lower:r.lower,upper:r.upper},result=search(source,c.aliases,range,options),record={field:c.field,reverse:c.reverse,aliases:c.aliases,headerRange:index,range,...result};fs.appendFileSync(path.join(out,'pilot_cases.jsonl'),JSON.stringify(record)+'\n');count++;nodes+=result.nodes;incomplete+=Number(!result.complete);hits+=result.hits.length;console.log(JSON.stringify({field:c.field,reverse:c.reverse,index,complete:result.complete,nodes:result.nodes,hits:result.hits.length,ms:result.elapsedMs}));
  }
  const summary={finished:true,complete:incomplete===0,cases:count,nodes,incomplete,hits,casesSHA256:sha(fs.readFileSync(path.join(out,'pilot_cases.jsonl')))};fs.writeFileSync(path.join(out,'pilot_summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}
if(require.main===module)main();module.exports={model,search};
