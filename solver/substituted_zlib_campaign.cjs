'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {search}=require('./substituted_zlib_search.cjs');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','substituted_zlib_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const headerRaw=fs.readFileSync(path.join(root,'_work','substituted_format_headers_2026-09-16','cases.json')),header=JSON.parse(headerRaw),inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),options={maxNodes:100000,maxMs:15000,maxOutputLength:1048576};
fs.mkdirSync(out,{recursive:true});assert(!fs.existsSync(path.join(out,'cases.jsonl')),'Existing campaign: inspect before rerunning');
const spec={scope:'Complete DBBI/FAED in both source directions. Any bijection a..i to 1..9; every occurrence of zero, one or two selected letters may instead be zero. Zlib without a preset dictionary; minimal big-endian bytes, complete consumption required. A bounded case remains inconclusive with all frontier states saved.',options,inputSHA256:sha(inputRaw),headerCasesSHA256:sha(headerRaw),sources:Object.fromEntries(['substituted_zlib_campaign.cjs','substituted_zlib_search.cjs','compressed_payload_constraints.cjs'].map(f=>[f,sha(fs.readFileSync(path.join(__dirname,f)))])),pilotSummarySHA256:sha(fs.readFileSync(path.join(out,'pilot_summary.json')))};
fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');let count=0,nodes=0,incomplete=0,hits=0;const start=Date.now();
for(const [caseIndex,c]of header.entries())if(c.format==='zlib')for(const [index,r]of c.results.entries()){
  if(!r.compatible||(parseInt(r.magic.slice(2),16)&32))continue;
  const source=c.reverse?[...input[c.field]].reverse().join(''):input[c.field],range={bytes:r.bytes,magic:r.magic,lower:r.lower,upper:r.upper},result=search(source,c.aliases,range,options),record={field:c.field,reverse:c.reverse,aliases:c.aliases,headerCase:caseIndex,headerRange:index,range,...result};
  fs.appendFileSync(path.join(out,'cases.jsonl'),JSON.stringify(record)+'\n');count++;nodes+=result.nodes;incomplete+=Number(!result.complete);hits+=result.hits.length;
  const progress={finished:false,cases:count,nodes,incomplete,hits,elapsedMs:Date.now()-start};fs.writeFileSync(path.join(out,'progress.json'),JSON.stringify(progress)+'\n');
  if(count%20===0||!result.complete||result.hits.length)console.log(JSON.stringify({...progress,last:[c.field,c.reverse,c.aliases,index]}));
}
const summary={finished:true,complete:incomplete===0,cases:count,nodes,incomplete,hits,elapsedMs:Date.now()-start,casesSHA256:sha(fs.readFileSync(path.join(out,'cases.jsonl')))};
fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
