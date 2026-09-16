'use strict';
// Independent word-boundary dynamic programming with numeric codeword tables.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','ebcdic_decimal_2026-09-16','codepoints'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw);
const tableRaw=fs.readFileSync(path.join(out,'..','encoding.json')),table=JSON.parse(tableRaw.toString('utf8').replace(/^\uFEFF/,''));
const allowed=table.decoded.flatMap((c,i)=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126||[9,10,13].includes(c.charCodeAt(0))?[i]:[]),present=new Set(allowed);
const domains=Array.from({length:18},(_,i)=>i<9?[i+1]:[0,i-8]);
function lookup(padded){
  const one=new Uint8Array(18),two=new Uint8Array(324),three=new Uint8Array(5832);
  for(let i=0;i<18;i++)for(const a of domains[i]){
    if(!padded&&present.has(a))one[i]=1;
    for(let j=0;j<18;j++)for(const b of domains[j]){
      if(!padded&&a>0&&present.has(a*10+b))two[i*18+j]=1;
      for(let k=0;k<18;k++)for(const c of domains[k])if((padded||a>0)&&present.has(a*100+b*10+c))three[i*324+j*18+k]=1;
    }
  }
  return {one,two,three};
}
const tables=[lookup(false),lookup(true)];
function accepts(source,map,aliases,padded){
  const ids=map.map((d,i)=>d-1+((aliases&(1<<i))?9:0)),t=tables[Number(padded)];let positions=1;
  for(let i=0;i<source.length;i++){
    if(positions&1){const a=ids[source[i]];if(t.one[a])positions|=2;
      if(i+1<source.length){const b=ids[source[i+1]];if(t.two[a*18+b])positions|=4;
        if(i+2<source.length&&t.three[a*324+b*18+ids[source[i+2]]])positions|=8;}
    }
    positions>>>=1;if(!positions)return false;
  }
  return !!(positions&1);
}
function permutations(fn,prefix=[],used=0){if(prefix.length===9){fn(prefix);return;}for(let d=1;d<=9;d++)if(!(used&(1<<d))){prefix.push(d);permutations(fn,prefix,used|1<<d);prefix.pop();}}
function controls(){
  let lookupChecks=0,plants=0;
  for(const padded of [false,true]){
    const t=tables[Number(padded)];
    for(let i=0;i<18;i++)for(let j=0;j<18;j++)for(let k=0;k<18;k++){
      const words=allowed.map(n=>padded?String(n).padStart(3,'0'):String(n));
      const ds=[domains[i],domains[j],domains[k]];
      for(let len=1;len<=3;len++){
        const expected=words.some(w=>w.length===len&&[...w].every((c,p)=>ds[p].includes(Number(c))));
        const actual=len===1?t.one[i]:len===2?t.two[i*18+j]:t.three[i*324+j*18+k];assert.equal(Boolean(actual),expected);lookupChecks++;
      }
    }
    for(const map of [[1,2,3,4,5,6,7,8,9],[9,8,7,6,5,4,3,2,1],[3,5,7,9,2,4,6,8,1]])for(let alias=0;alias<9;alias++)for(const text of ['Matrix','zero','A0\n\t!']){
      let source=[];for(const c of text){const n=table.decoded.indexOf(c),digits=padded?String(n).padStart(3,'0'):String(n);source.push(...[...digits].map(d=>d==='0'?alias:map.indexOf(Number(d))));}
      assert(accepts(source,map,1<<alias,padded));plants++;
    }
  }
  return {lookupComparisons:lookupChecks,plantedRecoveries:plants};
}
function main(){
  const spec=JSON.parse(fs.readFileSync(path.join(out,'spec.json'))),saved=JSON.parse(fs.readFileSync(path.join(out,'summary.json')));
  assert(saved.complete);assert.equal(saved.partial.length,0);assert.equal(spec.inputSHA256,sha(inputRaw));assert.equal(spec.tableSHA256,sha(tableRaw));
  assert.equal(spec.sourceSHA256,sha(fs.readFileSync(path.join(__dirname,'ebcdic_codepoints.cjs'))));assert.equal(spec.permutationHelperSHA256,sha(fs.readFileSync(path.join(__dirname,'substituted_decimal_constraints.cjs'))));assert.deepEqual(spec.allowed,allowed);
  assert.equal(saved.accepted.length,0,'Nonempty candidate set needs full path verification, not just feasibility.');
  const aliasSets=['',...'abcdefghi'];for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)aliasSets.push(String.fromCharCode(97+i,97+j));
  const expected=[];for(const padded of [false,true])for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const aliases of aliasSets)expected.push(['fixed',field,reverse,aliases,padded].join('/'));
  for(const padded of [false,true])for(const aliases of 'abcdefghi')for(const field of ['dbbi','faed'])for(const reverse of [false,true])expected.push(['substituted',field,reverse,aliases,padded].join('/'));
  assert.deepEqual(saved.groups.map(g=>[g.family,g.field,g.reverse,g.aliases,g.padded].join('/')).sort(),expected.sort());
  const result={complete:false,controls:controls(),cases:0,accepted:0,groups:[],verifierSHA256:sha(fs.readFileSync(__filename)),summarySHA256:sha(fs.readFileSync(path.join(out,'summary.json')))};
  console.log(JSON.stringify({controls:result.controls}));
  for(const g of saved.groups){
    const source=[...(g.reverse?[...input[g.field]].reverse().join(''):input[g.field])].map(c=>c.charCodeAt(0)-97),aliases=[...g.aliases].reduce((m,c)=>m|1<<(c.charCodeAt(0)-97),0),started=Date.now();let cases=0,accepted=0;
    function one(map){cases++;if(accepts(source,map,aliases,g.padded))accepted++;}
    if(g.family==='fixed')one([1,2,3,4,5,6,7,8,9]);else permutations(one);
    assert.equal(cases,g.cases);assert.equal(accepted,g.accepted);result.cases+=cases;result.accepted+=accepted;result.groups.push({...g,elapsedMs:Date.now()-started});
  }
  assert.equal(result.cases,saved.cases);assert.equal(result.accepted,0);result.complete=true;
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({complete:true,cases:result.cases,accepted:result.accepted}));
}
if(require.main===module)main();module.exports={accepts};
