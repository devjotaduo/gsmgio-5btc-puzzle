/* Exhaustive vertex-cut check, independent of Gaussian elimination.
 * Verifies the saved edge-XOR certificates directly as even subgraphs.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/dbbi_distance_parity_2026-09-16');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function orders(){
  const row=[],column=[],diagonal=[],diagonalDescending=[];
  for(let a=0;a<14;a++)for(let b=a+1;b<14;b++)row.push([a,b]);
  for(let b=1;b<14;b++)for(let a=0;a<b;a++)column.push([a,b]);
  for(let d=1;d<14;d++)for(let a=0;a+d<14;a++)diagonal.push([a,a+d]);
  for(let d=13;d>=1;d--)for(let a=0;a+d<14;a++)diagonalDescending.push([a,a+d]);
  const result={row,column,diagonal,diagonalDescending};
  for(const[name,pairs]of Object.entries(result))result[name+'/reversed']=pairs.slice().reverse();
  return result;
}
function main(){
  const read=n=>JSON.parse(fs.readFileSync(path.join(out,n)));
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),input=JSON.parse(raw),spec=read('spec.json'),cases=read('cases.json'),summary=read('summary.json');
  assert.equal(hash(raw),spec.inputSHA256);assert.equal(hash(fs.readFileSync(path.join(root,'solver/dbbi_distance_parity.cjs'))),spec.sourceSHA256);
  assert.equal(hash(fs.readFileSync(path.join(out,'cases.json'))),summary.casesSHA256);
  const traversals=orders(),labels=[...input.dbbi].map(c=>c.charCodeAt(0)-97),ids=new Set(),checks=[];
  let cutsChecked=0,certificatesChecked=0;
  for(const item of cases){
    assert(Object.hasOwn(traversals,item.order));assert(item.erasedSymbol===null||/^[a-i]$/.test(item.erasedSymbol));
    const id=item.order+'/'+item.erasedSymbol;assert(!ids.has(id));ids.add(id);
    const pairs=traversals[item.order],skip=item.erasedSymbol===null?-1:item.erasedSymbol.charCodeAt(0)-97;
    assert.deepEqual(item.edges,pairs);
    const possible=Array(9).fill(0);let validCuts=0;
    // Fix vertex zero to parity zero: complementing every vertex changes no edge.
    for(let mask=0;mask<8192;mask++){
      cutsChecked++;const p=Array(9).fill(-1);let ok=true;
      for(let e=0;e<91;e++){
        const label=labels[e];if(label===skip)continue;
        const[a,b]=pairs[e],pa=a===0?0:(mask>>(a-1))&1,pb=b===0?0:(mask>>(b-1))&1,edge=pa^pb;
        if(p[label]===-1)p[label]=edge;else if(p[label]!==edge){ok=false;break;}
      }
      if(ok){validCuts++;p.forEach((v,i)=>{if(i!==skip){assert(v!==-1);possible[i]|=1<<v;}});}
    }
    assert.equal(validCuts,1);for(let s=0;s<9;s++)assert.equal(possible[s],s===skip?0:1);
    const expectedLabels=Array.from({length:9},(_,i)=>i).filter(i=>i!==skip);
    assert.deepEqual(item.certificates.map(c=>c.label),expectedLabels);
    assert.deepEqual(item.forcedEven,expectedLabels.map(i=>String.fromCharCode(97+i)));
    for(const cert of item.certificates){
      const degree=Array(14).fill(0),counts=Array(9).fill(0),unique=new Set();
      for(const e of cert.edgeIndices){
        assert(Number.isInteger(e)&&e>=0&&e<91&&!unique.has(e));unique.add(e);
        assert.notEqual(labels[e],skip);const[a,b]=pairs[e];degree[a]++;degree[b]++;counts[labels[e]]++;
      }
      assert(degree.every(d=>d%2===0));assert(counts.every((n,s)=>n%2===Number(s===cert.label)));certificatesChecked++;
    }
    // Check that no two vertices have equal labels to all other vertices.
    const grid=Array.from({length:14},()=>Array(14));pairs.forEach(([a,b],i)=>grid[a][b]=grid[b][a]=labels[i]);
    const twins=[];for(let a=0;a<14;a++)for(let b=a+1;b<14;b++){
      let equal=true;for(let c=0;c<14;c++)if(c!==a&&c!==b&&grid[a][c]!==grid[b][c]){equal=false;break;}
      if(equal)twins.push([a,b]);
    }
    assert.deepEqual(item.twins,twins);assert.equal(twins.length,0);
    assert.equal(item.rank,skip===-1?22:21);
    checks.push({order:item.order,erasedSymbol:item.erasedSymbol,vertexCuts:8192,compatibleCuts:validCuts,
      forcedEven:item.forcedEven,certificates:item.certificates.length});
  }
  assert.equal(ids.size,80);assert.equal(summary.cases,80);assert.equal(summary.certificates,certificatesChecked);
  assert.equal(summary.allNonErasedSymbolsForcedEven,true);assert.equal(summary.allOrdersHaveNoTwins,true);
  assert.equal(Array.from({length:9},(_,i)=>i+1).filter(n=>n%2===0).length,4);
  assert.equal(Array.from({length:18},(_,i)=>i).filter(n=>n>0&&n%2===0).length,8);
  assert.equal(Array.from({length:19},(_,i)=>i).filter(n=>n>0&&n%2===0).length,9);
  const result={verifiedAt:new Date().toISOString(),inputSHA256:hash(raw),casesSHA256:summary.casesSHA256,
    verifierSHA256:hash(fs.readFileSync(__filename)),cutsChecked,certificatesChecked,
    cases:checks.length,checks,independentCutEnumeration:true,aesTrials:0,finalPasswordFound:false};
  fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify({...result,checks:undefined},null,2));
}
if(require.main===module)main();
