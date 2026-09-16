/* Necessary parity conditions for pairwise integer-coordinate distances.
 * All calculations are local and exact over GF(2). No guessed plaintext.
 */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work/dbbi_distance_parity_2026-09-16');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function orders(n){
  const row=[];for(let i=0;i<n;i++)for(let j=i+1;j<n;j++)row.push([i,j]);
  const result={row,column:[...row].sort((a,b)=>a[1]-b[1]||a[0]-b[0]),
    diagonal:[...row].sort((a,b)=>(a[1]-a[0])-(b[1]-b[0])||a[0]-b[0]),
    diagonalDescending:[...row].sort((a,b)=>(b[1]-b[0])-(a[1]-a[0])||a[0]-b[0])};
  for(const [name,pairs] of Object.entries(result))result[name+'/reversed']=[...pairs].reverse();
  return result;
}
function prove(n,pairs,labels,skip=null){
  const labelCount=Math.max(...labels)+1,columns=n+labelCount;
  assert(columns<31&&pairs.length===labels.length);
  const basis=Array(columns).fill(null);
  for(let index=0;index<pairs.length;index++){
    if(labels[index]===skip)continue;
    const [a,b]=pairs[index];let row=(1<<a)^(1<<b)^(1<<(n+labels[index])),witness=1n<<BigInt(index);
    for(let bit=columns-1;bit>=0;bit--)if(row&(1<<bit)){
      if(basis[bit]){row^=basis[bit].row;witness^=basis[bit].witness;}
      else{basis[bit]={row,witness};break;}
    }
  }
  const certificates=[];
  for(let label=0;label<labelCount;label++){
    if(label===skip)continue;
    let row=1<<(n+label),witness=0n;
    for(let bit=columns-1;bit>=0;bit--)if(row&(1<<bit)){
      if(!basis[bit])break;
      row^=basis[bit].row;witness^=basis[bit].witness;
    }
    if(row===0)certificates.push({label,edgeIndices:pairs.flatMap((_,i)=>witness&(1n<<BigInt(i))?[i]:[])});
  }
  return {rank:basis.filter(Boolean).length,certificates};
}
function checkCertificate(n,pairs,labels,cert,skip){
  let vertices=0,symbols=0;
  for(const i of cert.edgeIndices){assert.notEqual(labels[i],skip);const[a,b]=pairs[i];vertices^=(1<<a)^(1<<b);symbols^=1<<labels[i];}
  assert.equal(vertices,0);assert.equal(symbols,1<<cert.label);
}
function controls(){
  const triangle=[[0,1],[0,2],[1,2]];
  assert.deepEqual(prove(3,triangle,[0,0,0]).certificates,[{label:0,edgeIndices:[0,1,2]}]);
  assert.equal(prove(3,triangle,[0,1,2]).certificates.length,0);
  assert.equal(prove(3,triangle,[0,0,0],0).certificates.length,0);
  let planted=0,checkedCertificates=0;
  for(let seed=1;seed<=20;seed++){
    const vectors=Array.from({length:6},(_,i)=>Array.from({length:4},(_,j)=>(seed*(i+2)+j*j+3*i*j)%11));
    for(const kind of ['hamming','manhattan','squared']){
      const vs=kind==='hamming'?vectors.map(v=>v.map(x=>x%2)):vectors;
      const edges=orders(6).row,values=edges.map(([a,b])=>vs[a].reduce((sum,x,j)=>{
        const d=x-vs[b][j];return sum+(kind==='squared'?d*d:Math.abs(d));
      },0));
      const distinct=[...new Set(values)],labels=values.map(x=>distinct.indexOf(x));
      for(const skip of [null,0]){
        const proof=prove(6,edges,labels,skip);
        for(const cert of proof.certificates){checkCertificate(6,edges,labels,cert,skip);assert.equal(distinct[cert.label]%2,0);checkedCertificates++;}
        for(let e=0;e<edges.length;e++){
          const[a,b]=edges[e],pa=vs[a].reduce((a,b)=>a+b,0)%2,pb=vs[b].reduce((a,b)=>a+b,0)%2;
          assert.equal(values[e]%2,pa^pb);
        }
        planted++;
      }
    }
  }
  return {triangleControls:3,plantedIntegerMetrics:planted,validCertificatesOnControls:checkedCertificates};
}
function twins(n,pairs,labels){
  const grid=Array.from({length:n},()=>Array(n).fill(-1));pairs.forEach(([i,j],e)=>grid[i][j]=grid[j][i]=labels[e]);
  const result=[];for(let i=0;i<n;i++)for(let j=i+1;j<n;j++)if(grid[i].every((x,k)=>k===i||k===j||x===grid[j][k]))result.push([i,j]);
  return result;
}
function main(){
  fs.mkdirSync(out,{recursive:true});
  const raw=fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')),data=JSON.parse(raw),labels=[...data.dbbi].map(c=>c.charCodeAt(0)-97);
  assert.equal(labels.length,91);assert.equal(new Set(labels).size,9);
  const save=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
  save('spec.json',{createdAt:new Date().toISOString(),inputSHA256:sha(raw),sourceSHA256:sha(fs.readFileSync(__filename)),
    hypothesis:'DBBI is the 91 pairwise distances of 14 integer-coordinate vectors in one of eight listed triangular traversals. Any vertex permutation is allowed. Letter values may be permuted; one chosen letter may have arbitrary values per edge, including independent zero choices.',
    identities:['Integer L1: abs(a-b) mod 2 = (a+b) mod 2.','Squared Euclidean: (a-b)^2 mod 2 = (a+b) mod 2.','Binary Hamming is both of the preceding metrics. Integer coordinate weights preserve the parity identity.'],
    model:'For every non-erased edge (i,j) with symbol s: vertexParity[i] XOR vertexParity[j] XOR symbolParity[s] = 0.',
    scope:'Actual distance values represented by a fixed bijection a..i -> 1..9, with at most one symbol allowed arbitrary edge values. Separately, arbitrary injective integer labels for unweighted binary Hamming distance. No deletions, nonlinear relabeling preserving neither integers nor parity, general real-coordinate distances, odd-modulus reductions, or arbitrary reordering of 91 edges.',
    parityConsequence:'If eight non-erased letters are forced even, no bijection to 1..9 can satisfy them, since only four of those digits are even.'});
  const checked=controls(),cases=[];
  for(const[name,pairs]of Object.entries(orders(14))){
    const same=twins(14,pairs,labels);
    for(const skip of [null,...Array.from({length:9},(_,i)=>i)]){
      const proof=prove(14,pairs,labels,skip);
      for(const cert of proof.certificates)checkCertificate(14,pairs,labels,cert,skip);
      assert.equal(proof.certificates.length,skip===null?9:8);
      cases.push({order:name,erasedSymbol:skip===null?null:String.fromCharCode(97+skip),edges:pairs,
        twins:same,...proof,forcedEven:proof.certificates.map(c=>String.fromCharCode(97+c.label))});
    }
  }
  save('cases.json',cases);
  const summary={controls:checked,cases:cases.length,orders:8,certificates:cases.reduce((n,c)=>n+c.certificates.length,0),
    allNonErasedSymbolsForcedEven:cases.every(c=>c.forcedEven.length===(c.erasedSymbol===null?9:8)),
    allOrdersHaveNoTwins:cases.every(c=>c.twins.length===0),
    consequences:{digitBijection1to9Impossible:true,oneArbitrarySymbolStillImpossible:true,
      hammingAnyInjectiveLabelsMinimumDimensionWithoutErasure:18},
    casesSHA256:sha(fs.readFileSync(path.join(out,'cases.json'))),aesTrials:0,finalPasswordFound:false};
  save('summary.json',summary);console.log(JSON.stringify(summary,null,2));
}
if(require.main===module)main();
module.exports={prove};
