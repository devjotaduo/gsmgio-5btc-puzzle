/* Reproduce X's recipe and audit all unit symbol mutations and colour swaps.
 * node solver/recipe_dependency_audit.cjs
 * Local data only. No passwords are inferred from the mutation controls.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'recipe_audit_2026-09-11');
const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
const input = JSON.parse(inputBytes);
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const names = ['base', 'blue', 'yellow'];
const markers = {base: [11, 'SENDTHE'], blue: [9, 'BLUE'], yellow: [11, 'TOSETHEX']};
const expected = {
  base: 'JLIQFOPGVBLSENDTHECZAGJJYDSWCGUDJNFTWB',
  blue: 'JLUPFLPGLBLUENETDICZAGAJQDSWCGUDONFHWB',
  yellow: 'OLIQUBROVQLTOSETHEXQYOJSSICJFGUDCCVBWQ',
};
const edges = [];
for (let i = 0; i < 14; i++) for (let j = i + 1; j < 14; j++) edges.push([i, j]);
const colors = input.colored.map(([,color,r,c]) => ({color, r, c, p: r * 14 + c + 1})).sort((a,b) => a.p - b.p);
const prime = n => n >= 2 && Array.from({length: Math.max(0, Math.floor(Math.sqrt(n)) - 1)}, (_,i) => i + 2).every(d => n % d);
const mod = (xs, m) => new Set(xs.map(x => (x - 1) % m + 1));
const edgeName = (r,c) => [r,c].sort((a,b) => a-b).join(',');
function settings(cells) {
  const bp = cells.filter(x => x.color === 'B').map(x => x.p);
  const yp = cells.filter(x => x.color === 'Y').map(x => x.p);
  return {rows: mod(bp,38), columns: mod(yp,15), values: mod(bp.filter(prime),9),
    yellowEdges: new Set(cells.filter(x => x.color === 'Y').map(x => edgeName(x.r,x.c)))};
}
const config = settings(colors);
function contribution(pos, value, cfg) {
  return cfg.rows.has(Math.floor(pos/15)+1) && cfg.columns.has(pos%15+1) && cfg.values.has(value) ? 0 : value;
}
function calculate(a,b,cfg) {
  const K = Array(14).fill(0), KY = Array(14).fill(0);
  [...a].forEach((ch,i) => {
    const v=ch.charCodeAt(0)-96, [r,c]=edges[i];
    K[r]+=v; K[c]+=v;
    if (!cfg.yellowEdges.has(edgeName(r,c))) { KY[r]+=v; KY[c]+=v; }
  });
  const R = Array(38).fill(0), RB = Array(38).fill(0);
  [...b].forEach((ch,i) => { const v=ch.charCodeAt(0)-96; R[Math.floor(i/15)]+=v; RB[Math.floor(i/15)]+=contribution(i,v,cfg); });
  const result = {};
  for (const name of names) {
    const sums = name === 'blue' ? RB : R, key = name === 'yellow' ? KY : K;
    const raw = sums.map((n,i) => n ^ key[i%14]);
    result[name] = {sums, key, raw, remainder: raw.map(n => n%26), text: String.fromCharCode(...raw.map(n => n%26+65))};
  }
  return result;
}
const base = calculate(input.dbbi,input.faed,config);
for (const name of names) assert.equal(base[name].text,expected[name]);
assert.equal(input.dbbi.length,91); assert.equal(input.faed.length,570);
assert.equal(input.matrix.flat().reduce((a,b)=>a+b,0),101);
assert.equal(colors.filter(x=>x.color==='B').length,15);
assert.equal(colors.filter(x=>x.color==='Y').length,9);
fs.mkdirSync(out,{recursive:true});
const save = (file, value) => fs.writeFileSync(path.join(out,file),JSON.stringify(value,null,2)+'\n');
save('spec.json',{
  sourceSHA256:sha(fs.readFileSync(__filename)),inputsSHA256:sha(inputBytes),
  originalSourceSHA256:sha(fs.readFileSync(path.join(root,'_work','endgame_review_2026-09-11','original_dbbi_sum_faed.py'))),
  alphabet:'abcdefghi',unitMutations:5288,colorSwaps:135,markers,
  scope:'All 661 positions changed to each other symbol, one position at a time. Every blue/yellow pair swapped. Recipe otherwise fixed. Marker scores are diagnostic, not a solution test.',
  indexing:'Saved input and output positions are 1-based; array entries are 0-based.',
});
save('baseline.json',base);
save('parameters.json',{
  blueRows:[...config.rows].sort((a,b)=>a-b),yellowColumns:[...config.columns].sort((a,b)=>a-b),
  primeBlueValues:[...config.values].sort((a,b)=>a-b),
  yellowCoordinates:colors.filter(x=>x.color==='Y'),
  zeroedDBBIEdges:edges.flatMap(([r,c],i)=>config.yellowEdges.has(edgeName(r,c))?[{position:i+1,r:r+1,c:c+1,symbol:input.dbbi[i]}]:[]),
  zeroedFAEDPositions:[...input.faed].flatMap((ch,i)=>contribution(i,ch.charCodeAt(0)-96,config)===0?[i+1]:[]),
});
function markerScore(result) {
  return names.reduce((score,name)=>{
    const [offset,word]=markers[name];
    return score+[...word].filter((ch,i)=>result[name].text[offset+i]===ch).length;
  },0);
}
const dependencies = names.flatMap(name => Array.from({length:38},(_,row)=>({
  rail:name,outputPosition:row+1,keyNode:row%14+1,
  dbbiPositions:edges.flatMap(([r,c],i)=>(r===row%14||c===row%14) && (name!=='yellow'||!config.yellowEdges.has(edgeName(r,c)))?[i+1]:[]),
  faedPositions:Array.from({length:15},(_,i)=>row*15+i+1),
  faedPotentialZeroColumns:name==='blue'&&config.rows.has(row+1)?[...config.columns].sort((a,b)=>a-b):[],
  R:base[name].sums[row],K:base[name].key[row%14],xor:base[name].raw[row],remainder:base[name].remainder[row],letter:base[name].text[row],
})));
save('dependencies.json',dependencies);
const mutations=[];
const stats={};
for (const field of ['dbbi','faed']) {
  const source=input[field];
  stats[field]={mutations:0,allRailsUnchanged:0,primaryMarkersUnchanged:0,rawChangesHiddenByMod26:0,
    perRail:Object.fromEntries(names.map(name=>[name,{changedMutations:0,changedOutputPositions:0}]))};
  for (let pos=0;pos<source.length;pos++) for (const replacement of 'abcdefghi') {
    if (source[pos]===replacement) continue;
    const modified=source.slice(0,pos)+replacement+source.slice(pos+1);
    const actual=calculate(field==='dbbi'?modified:input.dbbi,field==='faed'?modified:input.faed,config);
    const before=source.charCodeAt(pos)-96, after=replacement.charCodeAt(0)-96;
    const changes=[];
    for (const name of names) for (let row=0;row<38;row++) {
      let R=base[name].sums[row],K=base[name].key[row%14];
      if (field==='faed' && Math.floor(pos/15)===row) R+=name==='blue'?contribution(pos,after,config)-contribution(pos,before,config):after-before;
      if (field==='dbbi') {
        const [r,c]=edges[pos];
        if ((r===row%14||c===row%14) && (name!=='yellow'||!config.yellowEdges.has(edgeName(r,c)))) K+=after-before;
      }
      const raw=R^K;
      assert.equal(actual[name].sums[row],R); assert.equal(actual[name].key[row%14],K);
      assert.equal(actual[name].raw[row],raw); assert.equal(actual[name].text[row],String.fromCharCode(raw%26+65));
      if (R!==base[name].sums[row]||K!==base[name].key[row%14]) {
        changes.push({rail:name,position:row+1,R,K,raw,letter:actual[name].text[row],letterChanged:actual[name].text[row]!==base[name].text[row]});
        if (raw!==base[name].raw[row]&&raw%26===base[name].remainder[row]) stats[field].rawChangesHiddenByMod26++;
      }
    }
    const unchanged=names.every(name=>actual[name].text===base[name].text),score=markerScore(actual);
    stats[field].mutations++; stats[field].allRailsUnchanged+=Number(unchanged); stats[field].primaryMarkersUnchanged+=Number(score===19);
    for (const name of names) {
      const changed=[...actual[name].text].filter((ch,i)=>ch!==base[name].text[i]).length;
      stats[field].perRail[name].changedMutations+=Number(changed>0); stats[field].perRail[name].changedOutputPositions+=changed;
    }
    mutations.push({field,position:pos+1,original:source[pos],replacement,texts:Object.fromEntries(names.map(n=>[n,actual[n].text])),score,changes});
  }
}
assert.equal(mutations.length,5288);
fs.writeFileSync(path.join(out,'unit_mutations.jsonl'),mutations.map(x=>JSON.stringify(x)).join('\n')+'\n');
const swaps=[];
for (const blue of colors.filter(x=>x.color==='B')) for (const yellow of colors.filter(x=>x.color==='Y')) {
  const changedColors=colors.map(x=>({...x,color:x.p===blue.p?'Y':x.p===yellow.p?'B':x.color}));
  const result=calculate(input.dbbi,input.faed,settings(changedColors));
  assert.equal(result.base.text,base.base.text);
  swaps.push({bluePosition:blue.p,yellowPosition:yellow.p,score:markerScore(result),
    texts:Object.fromEntries(names.map(n=>[n,result[n].text])),allRailsUnchanged:names.every(n=>result[n].text===base[n].text)});
}
assert.equal(swaps.length,135);
save('color_swaps.json',swaps);
// A deliberately altered input with identical pre-modulo aggregates. These
// collisions demonstrate the compression of sums, not that the recipe is false.
const alteredFAED=[...input.faed];
for (let row=0;row<38;row++) for (const eligible of [false,true]) {
  const group=Array.from({length:15},(_,i)=>row*15+i).filter(i=>(config.rows.has(row+1)&&config.columns.has(i%15+1))===eligible);
  const reversed=group.map(i=>input.faed[i]).reverse();
  group.forEach((pos,i)=>{alteredFAED[pos]=reversed[i];});
}
const alteredDBBI=[...input.dbbi].map(ch=>ch.charCodeAt(0)-96);
const edgeIndex=new Map(edges.map(([r,c],i)=>[edgeName(r,c),i]));
let cycle=null;
outer:for (let a=0;a<14;a++) for(let b=a+1;b<14;b++) for(let c=b+1;c<14;c++) for(let d=c+1;d<14;d++) {
  const changes=[[a,b,1],[b,c,-1],[c,d,1],[d,a,-1]];
  if(changes.some(([r,c,delta])=>config.yellowEdges.has(edgeName(r,c))||alteredDBBI[edgeIndex.get(edgeName(r,c))]+delta<1||alteredDBBI[edgeIndex.get(edgeName(r,c))]+delta>9)) continue;
  cycle=changes.map(([r,c,delta])=>({r:r+1,c:c+1,position:edgeIndex.get(edgeName(r,c))+1,delta}));
  for(const {position,delta} of cycle) alteredDBBI[position-1]+=delta;
  break outer;
}
assert(cycle);
const collisionA=String.fromCharCode(...alteredDBBI.map(n=>n+96)),collisionB=alteredFAED.join('');
const collision=calculate(collisionA,collisionB,config);
assert.deepEqual(collision,base);
save('aggregate_collision.json',{dbbi:collisionA,faed:collisionB,dbbiCycle:cycle,
  changedDBBI:[...collisionA].filter((ch,i)=>ch!==input.dbbi[i]).length,
  changedFAED:[...collisionB].filter((ch,i)=>ch!==input.faed[i]).length,
  sameFullPreModuloState:true,scope:'Constructed input collision, not another solution or disproof of a sum-based recipe.'});
const markerColumns=Object.fromEntries(names.map(n=>[n,Array.from({length:markers[n][1].length},(_,i)=>markers[n][0]+i+1)]));
const covered=new Set(Object.values(markerColumns).flat());
const invisibleFAED=Array.from({length:570},(_,i)=>i+1).filter(i=>!covered.has(Math.floor((i-1)/15)+1));
const summary={expected,primaryMarkerScore:markerScore(base),stats,
  swaps:{tested:swaps.length,primaryMarkersUnchanged:swaps.filter(x=>x.score===19).length,allRailsUnchanged:swaps.filter(x=>x.allRailsUnchanged).length,maxScore:Math.max(...swaps.map(x=>x.score))},
  markerColumns,faedPositionsOutsideAllPrimaryMarkerRows:invisibleFAED.length,
  collision:{changedDBBI:4,changedFAED:[...collisionB].filter((ch,i)=>ch!==input.faed[i]).length,sameFullPreModuloState:true},
  analyticPredictionsChecked:mutations.length*38*3,
  interpretation:'All controls hold the published recipe fixed. Invariance of aggregates/markers measures information loss and is not evidence that a sum-based puzzle is invalid.'};
save('summary.json',summary);
console.log(JSON.stringify(summary,null,2));
