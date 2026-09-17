'use strict';
// Seven visible shape differences measured against Telegram #72118's stock image.
// They are observations, not evidence that the changes encode a password.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {open}=require('./decimal_keystream_constraints.cjs');
const root=path.resolve(__dirname,'..');
const out=path.resolve(process.argv[2]||path.join(root,'_work/prime_host_delta_2026-09-17/rabbit_delta'));
assert(!fs.existsSync(out),'Use a new output folder');fs.mkdirSync(out,{recursive:true});
const data=JSON.parse(fs.readFileSync(path.join(root,'_work/prime_geometry_2026-09-11/inputs.json')));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const save=(name,x)=>fs.writeFileSync(path.join(out,name),JSON.stringify(x,null,2)+'\n',{flag:'wx'});
// [glyph row, glyph column, stock bit, puzzle bit], black=1. Glyph origin: subcell (30,32).
const changes=[[6,12,0,1],[6,13,0,1],[7,12,1,0],[8,12,0,1],[9,8,0,1],[9,9,0,1],[9,12,1,0]];
assert.equal(new Set(changes.map(([r,c])=>`${r},${c}`)).size,7);
const materials=new Map();
function add(b,label){b=Buffer.isBuffer(b)?b:Buffer.from(String(b));if(!b.length)return;const h=b.toString('hex');if(!materials.has(h))materials.set(h,{id:materials.size,hex:h,provenance:label});}
function list(values,label){for(const reverse of [false,true]){const v=reverse?[...values].reverse():values,tag=label+(reverse?'/reversed':'');for(const sep of ['',' ',',','\n'])add(v.join(sep),tag+'/list');add(JSON.stringify(v),tag+'/json');if(v.every(n=>n>=0&&n<=255))add(Buffer.from(v),tag+'/bytes');}}
for(const origin of [0,1]){
 list(changes.flatMap(([r,c])=>[r+origin,c+origin]),'local-coordinates/'+origin);
 list(changes.flatMap(([r,c])=>[r+30+origin,c+32+origin]),'global-subcell-coordinates/'+origin);
 list(changes.map(([r,c])=>r*14+c+origin),'glyph-ranks/'+origin);
 list(changes.map(([r,c])=>(r+30)*70+c+32+origin),'global-subcell-ranks/'+origin);
 list(changes.map(([r,c])=>data.spiral.findIndex(([y,x])=>y===Math.floor((r+30)/5)&&x===Math.floor((c+32)/5))+origin),'spiral-parent-cells/'+origin);
}
for(const kind of ['xor','signed'])for(const crop of [false,true]){
 const rows=crop?4:13,cols=crop?6:14,y0=crop?6:0,x0=crop?8:0,g=Array.from({length:rows},()=>Array(cols).fill(0));
 for(const [r,c,before,after]of changes)g[r-y0][c-x0]=kind==='xor'?1:after-before;
 const label=kind+(crop?'/bounded4x6':'/glyph13x14');
 list(g.map(r=>r.reduce((a,b)=>a+b,0)),label+'/rows');
 list(Array.from({length:cols},(_,c)=>g.reduce((s,r)=>s+r[c],0)),label+'/columns');
 if(kind==='xor')for(const order of ['rows','columns'])for(const reverse of [false,true])for(const complement of [false,true]){
  let bits=(order==='rows'?g.flat():Array.from({length:cols},(_,c)=>g.map(r=>r[c])).flat()).map(v=>complement?1-v:v);
  if(reverse)bits.reverse();const s=bits.join(''),tag=label+`/${order}/${reverse}/${complement}`;add(s,tag+'/bits');
  const n=BigInt('0b'+s),h=n.toString(16);add(h,tag+'/hex');add(n.toString(),tag+'/integer');add(Buffer.from(h.padStart(Math.ceil(h.length/2)*2,'0'),'hex'),tag+'/minimal-bytes');
  for(const side of ['left','right']){
   const full=side==='left'?s.padStart(Math.ceil(s.length/8)*8,'0'):s.padEnd(Math.ceil(s.length/8)*8,'0');
   add(Buffer.from(full.match(/.{8}/g).map(b=>parseInt(b,2))),tag+'/packed-'+side);
  }
 }
}
save('spec.json',{sourceSHA256:sha(fs.readFileSync(__filename)),changes,source:{messageID:72118,date:'2026-09-17',author:'Boulayo',
 url:'https://www.shutterstock.com/image-vector/pixelated-bunny-8-bit-pixel-art-541878964',assetAuthor:'paramouse',catalogDate:'2016-12-23',
 referencePhotoSHA256:'5483649c1a9fd5a67f85d6ff963c38077aa7e2225c56f3dd16f6dd8ba0228b87',
 registration:{puzzleSubcellOrigin:[30,32],puzzlePitch:15,referenceBoxXYWH:[64,69,132,122],rows:13,cols:14},referenceSampleChecks:27},
 scope:'Seven visible differing subcells. XOR and signed difference, whole registered glyph or minimum bounding rectangle. Row/column sums, coordinates, indices, row/column bit reads, reversal, complement, integer/hex/bytes. Raw and SHA256-hex passwords, three original blobs, EVP-SHA256 and EVP-MD5.',
 limitations:'Reference is a Telegram JPEG, not a pristine vector/PNG. Only 144 cells with a known white puzzle background were compared; 38 hidden cells are unknown. No claim that these changes encode a message or establish FEFEFE origin.'});
save('materials.json',[...materials.values()]);
const ctrl=Buffer.from(data.phase32_control_b64,'base64');
assert.equal(sha(open(Buffer.from(data.phase32_control_password),{salt:ctrl.subarray(8,16).toString('hex'),ciphertext:ctrl.subarray(16).toString('hex')},'sha256')),'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
save('controls.json',{distinctChangedCells:7,phase32:true});
let attempts=0,maxPrintable=0;const padding=[],decisions=crypto.createHash('sha256'),semantic=[];
for(const m of materials.values())for(const form of ['direct','sha256-hex']){
 const raw=Buffer.from(m.hex,'hex'),pw=form==='direct'?raw:Buffer.from(sha(raw));
 for(const [blob,b]of Object.entries(data.blobs))for(const digest of ['sha256','md5']){
  const pt=open(pw,b,digest);attempts++;decisions.update([m.id,form,blob,digest,pt?pt.toString('hex'):'-'].join('|')+'\n');
  if(pt){const printable=[...pt].filter(b=>b>=32&&b<=126||[9,10,13].includes(b)).length/pt.length,rec={material:m.id,form,blob,digest,hex:pt.toString('hex'),printable};padding.push(rec);maxPrintable=Math.max(maxPrintable,printable);if(printable>=.85||pt.includes(Buffer.from('Salted__'))||pt.includes(Buffer.from('U2FsdGVk')))semantic.push(rec);}
 }
}
save('padding.json',padding);save('semantic_candidates.json',semantic);
const summary={visibleCellsCompared:144,hiddenCellsUnknown:38,visibleDifferences:7,materials:materials.size,passwordCases:materials.size*2,attempts,padding:padding.length,maxPrintable,semanticCandidates:semantic.length,decisionsSHA256:decisions.digest('hex')};save('summary.json',summary);console.log(JSON.stringify(summary,null,2));
