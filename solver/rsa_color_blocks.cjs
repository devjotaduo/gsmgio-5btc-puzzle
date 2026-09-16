'use strict';
// Textbook modular-power character codes; not a padded PKCS#1 implementation.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),out=path.join(root,'_work','rsa_color_blocks_2026-09-16'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const inputRaw=fs.readFileSync(path.join(root,'_work','prime_geometry_2026-09-11','inputs.json')),input=JSON.parse(inputRaw),alphabet='abcdefghi';
const allowed=[9,10,13,...Array.from({length:95},(_,i)=>i+32)],letters=m=>m===32||m>=65&&m<=90||m>=97&&m<=122;
function gcd(a,b){while(b)[a,b]=[b,a%b];return a;}
function factor(n){const result=[];for(let p=2;p*p<=n;p++)while(n%p===0){result.push(p);n/=p;}if(n>1)result.push(n);return result;}
function pow(a,e,n){let x=1;while(e){if(e%2)x=x*a%n;a=a*a%n;e=Math.floor(e/2);}return x;}
const blue=0x3f48cc,yellow=0xfff200,blueFactors=factor(blue),yellowFactors=factor(yellow),moduli=[];
for(const p of [...new Set(blueFactors)])for(const q of [...new Set(yellowFactors)])if(p!==q){const lambda=(p-1)*(q-1)/gcd(p-1,q-1);moduli.push({p,q,n:p*q,lambda,unitExponents:Array.from({length:lambda-1},(_,i)=>i+1).filter(e=>gcd(e,lambda)===1)});}
const aliasSets=['',...alphabet];for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)aliasSets.push(alphabet[i]+alphabet[j]);
const models=[];for(const field of ['dbbi','faed'])for(const reverse of [false,true])for(const aliases of aliasSets)for(const format of ['minimal','padded'])models.push({field,reverse,aliases,format});
function graphs(source,aliases,n){
  const width=String(n-1).length,mask=[...aliases].reduce((v,c)=>v|(1<<(c.charCodeAt(0)-97)),0),minimal=[],padded=[],hm=[0],hp=[0];
  for(let at=0;at<source.length;at++){
    let states=[{v:0,zero:false}];
    for(let len=1;len<=width&&at+len<=source.length;len++){
      const idx=source.charCodeAt(at+len-1)-97,ds=mask>>idx&1?[idx+1,0]:[idx+1],next=[];
      for(const state of states)for(const digit of ds){const value=state.v*10+digit;if(value>=n)continue;const zero=state.zero||len===1&&digit===0;next.push({v:value,zero});if(value>0){if(!zero)minimal.push(at+len,value);if(len===width)padded.push(at+len,value);}}
      states=next;if(!states.length)break;
    }
    hm.push(minimal.length);hp.push(padded.length);
  }
  return {width,minimal:{edges:Uint32Array.from(minimal),heads:Uint32Array.from(hm)},padded:{edges:Uint32Array.from(padded),heads:Uint32Array.from(hp)}};
}
function workspace(length){return {all:Array(length+1).fill(0n),print:Array(length+1).fill(0n),letter:Array(length+1).fill(0n),min:new Uint16Array(length+1),max:new Uint16Array(length+1),parent:new Uint16Array(length+1),byte:new Uint8Array(length+1),parentLetter:new Uint16Array(length+1),byteLetter:new Uint8Array(length+1)};}
function parse(graph,length,stamp,decode,tag,w){
  const touched=[0];w.all[0]=w.print[0]=w.letter[0]=1n;w.min[0]=w.max[0]=0;let furthest=0;
  for(let at=0;at<=furthest&&at<length;at++)if(w.all[at])for(let edge=graph.heads[at];edge<graph.heads[at+1];edge+=2){
    const end=graph.edges[edge],v=graph.edges[edge+1];if(stamp[v]!==tag)continue;const m=decode[v];
    if(w.all[end]===0n){touched.push(end);w.min[end]=w.min[at]+1;w.max[end]=w.max[at]+1;w.parent[end]=at;w.byte[end]=m;}else {w.min[end]=Math.min(w.min[end],w.min[at]+1);w.max[end]=Math.max(w.max[end],w.max[at]+1);}
    w.all[end]+=w.all[at];if(m>=32)w.print[end]+=w.print[at];if(letters(m)&&w.letter[at]){if(!w.letter[end]){w.parentLetter[end]=at;w.byteLetter[end]=m;}w.letter[end]+=w.letter[at];}if(end>furthest)furthest=end;
  }
  let result=null;if(w.all[length]){
    function witness(letter){const a=[];let at=length;while(at){a.push(letter?w.byteLetter[at]:w.byte[at]);at=letter?w.parentLetter[at]:w.parent[at];}return Buffer.from(a.reverse()).toString('hex');}
    result={pathsAscii:String(w.all[length]),pathsPrintable:String(w.print[length]),pathsLettersSpace:String(w.letter[length]),minBytes:w.min[length],maxBytes:w.max[length],witnessHex:witness(false),letterWitnessHex:w.letter[length]?witness(true):null};
  }
  for(const at of touched)w.all[at]=w.print[at]=w.letter[at]=0n;return result;
}
function controls(){
  let plants=0,exhaustive=0;
  for(const [p,q]of [[3,181],[37,181],[9341,181]])for(const aliases of ['g','be'])for(const format of ['minimal','padded']){
    const n=p*q,e=65537,width=String(n-1).length,message=Buffer.from('MATRIXSUM LIST'),numbers=[...message].map(m=>pow(m,e,n)),digits=numbers.map(v=>format==='padded'?String(v).padStart(width,'0'):String(v)).join('');let zero=0;const source=[...digits].map(d=>d==='0'?aliases[zero++%aliases.length]:alphabet[+d-1]).join(''),g=graphs(source,aliases,n),stamp=new Uint32Array(n),decode=new Uint8Array(n);
    for(const m of allowed.filter(m=>m<n)){const c=pow(m,e,n);stamp[c]=1;decode[c]=m;}
    const result=parse(g[format],source.length,stamp,decode,1,workspace(source.length));assert(result&&BigInt(result.pathsLettersSpace)>0n);let at=0;for(let i=0;i<numbers.length;i++){const word=format==='padded'?String(numbers[i]).padStart(width,'0'):String(numbers[i]);assert([...word].every((d,j)=>d==='0'?aliases.includes(source[at+j]):alphabet[+d-1]===source[at+j]));at+=word.length;}assert.equal(at,source.length);plants++;
  }
  // Exhaust every zero mask and literal decimal-word segmentation for short inputs.
  for(const source of ['abc','ggb','bdgg','fbab'])for(const aliases of ['','g','bg'])for(const format of ['minimal','padded']){
    const n=3*181,e=17,width=String(n-1).length,book=new Map(allowed.map(m=>[pow(m,e,n),m])),positions=[...source].flatMap((c,i)=>aliases.includes(c)?[i]:[]);let all=0n,print=0n,letter=0n;
    for(let mask=0;mask<2**positions.length;mask++){const ds=[...source].map(c=>String(c.charCodeAt(0)-96));positions.forEach((p,i)=>{if(mask>>i&1)ds[p]='0';});const digits=ds.join('');function visit(at,printable,alpha){if(at===digits.length){all++;if(printable)print++;if(alpha)letter++;return;}for(let end=at+1;end<=Math.min(at+width,digits.length);end++){const word=digits.slice(at,end);if(format==='padded'?word.length!==width:word.length>1&&word[0]==='0')continue;const m=book.get(+word);if(m!==undefined)visit(end,printable&&m>=32,alpha&&letters(m));}}visit(0,true,true);}
    const stamp=new Uint32Array(n),decode=new Uint8Array(n);for(const [c,m]of book){stamp[c]=1;decode[c]=m;}const g=graphs(source,aliases,n),r=parse(g[format],source.length,stamp,decode,1,workspace(source.length));assert.equal(r?.pathsAscii||'0',String(all));assert.equal(r?.pathsPrintable||'0',String(print));assert.equal(r?.pathsLettersSpace||'0',String(letter));exhaustive++;
  }
  return {planted:plants,exhaustiveMaskAndSegmentationCases:exhaustive};
}
function main(){
  fs.mkdirSync(out,{recursive:true});assert(!fs.existsSync(path.join(out,'valid.jsonl'))&&!fs.existsSync(path.join(out,'flags.bin')),'Existing results: inspect before rerunning');const checked=controls(),spec={scope:'Per-character modular exponentiation c=m^e mod p*q. Distinct prime factors p of blue RGB and q of yellow RGB; all exponent classes coprime to lambda. ASCII TAB/LF/CR/32..126 with m<n. Cipher integers concatenated in minimal decimal or padded to digits(n-1). a..i=1..9, with zero/one/two chosen letters optionally representing 0. Both full fields and source directions. Includes p=2 and exponent class 1 as explicit relaxations beyond standard RSA; no OAEP/PKCS padding, multiple plaintext bytes per block, digit permutation or leading/trailing removal.',blue:{hex:'3f48cc',value:blue,factors:blueFactors},yellow:{hex:'fff200',value:yellow,factors:yellowFactors},moduli:moduli.map(({unitExponents,...m})=>({...m,exponentClasses:unitExponents.length})),models,allowed,controls:checked,inputSHA256:sha(inputRaw),sourceSHA256:sha(fs.readFileSync(__filename)),reference:'https://www.rfc-editor.org/rfc/rfc8017.html',flags:'Key order: moduli as listed, exponent classes ascending; then models in listed order. Bit 0 ASCII path exists, bit 1 fully printable path exists, bit 2 letters/space path exists.'};
  fs.writeFileSync(path.join(out,'spec.json'),JSON.stringify(spec,null,2)+'\n');fs.writeFileSync(path.join(out,'valid.jsonl'),'');const totalKeys=moduli.reduce((s,m)=>s+m.unitExponents.length,0),flags=Buffer.alloc(totalKeys*models.length),codeHash=crypto.createHash('sha256'),groups=[];let keyIndex=0,flagOffset=0,valid=0,printable=0,letter=0;const start=Date.now(),work=new Map();
  for(const modulus of moduli){
    const {p,q,n,lambda}=modulus,width=String(n-1).length,bytes=allowed.filter(m=>m<n),current=bytes.slice(),stamp=new Uint32Array(n),decode=new Uint8Array(n),cache=new Map(),prepared=models.map(m=>{const id=[m.field,m.reverse,m.aliases].join('/'),source=m.reverse?[...input[m.field]].reverse().join(''):input[m.field];if(!cache.has(id))cache.set(id,graphs(source,m.aliases,n));if(!work.has(source.length))work.set(source.length,workspace(source.length));return {source,graph:cache.get(id)[m.format],width};});let groupValid=0,groupPrint=0,groupLetter=0,keys=0;
    for(let e=1;e<lambda;e++){
      if(gcd(e,lambda)===1){
        const tag=e+1,hashBytes=Buffer.alloc(8+bytes.length*5);hashBytes.writeUInt32LE(n,0);hashBytes.writeUInt32LE(e,4);for(let i=0;i<bytes.length;i++){stamp[current[i]]=tag;decode[current[i]]=bytes[i];hashBytes[8+5*i]=bytes[i];hashBytes.writeUInt32LE(current[i],9+5*i);}codeHash.update(hashBytes);
        for(let modelIndex=0;modelIndex<models.length;modelIndex++){
          const model=models[modelIndex],{source,graph}=prepared[modelIndex];let r=null;if(model.format!=='padded'||source.length%width===0)r=parse(graph,source.length,stamp,decode,tag,work.get(source.length));
          if(r){const fp=BigInt(r.pathsPrintable)>0n,fl=BigInt(r.pathsLettersSpace)>0n;flags[flagOffset]=1+2*Number(fp)+4*Number(fl);valid++;groupValid++;printable+=Number(fp);groupPrint+=Number(fp);letter+=Number(fl);groupLetter+=Number(fl);fs.appendFileSync(path.join(out,'valid.jsonl'),JSON.stringify({keyIndex,modelIndex,p,q,n,lambda,e,...model,...r})+'\n');}flagOffset++;
        }
        keyIndex++;keys++;
      }
      for(let i=0;i<current.length;i++)current[i]=current[i]*bytes[i]%n;
    }
    const group={p,q,n,lambda,keys,models:keys*models.length,valid:groupValid,printable:groupPrint,lettersSpace:groupLetter};groups.push(group);console.log(JSON.stringify({...group,elapsedMs:Date.now()-start}));
  }
  assert.equal(keyIndex,totalKeys);assert.equal(flagOffset,flags.length);fs.writeFileSync(path.join(out,'flags.bin'),flags);const summary={complete:true,keys:keyIndex,models:flags.length,valid,printable,lettersSpace:letter,groups,codebooksSHA256:codeHash.digest('hex'),flagsSHA256:sha(flags),validSHA256:sha(fs.readFileSync(path.join(out,'valid.jsonl'))),elapsedMs:Date.now()-start};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}
if(require.main===module)main();module.exports={graphs,parse,workspace,pow,allowed};
