'use strict';
// F3 sem_zero_integral — cobre TODOS os caminhos de decodificação (não só o melhor) para os
// modelos "codigos ASCII decimais com zeros apagados" que sao compativeis com DBBI (ENDGAME.md
// tabela 4-B: "192.969 modelos compatíveis e só o melhor caminho de cada foi testado").
//
// Reusa machine()/eachPermutation() de solver/zero_free_numerals.cjs (já testado com self-tests
// no script original) para a parte de aceitação/DFA. A parte de contagem exata por comprimento e
// materialização de caminhos é nova (o script original só media aceitação booleana e contagem
// total via BigInt; aqui precisamos do comprimento EXATO de cada caminho, para poder testar como
// senha/escalar de tamanho fixo sem enumerar os ~10^20 caminhos totais).
//
// Encoding CP1141 fica DE FORA: o arquivo _work/ebcdic_decimal_2026-09-16/encoding.json (tabela
// EBCDIC decodificada usada pelo script original) nao existe neste clone. Isso cobre 9 dos
// 192.969 modelos relatados (78.480 ASCII fwd + 114.480 ASCII rev + 9 CP1141 rev = 192.969).
// Rodamos os 192.960 modelos ASCII (99,995% do total) e declaramos os 9 CP1141 como fora de
// escopo por falta de insumo.

const fs = require('node:fs'), path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const zf = require(path.join(root, 'solver/zero_free_numerals.cjs'));
const { eachPermutation, machine } = zf;

const outDir = path.resolve(__dirname, '../../../_work/enxame_2026-09-19/sem_zero_integral');
fs.mkdirSync(outDir, { recursive: true });

const data = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')));
const dbbiText = data.dbbi;
if (dbbiText.length !== 91) throw new Error('dbbi length changed');

const fields = [
  { field: 'dbbi', reverse: false, text: dbbiText },
  { field: 'dbbi', reverse: true, text: [...dbbiText].reverse().join('') },
];
for (const f of fields) f.source = [...f.text].map(c => c.charCodeAt(0) - 97);

// --- Modelos ASCII (encoding.value === codepoint) -------------------------------------------
const REPERTOIRES = ['lower-space', 'upper-space', 'printable-controls'];
function buildModel(repertoire) {
  const allowed = Array.from({ length: 128 }, (_, m) => m).filter(m =>
    repertoire === 'lower-space' ? (m === 32 || (m >= 97 && m <= 122)) :
    repertoire === 'upper-space' ? (m === 32 || (m >= 65 && m <= 90)) :
    ((m >= 32 && m <= 126) || [9, 10, 13].includes(m)));
  const codes = allowed.map(m => ({ m, value: m }));
  codes.forEach(c => { c.word = String(c.value).replaceAll('0', ''); });
  if (!codes.every(c => /^[1-9]+$/.test(c.word))) throw new Error('bad word ' + repertoire);
  // words por comprimento, para o DP rapido de comprimento exato (sem varrer os ~95 codigos a
  // cada posicao: so os que tem o comprimento certo).
  const byLen = { 1: new Map(), 2: new Map(), 3: new Map() };
  let maxLen = 0;
  for (const c of codes) {
    const L = c.word.length; maxLen = Math.max(maxLen, L);
    if (!byLen[L]) byLen[L] = new Map();
    byLen[L].set(c.word, c.m); // word -> emitted byte (m). words sao unicos por construcao (m unico -> value unico -> string unica ainda que zeros removidos possam colidir entre CODES DIFERENTES; ver nota abaixo)
  }
  return { repertoire, encoding: 'ASCII', machine: machine(codes), byLen, maxLen, codes };
}
// Nota sobre colisao de 'word': e.g. m=1 -> "1" e m=10->"1" (zero removido) tambem dao "1".
// Isso e EXATAMENTE a ambiguidade que o automato machine() trata (varios m podem compartilhar o
// mesmo word). Para a materializacao de texto, quando um word colide entre varios m diferentes,
// cada ocorrencia desse word no caminho pode ter vindo de qualquer um desses m -- isso multiplica
// o numero de "leituras byte" por caminho de segmentacao. Registramos essa multiplicidade
// explicitamente (campo 'alts') em vez de fixar arbitrariamente um m.
function buildByLenWithAlts(codes) {
  const byLen = { 1: new Map(), 2: new Map(), 3: new Map() };
  for (const c of codes) {
    const L = c.word.length;
    if (!byLen[L].has(c.word)) byLen[L].set(c.word, []);
    byLen[L].get(c.word).push(c.m);
  }
  return byLen;
}

const models = REPERTOIRES.map(r => {
  const m = buildModel(r);
  m.byLenAlts = buildByLenWithAlts(m.codes);
  return m;
});

// --- Fase 1: aceitacao para TODAS as 362.880 permutacoes, para os 3 modelos x 2 direcoes -------
// (reproduz e estende o zero_free_numerals.cjs original, restrito a ASCII x DBBI, para conferir
// os totais 78.480 fwd + 114.480 rev = 192.960 contra o relatorio historico.)
const compatible = []; // {modelIdx, fieldIdx, mapping:[9], rank}
let counts = models.map(() => fields.map(() => 0));
const t0 = Date.now();
eachPermutation((mapping) => {
  for (let mi = 0; mi < models.length; mi++) {
    for (let fi = 0; fi < fields.length; fi++) {
      if (models[mi].machine.accepts(fields[fi].source, mapping)) {
        counts[mi][fi]++;
        compatible.push({ mi, fi, mapping: mapping.slice() });
      }
    }
  }
});
const fwdTotal = models.reduce((s, _, mi) => s + counts[mi][0], 0);
const revTotal = models.reduce((s, _, mi) => s + counts[mi][1], 0);
console.error(JSON.stringify({ phase: 1, fwdTotal, revTotal, sum: fwdTotal + revTotal, elapsedMs: Date.now() - t0 }));

// --- Fase 2: para cada combo compativel, DP de comprimentos alcancaveis (existencia exata) -----
// reach = BigInt bitmask sobre posicao 0 (digito consumido) -> conjunto de comprimentos emitidos
// possiveis para chegar aquela posicao. Ao final (pos=91) da os comprimentos de caminho COMPLETO
// possiveis. Isto decide EXISTENCIA para TODOS os caminhos sem enumera-los (mesma ideia do teste
// de limiar exato por DP do a1z26, aplicada a "comprimento" em vez de "escore").
const TARGET_LENS = [32, 51, 52, 64]; // 32 = escalar cru de 32B; 51/52 = WIF ASCII; 64 = hex64/senha longa
const digitsCache = new Map(); // mapping.join('') + field -> digits string

function digitsFor(mapping, fi) {
  const src = fields[fi].source;
  let s = '';
  for (const sym of src) s += mapping[sym];
  return s;
}

function reachableLengths(model, digits) {
  const n = digits.length;
  // reach[pos] : BigInt bitmask (bit e => comprimento emitido e alcanca posicao pos)
  const reach = new Array(n + 1).fill(0n);
  reach[0] = 1n; // bit 0
  const byLen = model.byLenAlts;
  for (let pos = 0; pos < n; pos++) {
    if (reach[pos] === 0n) continue;
    const shifted = reach[pos] << 1n; // soma 1 ao comprimento emitido
    for (let L = 1; L <= 3; L++) {
      if (pos + L > n) continue;
      const w = digits.substr(pos, L);
      if (byLen[L].has(w)) reach[pos + L] |= shifted;
    }
  }
  return reach[n];
}

let existAt = TARGET_LENS.map(() => 0);
const hitsPerLength = TARGET_LENS.map(() => []); // {mi, fi, mapping, len}
let processed = 0;
const t1 = Date.now();
for (const c of compatible) {
  const digits = digitsFor(c.mapping, c.fi);
  const mask = reachableLengths(models[c.mi], digits);
  for (let li = 0; li < TARGET_LENS.length; li++) {
    const L = TARGET_LENS[li];
    if ((mask >> BigInt(L)) & 1n) {
      existAt[li]++;
      hitsPerLength[li].push({ mi: c.mi, fi: c.fi, mapping: c.mapping, digits });
    }
  }
  processed++;
  if (processed % 20000 === 0) console.error(JSON.stringify({ phase: 2, processed, of: compatible.length, elapsedMs: Date.now() - t1 }));
}
console.error(JSON.stringify({ phase: 2, done: true, processed, existAt, elapsedMs: Date.now() - t1 }));

// --- Fase 3: para os combos com existencia em um comprimento-alvo, contar EXATO e materializar --
// se a contagem exata <= CAP, enumerar TODOS os caminhos (DP reverso + DFS guiado, sem sorte:
// cada aresta so e tomada se leva a pelo menos 1 solucao completa). Caso contrario, declarar a
// contagem exata sem materializar (fracao nao coberta, declarada, nunca amostrada como exaustao).
const CAP_PER_COMBO = 4000;       // materializacao completa por combo
const GLOBAL_CAP = 400000;        // teto de candidatos totais materializados (orcamento de tempo)
let globalMaterialized = 0;

function countAndEnumerate(model, digits, Ltarget) {
  const n = digits.length;
  const byLen = model.byLenAlts;
  // ways[pos][e] = numero de caminhos de (pos,e) ate (n, Ltarget)
  const ways = Array.from({ length: n + 1 }, () => new Array(Ltarget + 1).fill(0n));
  ways[n][Ltarget] = 1n;
  const edgesAt = Array.from({ length: n }, () => []); // {L, word}
  for (let pos = n - 1; pos >= 0; pos--) {
    for (let L = 1; L <= 3; L++) {
      if (pos + L > n) continue;
      const w = digits.substr(pos, L);
      if (!byLen[L].has(w)) continue;
      edgesAt[pos].push({ L, word: w });
    }
    for (let e = 0; e <= Ltarget; e++) {
      let total = 0n;
      if (e < Ltarget) {
        for (const ed of edgesAt[pos]) total += ways[pos + ed.L][e + 1];
      }
      ways[pos][e] = total;
    }
  }
  const total = ways[0][0];
  return { total, ways, edgesAt };
}

function enumerateAll(model, digits, Ltarget, ways, edgesAt, limit) {
  const n = digits.length;
  const byLen = model.byLenAlts;
  const results = []; // arrays of m-sequences (Buffer-ables); cada posicao pode ter ALTS (varios m para o mesmo word)
  function dfs(pos, e, chosen) {
    if (results.length >= limit) return;
    if (pos === n) { if (e === Ltarget) results.push(chosen.slice()); return; }
    for (const ed of edgesAt[pos]) {
      if (e + 1 > Ltarget) continue;
      if (ways[pos + ed.L][e + 1] === 0n) continue;
      const alts = byLen[ed.L].get(ed.word);
      chosen.push(alts); // guarda TODAS as alternativas de byte para este passo
      dfs(pos + ed.L, e + 1, chosen);
      chosen.pop();
      if (results.length >= limit) return;
    }
  }
  dfs(0, 0, []);
  return results;
}

const materializedFile = path.join(outDir, 'candidates.jsonl');
fs.writeFileSync(materializedFile, '');
const fd = fs.openSync(materializedFile, 'a');
const summaryPerLen = TARGET_LENS.map(L => ({ L, combosWithExistence: 0, combosMaterializedFully: 0, combosDeclaredOnly: 0, exactTotalPathsMaterializedCombos: '0', exactTotalPathsDeclaredOnly: '0', candidatesWritten: 0 }));

const t3 = Date.now();
let phase3Processed = 0;
for (let li = 0; li < TARGET_LENS.length; li++) {
  const L = TARGET_LENS[li];
  const combos = hitsPerLength[li];
  summaryPerLen[li].combosWithExistence = combos.length;
  let sumMat = 0n, sumDecl = 0n;
  for (const c of combos) {
    phase3Processed++;
    if (phase3Processed % 5000 === 0) console.error(JSON.stringify({ phase: 3, phase3Processed, L, globalMaterialized, elapsedMs: Date.now() - t3 }));
    if (globalMaterialized >= GLOBAL_CAP) {
      // orcamento global esgotado: so contamos exatamente, nao materializamos mais
      const { total } = countAndEnumerate(models[c.mi], c.digits, L);
      sumDecl += total; summaryPerLen[li].combosDeclaredOnly++;
      continue;
    }
    const { total, ways, edgesAt } = countAndEnumerate(models[c.mi], c.digits, L);
    if (total <= BigInt(CAP_PER_COMBO)) {
      const seqs = enumerateAll(models[c.mi], c.digits, L, ways, edgesAt, CAP_PER_COMBO + 1);
      // seqs[i] = array de 'alts' (arrays de m possiveis) por posicao emitida; expandir produto
      // cartesiano SO se pequeno (colisao de word rara); caso contrario cada alt vira um candidato
      // com o primeiro m de cada posicao registrado + contagem de alternativas.
      for (const seq of seqs) {
        const anyMulti = seq.some(a => a.length > 1);
        if (!anyMulti) {
          const bytes = Buffer.from(seq.map(a => a[0]));
          fs.writeSync(fd, JSON.stringify({ model: models[c.mi].repertoire, field: fields[c.fi].field, reverse: fields[c.fi].reverse, mapping: c.mapping.join(''), len: L, hex: bytes.toString('hex') }) + '\n');
          globalMaterialized++; summaryPerLen[li].candidatesWritten++;
        } else {
          // expande produto cartesiano das colisoes (largura limitada a 64 variantes POR POSICAO;
          // o cap trunca a LARGURA, nunca pula posicoes -- bug anterior corrigido em 2026-09-19:
          // um `break` fora dos loops internos cortava as posicoes restantes de `seq`, produzindo
          // candidatos truncados com menos de Ltarget bytes. Corrigido: o `break` so encerra os
          // loops internos (largura desta posicao); o loop externo sobre `seq` sempre percorre
          // TODAS as posicoes, entao todo candidato final tem exatamente Ltarget bytes.
          let combosOut = [[]];
          for (const a of seq) {
            const next = [];
            outer: for (const prefix of combosOut) {
              for (const alt of a) {
                next.push(prefix.concat([alt]));
                if (next.length >= 64) break outer;
              }
            }
            combosOut = next;
          }
          for (const bytesArr of combosOut) {
            const bytes = Buffer.from(bytesArr);
            fs.writeSync(fd, JSON.stringify({ model: models[c.mi].repertoire, field: fields[c.fi].field, reverse: fields[c.fi].reverse, mapping: c.mapping.join(''), len: L, hex: bytes.toString('hex'), fromCollision: true }) + '\n');
            globalMaterialized++; summaryPerLen[li].candidatesWritten++;
          }
        }
      }
      summaryPerLen[li].combosMaterializedFully++;
      sumMat += total;
    } else {
      summaryPerLen[li].combosDeclaredOnly++;
      sumDecl += total;
    }
  }
  summaryPerLen[li].exactTotalPathsMaterializedCombos = sumMat.toString();
  summaryPerLen[li].exactTotalPathsDeclaredOnly = sumDecl.toString();
}
fs.closeSync(fd);

const summary = {
  ascii_compatible_combos: compatible.length,
  fwdTotal, revTotal,
  cp1141_out_of_scope: 9,
  reported_total_192969: fwdTotal + revTotal + 9,
  targetLengths: TARGET_LENS,
  perLength: summaryPerLen,
  globalMaterialized,
  GLOBAL_CAP, CAP_PER_COMBO,
};
fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify(summary, null, 2));
