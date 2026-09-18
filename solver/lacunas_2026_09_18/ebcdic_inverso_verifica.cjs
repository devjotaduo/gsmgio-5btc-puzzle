'use strict';
// Reconta, com o accepts() de solver/verify_ebcdic_codepoints.cjs (DP por fronteiras de palavra, independente
// do autômato do buscador), os casos aceitos de cada grupo da busca inversa. O main() do verificador recusa
// conjunto aceito não vazio; aqui a conferência é grupo a grupo, com a mesma tabela inversa da pré-carga.
//   node -r ./solver/lacunas_2026_09_18/ebcdic_inverso_patch.cjs solver/lacunas_2026_09_18/ebcdic_inverso_verifica.cjs
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const {accepts} = require('../verify_ebcdic_codepoints.cjs');
const root = path.resolve(__dirname, '..', '..');
const OUT = path.join(root, '_work', 'lacunas_2026-09-18', 'ebcdic_codepoints_inverso');
const input = JSON.parse(fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json')));
const saved = JSON.parse(fs.readFileSync(path.join(OUT, 'summary_completo.json')));

function permutacoes(fn, pre = [], usados = 0) {
  if (pre.length === 9) return fn(pre);
  for (let d = 1; d <= 9; d++) if (!(usados & (1 << d))) { pre.push(d); permutacoes(fn, pre, usados | 1 << d); pre.pop(); }
}
const porGrupo = {};
for (const a of saved.accepted) {
  const k = [a.family, a.field, a.reverse, a.aliases, a.padded].join('/');
  (porGrupo[k] ||= new Set()).add(a.mapping);
}
let casos = 0, aceitos = 0;
for (const g of saved.groups) {
  const k = [g.family, g.field, g.reverse, g.aliases, g.padded].join('/');
  const src = [...(g.reverse ? [...input[g.field]].reverse().join('') : input[g.field])].map(c => c.charCodeAt(0) - 97);
  const alias = [...g.aliases].reduce((m, c) => m | 1 << (c.charCodeAt(0) - 97), 0);
  const achados = new Set();
  let n = 0;
  const um = map => { n++; if (accepts(src, map, alias, g.padded)) achados.add(map.join('')); };
  if (g.family === 'fixed') um([1, 2, 3, 4, 5, 6, 7, 8, 9]); else permutacoes(um);
  assert.equal(n, g.cases, k);
  assert.deepEqual([...achados].sort(), [...(porGrupo[k] || [])].sort(), k);
  casos += n; aceitos += achados.size;
}
assert.equal(casos, saved.cases);
assert.equal(aceitos, saved.accepted.length);
const res = {conferido: true, casos, aceitos, grupos: saved.groups.length,
  metodo: 'accepts() de verify_ebcdic_codepoints.cjs (tabelas de 1–3 dígitos), mapeamentos aceitos iguais grupo a grupo'};
fs.writeFileSync(path.join(OUT, 'verificacao.json'), JSON.stringify(res, null, 1) + '\n');
console.log(JSON.stringify(res));
