'use strict';
// Conditional reading of the first image: primes are URL character values.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { open } = require('./decimal_keystream_constraints.cjs');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work/url_prime_reinsertion_2026-09-16');
const digest = b => crypto.createHash('sha256').update(b).digest();
const sha = b => digest(b).toString('hex');
function prime(n) {
  if (!Number.isInteger(n) || n < 2) return false;
  for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
  return true;
}
function derive(input) {
  const bits = input.spiral.map(([r, c]) => input.matrix[r][c]);
  assert.equal(bits.length, 196);
  assert.deepEqual(bits.slice(192), [0, 0, 0, 0]);
  const bytes = Buffer.from(Array.from({ length: 24 }, (_, i) => parseInt(bits.slice(i * 8, i * 8 + 8).join(''), 2)));
  assert.equal(bytes.toString(), 'gsmg.io/theseedisplanted');
  const cells = input.colored.map(([index, color, r, c], i) => {
    assert.equal(index, i * 8 + 7);
    assert.deepEqual(input.spiral[index], [r, c]);
    assert.equal(bytes[i] % 2, Number(color === 'B'));
    return { i, index, color, r, c, character: String.fromCharCode(bytes[i]), code: bytes[i], prime: prime(bytes[i]) };
  });
  const matrices = [], lists = [], materials = new Map();
  const suffixes = ['reinsertingtheprimebasicsafterwhichyouwillberequiredto', 'sheisgoingtodieandthereisnothingyoucandotostopit'];
  const add = (value, provenance) => {
    const hex = Buffer.from(value).toString('hex');
    if (!materials.has(hex)) materials.set(hex, { id: materials.size, hex, provenance });
  };
  for (const selection of ['prime', 'nonprime', 'all']) {
    const selected = cells.map(x => selection === 'all' || x.prime === (selection === 'prime'));
    add(Buffer.from(bytes.filter((_, i) => selected[i])), { selection, format: 'selected-url-characters' });
    add(Buffer.from(bytes.map((v, i) => selected[i] ? v : 0)), { selection, format: 'nul-masked-url' });
    for (const placement of ['byte-bits', 'coloured-code-bits-background', 'coloured-code-zero-background']) {
      const matrix = input.matrix.map(row => row.map(v => placement.endsWith('zero-background') ? 0 : v));
      if (placement === 'byte-bits') {
        input.spiral.forEach(([r, c], i) => { if (i < 192 && !selected[Math.floor(i / 8)]) matrix[r][c] = 0; });
      } else {
        for (const x of cells) matrix[x.r][x.c] = selected[x.i] ? x.code : 0;
      }
      const matrixId = matrices.length;
      matrices.push({ id: matrixId, selection, placement, matrix });
      const rows = matrix.map(row => row.reduce((a, b) => a + b, 0));
      const cols = matrix[0].map((_, c) => matrix.reduce((s, row) => s + row[c], 0));
      assert.equal(rows.reduce((a, b) => a + b, 0), cols.reduce((a, b) => a + b, 0));
      for (const [order, values] of [['rows', rows], ['columns', cols], ['rows-columns', [...rows, ...cols]], ['columns-rows', [...cols, ...rows]], ['interleaved', rows.flatMap((v, i) => [v, cols[i]])]]) {
        for (const reverse of [false, true]) {
          const list = reverse ? [...values].reverse() : values, id = lists.length;
          lists.push({ id, matrix: matrixId, order, reverse, values: list });
          for (const [format, text] of [['concatenated', list.join('')], ['comma', list.join(',')], ['space', list.join(' ')], ['newline', list.join('\n')], ['json', JSON.stringify(list)], ['bracket-spaces', '[' + list.join(', ') + ']']]) {
            add(text, { list: id, format, suffix: null });
            for (const [suffix, words] of suffixes.entries()) add(text + words, { list: id, format, suffix });
          }
        }
      }
    }
  }
  return { url: bytes.toString(), cells, suffixes, matrices, lists, materials: [...materials.values()] };
}
function main() {
  fs.mkdirSync(out, { recursive: true });
  assert(!fs.existsSync(path.join(out, 'oracles.json')), 'Inspect existing results before rerunning');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json'));
  const input = JSON.parse(inputRaw), data = derive(input);
  const spec = { hypothesis: 'Each coloured cell marks the final bit of one byte of the original URL. Interpret primes as the values of those ASCII bytes, not as their positions. Select prime-valued bytes, nonprime-valued bytes, or all bytes. Either zero the unselected original bytes in the bitmap, or replace each coloured cell with the selected ASCII value while other cells keep bits or become zero. Compute row/column lists. Nonprime/all are declared comparison alternatives, not creator instructions.', scope: 'Five list orders, reversal, six fixed formats; list alone or followed by one of two previously selected last-word clauses. Also filtered URL bytes and NUL-masked URL bytes. Direct and SHA256-hex passwords; EVP-SHA256/MD5 on three original blobs. SHA256 of each material and password as scalar, and complete 32-byte/64-hex plaintext only. No shifted positions, alternate URLs, arbitrary primes, new cipher layers or binary-window searches.', inputSHA256: sha(inputRaw), sourceSHA256: sha(fs.readFileSync(__filename)), helperSHA256: sha(fs.readFileSync(path.join(__dirname, 'decimal_keystream_constraints.cjs'))) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'derivation.json'), JSON.stringify(data, null, 2) + '\n');
  const ctrl = Buffer.from(input.phase32_control_b64, 'base64');
  assert.equal(sha(open(Buffer.from(input.phase32_control_password), { salt: ctrl.subarray(8, 16).toString('hex'), ciphertext: ctrl.subarray(16).toString('hex') }, 'sha256')), 'b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34');
  const passwords = new Map(), scalarSet = new Set(), padding = [], flags = [];
  for (const m of data.materials) {
    const bytes = Buffer.from(m.hex, 'hex');
    scalarSet.add(sha(bytes));
    for (const [form, b] of [['direct', bytes], ['sha256-hex', Buffer.from(sha(bytes))]]) {
      const hex = b.toString('hex');
      if (!passwords.has(hex)) passwords.set(hex, { id: passwords.size, material: m.id, form, hex });
    }
  }
  for (const pw of passwords.values()) {
    const b = Buffer.from(pw.hex, 'hex');
    scalarSet.add(sha(b));
    for (const [name, blob] of Object.entries(input.blobs)) for (const kdf of ['sha256', 'md5']) {
      const p = open(b, blob, kdf); flags.push(Number(p !== null));
      if (p === null) continue;
      const printable = [...p].filter(x => x >= 32 && x <= 126 || [9, 10, 13].includes(x)).length / p.length;
      padding.push({ password: pw.id, name, kdf, hex: p.toString('hex'), printable });
      if (p.length === 32) scalarSet.add(p.toString('hex'));
      if (/^[0-9a-fA-F]{64}$/.test(p.toString())) scalarSet.add(p.toString().toLowerCase());
    }
  }
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const scalars = [...scalarSet].filter(h => BigInt('0x' + h) > 0n && BigInt('0x' + h) < order).sort();
  const ec = crypto.createECDH('secp256k1'), matches = [];
  ec.setPrivateKey(Buffer.from('1'.padStart(64, '0'), 'hex'));
  assert.equal(ec.getPublicKey('hex', 'compressed'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(crypto.createHash('ripemd160').update(digest(Buffer.from(input.target_pubkey, 'hex'))).digest('hex'), input.target_h160);
  for (const h of scalars) {
    ec.setPrivateKey(Buffer.from(h, 'hex'));
    const pub = ec.getPublicKey('hex', 'uncompressed');
    if (pub.slice(2, 66) === input.target_pubkey.slice(2, 66)) matches.push({ scalar: h, exact: pub === input.target_pubkey });
  }
  const result = { complete: true, matrices: data.matrices.length, lists: data.lists.length, materials: data.materials.length, passwords: [...passwords.values()], attempts: flags.length, flags: Buffer.from(flags).toString('base64'), padding, scalars: scalars.length, scalarStreamSHA256: sha(Buffer.concat(scalars.map(h => Buffer.from(h, 'hex')))), matches, maxPrintable: Math.max(0, ...padding.map(x => x.printable)), sourceSHA256: spec.sourceSHA256, derivationSHA256: sha(fs.readFileSync(path.join(out, 'derivation.json'))) };
  fs.writeFileSync(path.join(out, 'oracles.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ ...result, passwords: passwords.size, flags: undefined, padding: padding.length }));
}
if (require.main === module) main();
module.exports = { prime, derive };
