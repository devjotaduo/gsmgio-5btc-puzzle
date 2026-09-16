'use strict';
// Read-only audit of the preserved Decentraland MP3, not a general MP3 decoder.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
const sha = data => crypto.createHash('sha256').update(data).digest('hex');

function id3v22(data) {
  assert(data.length >= 10 && data.subarray(0, 3).toString() === 'ID3');
  assert.equal(data[3], 2); assert.equal(data[4], 0); assert.equal(data[5], 0);
  assert(data.subarray(6, 10).every(b => b < 128));
  const end = 10 + [...data.subarray(6, 10)].reduce((n, b) => n * 128 + b, 0);
  assert(end <= data.length);
  const frames = [];
  let pos = 10;
  while (pos + 6 <= end && data[pos] !== 0) {
    const id = data.subarray(pos, pos + 3).toString('ascii');
    assert(/^[A-Z0-9]{3}$/.test(id));
    const size = data.readUIntBE(pos + 3, 3);
    assert(pos + 6 + size <= end);
    const body = data.subarray(pos + 6, pos + 6 + size);
    frames.push({offset: pos, id, size, hex: body.toString('hex'), latin1: body.toString('latin1')});
    pos += 6 + size;
  }
  return {version: '2.2.0', end, frames, paddingStart: pos,
    paddingBytes: end - pos, paddingNonzero: data.subarray(pos, end).filter(b => b !== 0).length};
}

function bits(data, start, length) {
  assert(start >= 0 && start + length <= data.length * 8 && length <= 32);
  let value = 0;
  for (let i = start; i < start + length; i++) value = value * 2 + ((data[i >> 3] >> (7 - (i & 7))) & 1);
  return value;
}

function mpegFrames(data, start) {
  const frames = [], payloads = [];
  let pos = start, totalMainBytes = 0;
  while (pos + 4 <= data.length) {
    const h = data.readUInt32BE(pos);
    if ((h >>> 21) !== 2047) break; // Unparsed bytes remain explicit, never silently skipped.
    const version = (h >>> 19) & 3, layer = (h >>> 17) & 3;
    assert.equal(version, 3, 'Only MPEG-1 is supported by this audit');
    assert.equal(layer, 1, 'Only Layer III is supported by this audit');
    const bitrateIndex = (h >>> 12) & 15, rateIndex = (h >>> 10) & 3;
    assert(bitrateIndex > 0 && bitrateIndex < 15 && rateIndex < 3);
    const bitrate = [0,32,40,48,56,64,80,96,112,128,160,192,224,256,320][bitrateIndex] * 1000;
    const sampleRate = [44100,48000,32000][rateIndex], padding = (h >>> 9) & 1;
    const size = Math.floor(144 * bitrate / sampleRate) + padding;
    assert(pos + size <= data.length, 'Truncated MPEG frame');
    const protection = (h >>> 16) & 1, mode = (h >>> 6) & 3;
    const channels = mode === 3 ? 1 : 2, sideBytes = channels === 1 ? 17 : 32;
    const sideOffset = pos + 4 + (protection ? 0 : 2);
    const side = data.subarray(sideOffset, sideOffset + sideBytes);
    const mainDataBegin = bits(side, 0, 9);
    const privateWidth = channels === 1 ? 5 : 3;
    const sidePrivate = bits(side, 9, privateWidth);
    const scfsi = Array.from({length: channels}, (_, c) => bits(side, 9 + privateWidth + 4*c, 4));
    const granuleStart = 9 + privateWidth + 4*channels;
    const part23 = Array.from({length: 2*channels}, (_, j) => bits(side, granuleStart + 59*j, 12));
    assert.equal(granuleStart + 59 * 2 * channels, sideBytes * 8);
    const mainOffset = sideOffset + sideBytes, payload = data.subarray(mainOffset, pos + size);
    const usedStartBit = (totalMainBytes - mainDataBegin) * 8;
    const usedEndBit = usedStartBit + part23.reduce((a, b) => a + b, 0);
    assert(usedStartBit >= 0 && usedEndBit <= (totalMainBytes + payload.length) * 8);
    frames.push({index: frames.length, offset: pos, size, headerHex: data.subarray(pos,pos+4).toString('hex'),
      version, layer, protection, bitrate, sampleRate, padding, private: (h >>> 8)&1, mode,
      modeExtension: (h >>> 4)&3, copyright: (h >>> 3)&1, original: (h >>> 2)&1, emphasis: h&3,
      sideOffset, sideHex: side.toString('hex'), mainDataBegin, sidePrivate, scfsi, part23,
      mainOffset, mainBytes: payload.length, mainStreamOffset: totalMainBytes, usedStartBit, usedEndBit});
    payloads.push(payload); totalMainBytes += payload.length; pos += size;
  }
  return {frames, end: pos, trailingBytes: data.length - pos, mainData: Buffer.concat(payloads)};
}

function unusedMainData(parsed) {
  const {frames, mainData} = parsed, gaps = [];
  let end = 0;
  function addGap(start, stop) {
    if (start === stop) return;
    let nonzeroBits = 0;
    for (let i = start; i < stop; i++) nonzeroBits += bits(mainData, i, 1);
    const byteStart = Math.ceil(start / 8), byteEnd = Math.floor(stop / 8);
    gaps.push({startBit: start, endBit: stop, lengthBits: stop-start, nonzeroBits,
      alignedByteStart: byteStart, alignedByteEnd: byteEnd,
      alignedHex: mainData.subarray(byteStart, Math.max(byteStart,byteEnd)).toString('hex')});
  }
  for (const f of frames) {
    assert(f.usedStartBit >= end, 'Overlapping main-data allocations');
    addGap(end, f.usedStartBit); end = f.usedEndBit;
  }
  addGap(end, mainData.length * 8);
  return gaps;
}

function controls(data, tag, parsed) {
  const marker = Buffer.from('CONTROL-TRAILER');
  const appended = mpegFrames(Buffer.concat([data, marker]), tag.end);
  assert.equal(appended.trailingBytes, marker.length);
  assert.throws(() => mpegFrames(data.subarray(0, data.length-1), tag.end), /Truncated/);
  const padded = Buffer.from(data); padded[tag.paddingStart + 1] = 65;
  assert.equal(id3v22(padded).paddingNonzero, 1);
  const headerPrivate = Buffer.from(data); headerPrivate[tag.end + 2] ^= 1;
  assert.equal(mpegFrames(headerPrivate,tag.end).frames[0].private, 1-parsed.frames[0].private);
  const sidePrivate = Buffer.from(data); sidePrivate[parsed.frames[0].sideOffset+1] ^= 0x40;
  assert.equal(mpegFrames(sidePrivate,tag.end).frames[0].sidePrivate, parsed.frames[0].sidePrivate ^ 4);
  const gaps = unusedMainData(parsed), gap = gaps.find(g => g.lengthBits >= 8);
  assert(gap);
  const changed = {...parsed, mainData: Buffer.from(parsed.mainData)};
  changed.mainData[gap.startBit >> 3] ^= 1 << (7-(gap.startBit & 7));
  assert.notEqual(unusedMainData(changed).find(g => g.startBit === gap.startBit).nonzeroBits, gap.nonzeroBits);
  return ['appended trailer reported', 'truncated frame rejected', 'nonzero ID3 padding reported',
    'header private bit detected', 'side-info private bit detected', 'unused main-data bit detected'];
}

function main() {
  const destination = path.resolve(process.argv[2] || path.join(root, '_work/mp3_container_2026-09-16'));
  assert(!fs.existsSync(destination), 'Choose a new output directory; existing evidence is preserved');
  const source = path.join(root, '_work/decentraland/puzzlepiece.mp3');
  const data = fs.readFileSync(source);
  assert.equal(sha(data), 'ef17a96dce37b4dd7cbf79f210c5cbaf37fcae60e5faf8004de4e0832bd0dfee');
  assert(data.equals(fs.readFileSync(path.join(root, '_work/decentraland/sounds__puzzlepiece.mp3'))));
  const tag = id3v22(data), parsed = mpegFrames(data, tag.end), gaps = unusedMainData(parsed);
  const toolDir = path.join(process.env.LOCALAPPDATA, 'Microsoft/WinGet/Links');
  const ffprobe = path.join(toolDir,'ffprobe.exe'), ffmpeg = path.join(toolDir,'ffmpeg.exe');
  const probe = JSON.parse(execFileSync(ffprobe, ['-v','error','-show_packets','-show_entries',
    'packet=pos,size,duration','-show_format','-show_streams','-of','json',source], {encoding:'utf8'}));
  assert.equal(probe.packets.length, parsed.frames.length);
  probe.packets.forEach((p,i) => {
    assert.equal(Number(p.pos), parsed.frames[i].offset);
    assert.equal(Number(p.size), parsed.frames[i].size);
    assert.equal(p.duration, 368640);
  });
  const decoded = execFileSync(ffmpeg, ['-v','error','-i',source,'-f','s16le','-acodec','pcm_s16le','pipe:1'],
    {maxBuffer:8*1024*1024});
  assert.equal(decoded.length, parsed.frames.length * 1152 * 2 * 2);
  assert.equal(tag.frames[0].latin1.slice(1), probe.format.tags.TSS);
  for (const f of tag.frames.slice(1)) {
    const [name,text] = f.latin1.slice(4).split('\0');
    assert.equal(text, probe.format.tags[name]);
  }
  const gapless = probe.format.tags.iTunSMPB.trim().split(/\s+/).map(s => BigInt('0x'+s));
  assert.equal(gapless[1]+gapless[2]+gapless[3], BigInt(parsed.frames.length*1152));
  const phases = Array.from({length:49}, (_,p) => p).filter(p => parsed.frames.every((f,i) =>
    f.padding === Math.floor(((i+1)*44+p)/49)-Math.floor((i*44+p)/49)));
  const fields = Object.fromEntries(['protection','bitrate','sampleRate','private','mode','modeExtension',
    'copyright','original','emphasis','sidePrivate'].map(k => [k,[...new Set(parsed.frames.map(f => f[k]))]]));
  const signatures = Object.fromEntries([['Salted__','53616c7465645f5f'],['U2FsdGVk','553246736447566b'],
    ['ZIP','504b0304'],['PNG','89504e470d0a1a0a'],['PDF','255044462d']].map(([name,hex]) => {
      const needle = Buffer.from(hex,'hex'), offsets = [];
      for (let pos = data.indexOf(needle); pos >= 0; pos = data.indexOf(needle,pos+1)) offsets.push(pos);
      return [name,offsets];
    }));
  const report = {createdAt:new Date().toISOString(), source:path.relative(root,source), bytes:data.length,
    sha256:sha(data), duplicateIdentical:true, id3:tag, frames:parsed.frames.length,
    mpegBytes:parsed.end-tag.end, trailingBytes:parsed.trailingBytes, fields,
    paddedFrames:parsed.frames.reduce((n,f) => n+f.padding,0), paddingPhases:phases,
    mainDataBytes:parsed.mainData.length, unusedMainData:{regions:gaps.length,
      bits:gaps.reduce((n,g) => n+g.lengthBits,0), nonzeroBits:gaps.reduce((n,g) => n+g.nonzeroBits,0)},
    sampleFrames:decoded.length/4, decodedPcmSha256:sha(decoded),
    gapless:{delay:Number(gapless[1]),padding:Number(gapless[2]),samples:Number(gapless[3])},
    ffprobeVersion:execFileSync(ffprobe,['-version'],{encoding:'utf8'}).split(/\r?\n/)[0],
    ffmpegVersion:execFileSync(ffmpeg,['-version'],{encoding:'utf8'}).split(/\r?\n/)[0],
    packetComparison:'Every position, size and duration matched', decoder:'All frames decoded successfully',
    signatures, controls:controls(data,tag,parsed),
    limitations:'No exhaustive search of coded audio, scalefactors, parity steganography or signal transformations.'};
  fs.mkdirSync(destination,{recursive:true});
  for (const [name,value] of [['audit.json',report],['frames.json',parsed.frames],['unused_main_data.json',gaps],['ffprobe.json',probe]])
    fs.writeFileSync(path.join(destination,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify(report,null,2));
}
if (require.main === module) main();
module.exports = {id3v22,mpegFrames,unusedMainData,bits};
