// SPDX-License-Identifier: AGPL-3.0-or-later
// QR Code encoder — byte mode, error-correction level M (~15% redundancy),
// versions 1-15 (up to 535 byte capacity at level M). Pure JS; no vendor
// dependency. Renders an SVG matrix sharp at any zoom; CSP-clean.
//
// Reference: ISO/IEC 18004:2015 (QR Code) — public spec. Implementation
// algorithm follows the standard sequence:
//   1. Byte-mode data encoding (mode + char count + bytes + padding).
//   2. Reed-Solomon error-correction codewords over GF(256) with the
//      QR-standard primitive polynomial 0x11D.
//   3. Module placement: finder patterns, separators, timing strips,
//      alignment patterns (for versions ≥ 2), reserved format + version
//      regions, then data + EC bits in zigzag.
//   4. Masking: try 8 masks, pick the lowest-penalty per ISO §7.8.3.
//   5. Format-info + version-info bits written last (under their masks).
//
// Used by the device-pairing flow to render the CRATE-PAIR-… token for
// a phone to scan. The same module is the only stable API for
// downstream consumers (lib/folder.js, future QR-shaped UIs).

const SVG_NS = "http://www.w3.org/2000/svg";

// Byte mode = 0100; char-count length depends on version range.
const MODE_BYTE = 0x4;

// Error-correction level M is encoded as 0b00 for the format-info bits.
const EC_LEVEL_M = 0;
const FORMAT_EC_INDICATOR = 0; // M ⇒ 0b00

// QR_CAPACITY[version][level] = data codeword count for level M (we only
// expose level M; the table is per ISO Table 7). Versions 1-15 inclusive.
// (Level M capacity values; index 0 = version 1.)
const CAPACITY_M = [
  16, 28, 44, 64, 86, 108, 124, 154, 182, 216,
  254, 290, 334, 365, 415,
];
// Number of EC codewords per block at level M.
const EC_PER_BLOCK_M = [
  10, 16, 26, 18, 24, 16, 18, 22, 22, 26,
  30, 22, 22, 24, 24,
];
// Block layout: [{count, dataLen}] per version at level M. Each entry
// is one group; QR may split into 2 groups with differing dataLen — for
// the versions we ship, groupings are spec-direct.
const BLOCKS_M = [
  /* v1  */ [{ count: 1, dataLen: 16 }],
  /* v2  */ [{ count: 1, dataLen: 28 }],
  /* v3  */ [{ count: 1, dataLen: 44 }],
  /* v4  */ [{ count: 2, dataLen: 32 }],
  /* v5  */ [{ count: 2, dataLen: 43 }],
  /* v6  */ [{ count: 4, dataLen: 27 }],
  /* v7  */ [{ count: 4, dataLen: 31 }],
  /* v8  */ [{ count: 2, dataLen: 38 }, { count: 2, dataLen: 39 }],
  /* v9  */ [{ count: 3, dataLen: 36 }, { count: 2, dataLen: 37 }],
  /* v10 */ [{ count: 4, dataLen: 43 }, { count: 1, dataLen: 44 }],
  /* v11 */ [{ count: 1, dataLen: 50 }, { count: 4, dataLen: 51 }],
  /* v12 */ [{ count: 6, dataLen: 36 }, { count: 2, dataLen: 37 }],
  /* v13 */ [{ count: 8, dataLen: 37 }, { count: 1, dataLen: 38 }],
  /* v14 */ [{ count: 4, dataLen: 40 }, { count: 5, dataLen: 41 }],
  /* v15 */ [{ count: 5, dataLen: 41 }, { count: 5, dataLen: 42 }],
];
// Alignment pattern centre coordinates per version (versions 2+).
const ALIGNMENT_POSITIONS = [
  /* v1  */ [],
  /* v2  */ [6, 18],
  /* v3  */ [6, 22],
  /* v4  */ [6, 26],
  /* v5  */ [6, 30],
  /* v6  */ [6, 34],
  /* v7  */ [6, 22, 38],
  /* v8  */ [6, 24, 42],
  /* v9  */ [6, 26, 46],
  /* v10 */ [6, 28, 50],
  /* v11 */ [6, 30, 54],
  /* v12 */ [6, 32, 58],
  /* v13 */ [6, 34, 62],
  /* v14 */ [6, 26, 46, 66],
  /* v15 */ [6, 26, 48, 70],
];

// --- GF(256) Reed-Solomon helpers -----------------------------------------

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11D; // QR primitive poly
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255];
}

// Build the generator polynomial of degree `n` (coefficient array, len n+1).
function rsGeneratorPoly(n) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < n; i++) {
    // Multiply by (x - a^i)
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
    }
    poly = next;
  }
  return poly;
}

// Compute the EC codewords for `data` given the generator polynomial.
function rsEncode(data, generator) {
  const ecLen = generator.length - 1;
  const result = new Uint8Array(data.length + ecLen);
  result.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = result[i];
    if (factor === 0) continue;
    for (let j = 0; j < generator.length; j++) {
      result[i + j] ^= gfMul(generator[j], factor);
    }
  }
  return result.subarray(data.length);
}

// --- byte encoding --------------------------------------------------------

// pickVersion returns the smallest version (1..15) that fits `byteLen`
// bytes at EC level M. Throws if data is too big.
function pickVersion(byteLen) {
  // Total bits = mode(4) + charCount(8 or 16) + byteLen*8 + terminator(4)
  // (rounded to a byte). Compare against capacityM bytes * 8.
  for (let v = 1; v <= 15; v++) {
    const ccLen = v <= 9 ? 8 : 16;
    const bits = 4 + ccLen + byteLen * 8;
    if (bits + 4 /* terminator */ <= CAPACITY_M[v - 1] * 8) return v;
  }
  throw new Error(`qr: payload too large (${byteLen} bytes; supports up to ${CAPACITY_M[14]} at v15/M)`);
}

// encodeData produces the data codeword stream (data + padding to capacity).
function encodeData(bytes, version) {
  const ccLen = version <= 9 ? 8 : 16;
  const capacity = CAPACITY_M[version - 1] * 8;
  const bits = new BitStream();
  bits.append(MODE_BYTE, 4);
  bits.append(bytes.length, ccLen);
  for (const b of bytes) bits.append(b, 8);
  // Terminator (up to 4 zero bits).
  const term = Math.min(4, capacity - bits.length);
  bits.append(0, term);
  // Pad to byte boundary.
  while (bits.length % 8 !== 0) bits.append(0, 1);
  // Pad bytes alternating 0xEC, 0x11.
  const pad = [0xEC, 0x11];
  let pi = 0;
  while (bits.length < capacity) {
    bits.append(pad[pi % 2], 8);
    pi++;
  }
  return bits.toBytes();
}

// BitStream — append N-bit values, materialise as Uint8Array (big-endian).
class BitStream {
  constructor() { this.buf = []; this.length = 0; }
  append(value, nbits) {
    for (let i = nbits - 1; i >= 0; i--) {
      const byteIdx = this.length >> 3;
      if (this.buf[byteIdx] === undefined) this.buf[byteIdx] = 0;
      if ((value >> i) & 1) this.buf[byteIdx] |= 1 << (7 - (this.length & 7));
      this.length++;
    }
  }
  toBytes() { return Uint8Array.from(this.buf); }
}

// Build the full codeword stream (interleaved data + EC blocks) per ISO
// §7.6 "Constructing the final message codeword sequence."
function buildFullStream(dataBytes, version) {
  const blocks = BLOCKS_M[version - 1];
  const ecLen = EC_PER_BLOCK_M[version - 1];
  const gen = rsGeneratorPoly(ecLen);
  // Split dataBytes into per-block data arrays.
  const dataBlocks = [];
  const ecBlocks = [];
  let cursor = 0;
  for (const group of blocks) {
    for (let i = 0; i < group.count; i++) {
      const slice = dataBytes.subarray(cursor, cursor + group.dataLen);
      cursor += group.dataLen;
      dataBlocks.push(slice);
      ecBlocks.push(rsEncode(slice, gen));
    }
  }
  // Interleave by column.
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  const out = [];
  for (let i = 0; i < maxDataLen; i++) {
    for (const blk of dataBlocks) if (i < blk.length) out.push(blk[i]);
  }
  for (let i = 0; i < ecLen; i++) {
    for (const blk of ecBlocks) out.push(blk[i]);
  }
  return Uint8Array.from(out);
}

// --- matrix construction --------------------------------------------------

function sizeForVersion(v) { return 17 + 4 * v; }

// Matrix uses int8: -1 reserved, 0 light, 1 dark. The functional regions
// (finder/timing/alignment/format/version) are placed first; the data
// stream fills the remainder.
function newMatrix(size) {
  const m = [];
  for (let r = 0; r < size; r++) m.push(new Int8Array(size).fill(-1));
  return m;
}

function placeFinder(m, r0, c0) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const rr = r0 + r, cc = c0 + c;
      if (rr < 0 || rr >= m.length || cc < 0 || cc >= m.length) continue;
      if (r >= 0 && r <= 6 && c >= 0 && c <= 6) {
        const onBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        m[rr][cc] = onBorder || inCore ? 1 : 0;
      } else {
        // Separator (white border).
        m[rr][cc] = 0;
      }
    }
  }
}

function placeTiming(m) {
  const size = m.length;
  for (let i = 8; i < size - 8; i++) {
    m[6][i] = i % 2 === 0 ? 1 : 0;
    m[i][6] = i % 2 === 0 ? 1 : 0;
  }
}

function placeAlignment(m, version) {
  const coords = ALIGNMENT_POSITIONS[version - 1];
  for (const r0 of coords) {
    for (const c0 of coords) {
      // Skip overlaps with finder patterns.
      if ((r0 < 8 && c0 < 8) ||
          (r0 < 8 && c0 > m.length - 9) ||
          (r0 > m.length - 9 && c0 < 8)) continue;
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const rr = r0 + r, cc = c0 + c;
          const onBorder = r === -2 || r === 2 || c === -2 || c === 2;
          const isCentre = r === 0 && c === 0;
          m[rr][cc] = onBorder || isCentre ? 1 : 0;
        }
      }
    }
  }
}

// Reserve format-info modules (placed later under mask).
function reserveFormat(m) {
  const size = m.length;
  for (let i = 0; i <= 8; i++) {
    if (m[8][i] === -1) m[8][i] = 0;
    if (m[i][8] === -1) m[i][8] = 0;
  }
  for (let i = 0; i < 8; i++) {
    m[size - 1 - i][8] = 0;
    m[8][size - 1 - i] = 0;
  }
  m[size - 8][8] = 1; // dark module (mandatory)
}

// reserveVersion for versions ≥ 7. Mark cells; bits written later.
function reserveVersion(m, version) {
  if (version < 7) return;
  const size = m.length;
  for (let i = 0; i < 18; i++) {
    const r = Math.floor(i / 3), c = i % 3 + size - 11;
    if (m[r][c] === -1) m[r][c] = 0;
    if (m[c][r] === -1) m[c][r] = 0;
  }
}

// Walk data modules in zigzag (right-to-left, two-column groups), skipping
// the timing column at index 6.
function* dataModuleOrder(size) {
  let col = size - 1;
  let upward = true;
  while (col > 0) {
    if (col === 6) col--; // skip timing
    for (let i = 0; i < size; i++) {
      const r = upward ? size - 1 - i : i;
      for (let dc = 0; dc < 2; dc++) {
        const c = col - dc;
        yield [r, c];
      }
    }
    col -= 2;
    upward = !upward;
  }
}

function placeData(m, stream) {
  let bitIdx = 0;
  for (const [r, c] of dataModuleOrder(m.length)) {
    if (m[r][c] !== -1) continue; // already a functional module
    const bit = bitIdx < stream.length * 8
      ? (stream[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1
      : 0;
    m[r][c] = bit;
    bitIdx++;
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

// applyMask flips DATA modules (not functional regions) according to mask.
// We track which modules are functional via a sibling mask matrix.
function applyMask(m, mask, isFunctional) {
  const out = m.map((row) => Int8Array.from(row));
  for (let r = 0; r < out.length; r++) {
    for (let c = 0; c < out.length; c++) {
      if (isFunctional[r][c]) continue;
      if (mask(r, c)) out[r][c] ^= 1;
    }
  }
  return out;
}

// markFunctional returns a same-size matrix of booleans marking functional
// modules. We pre-compute this BEFORE placing data so the mask + score
// only consider data modules.
function markFunctional(version) {
  const size = sizeForVersion(version);
  const f = [];
  for (let i = 0; i < size; i++) f.push(new Uint8Array(size));
  // Finders + separators (8x8 each, three corners).
  const fSpots = [[0, 0], [0, size - 7], [size - 7, 0]];
  for (const [r0, c0] of fSpots) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = r0 + r, cc = c0 + c;
        if (rr >= 0 && rr < size && cc >= 0 && cc < size) f[rr][cc] = 1;
      }
    }
  }
  // Timing.
  for (let i = 0; i < size; i++) { f[6][i] = 1; f[i][6] = 1; }
  // Alignment.
  const coords = ALIGNMENT_POSITIONS[version - 1];
  for (const r0 of coords) {
    for (const c0 of coords) {
      if ((r0 < 8 && c0 < 8) ||
          (r0 < 8 && c0 > size - 9) ||
          (r0 > size - 9 && c0 < 8)) continue;
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) f[r0 + r][c0 + c] = 1;
      }
    }
  }
  // Format-info rows/cols (around finders).
  for (let i = 0; i <= 8; i++) { f[8][i] = 1; f[i][8] = 1; }
  for (let i = 0; i < 8; i++) {
    f[size - 1 - i][8] = 1;
    f[8][size - 1 - i] = 1;
  }
  // Version-info regions for v7+.
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const r = Math.floor(i / 3), c = i % 3 + size - 11;
      f[r][c] = 1;
      f[c][r] = 1;
    }
  }
  return f;
}

// Mask-penalty score per ISO §7.8.3.
function penaltyScore(m) {
  const size = m.length;
  let score = 0;
  // Rule 1: runs of 5+ same colour in row or column.
  for (let r = 0; r < size; r++) {
    let runColor = -1, runLen = 0;
    for (let c = 0; c < size; c++) {
      if (m[r][c] === runColor) {
        runLen++;
        if (runLen === 5) score += 3;
        else if (runLen > 5) score += 1;
      } else {
        runColor = m[r][c];
        runLen = 1;
      }
    }
  }
  for (let c = 0; c < size; c++) {
    let runColor = -1, runLen = 0;
    for (let r = 0; r < size; r++) {
      if (m[r][c] === runColor) {
        runLen++;
        if (runLen === 5) score += 3;
        else if (runLen > 5) score += 1;
      } else {
        runColor = m[r][c];
        runLen = 1;
      }
    }
  }
  // Rule 2: 2x2 solid blocks.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = m[r][c];
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) {
        score += 3;
      }
    }
  }
  // Rule 3: 1:1:3:1:1 finder-like patterns (rows + cols).
  const pattern1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const pattern2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  function matchPattern(line) {
    let s = 0;
    for (let i = 0; i <= line.length - pattern1.length; i++) {
      let m1 = true, m2 = true;
      for (let j = 0; j < pattern1.length; j++) {
        if (line[i + j] !== pattern1[j]) m1 = false;
        if (line[i + j] !== pattern2[j]) m2 = false;
        if (!m1 && !m2) break;
      }
      if (m1) s += 40;
      if (m2) s += 40;
    }
    return s;
  }
  for (let r = 0; r < size; r++) {
    const row = Array.from(m[r]);
    score += matchPattern(row);
  }
  for (let c = 0; c < size; c++) {
    const col = [];
    for (let r = 0; r < size; r++) col.push(m[r][c]);
    score += matchPattern(col);
  }
  // Rule 4: dark/light balance.
  let dark = 0;
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (m[r][c] === 1) dark++;
  const ratio = Math.abs((dark * 100) / (size * size) - 50);
  score += Math.floor(ratio / 5) * 10;
  return score;
}

// formatBits: 5 data bits (ECC level + mask pattern) + 10 BCH bits.
function formatBits(maskPattern) {
  const data = (FORMAT_EC_INDICATOR << 3) | maskPattern; // 5 bits but level=00
  // Actually: ec(2bits, M=00) | mask(3bits)
  let d = (0 << 3) | maskPattern;
  let rem = d;
  for (let i = 0; i < 10; i++) {
    rem <<= 1;
    if (rem & (1 << 10)) rem ^= 0b10100110111;
  }
  const bits = ((d << 10) | rem) ^ 0b101010000010010; // XOR mask per spec
  return bits;
  // Note: `data` unused; left as a marker for the bit-layout intent.
}
// Suppress unused warning on the `data` marker.
void formatBits;

// versionBits: 6 data bits + 12 BCH bits, for v7+.
function versionBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i++) {
    rem <<= 1;
    if (rem & (1 << 12)) rem ^= 0b1111100100101;
  }
  return (version << 12) | rem;
}

// placeFormatBits writes the 15 format bits in the two prescribed locations.
function placeFormatBits(m, bits) {
  const size = m.length;
  for (let i = 0; i < 6; i++) m[8][i] = (bits >> (14 - i)) & 1;
  m[8][7] = (bits >> 8) & 1;
  m[8][8] = (bits >> 7) & 1;
  m[7][8] = (bits >> 6) & 1;
  for (let i = 0; i < 6; i++) m[5 - i][8] = (bits >> i) & 1;
  // Mirrored copy.
  for (let i = 0; i < 7; i++) m[size - 1 - i][8] = (bits >> i) & 1;
  m[size - 8][8] = 1; // dark module
  for (let i = 0; i < 8; i++) m[8][size - 1 - i] = (bits >> (i + 7)) & 1;
}

function placeVersionBits(m, version) {
  if (version < 7) return;
  const bits = versionBits(version);
  const size = m.length;
  for (let i = 0; i < 18; i++) {
    const bit = (bits >> i) & 1;
    const r = Math.floor(i / 3), c = i % 3 + size - 11;
    m[r][c] = bit;
    m[c][r] = bit;
  }
}

// --- top-level encode -----------------------------------------------------

// encode(text) returns { matrix, size, version } where matrix is a 2D
// Int8Array array of 0/1.
export function encode(text) {
  if (typeof text !== "string") throw new Error("qr.encode: text must be string");
  const bytes = new TextEncoder().encode(text);
  const version = pickVersion(bytes.length);
  const data = encodeData(bytes, version);
  const stream = buildFullStream(data, version);

  // Build the base matrix (functional only; data placed in unmasked pass).
  const size = sizeForVersion(version);
  const isFunc = markFunctional(version);
  const base = newMatrix(size);
  placeFinder(base, 0, 0);
  placeFinder(base, 0, size - 7);
  placeFinder(base, size - 7, 0);
  placeTiming(base);
  placeAlignment(base, version);
  reserveFormat(base);
  reserveVersion(base, version);
  placeData(base, stream);

  // Pick best mask.
  let best = null;
  let bestScore = Infinity;
  for (let i = 0; i < 8; i++) {
    const masked = applyMask(base, MASKS[i], isFunc);
    // Write format bits for this mask before scoring (penalty considers
    // ALL modules including format).
    placeFormatBits(masked, computeFormatBitsForMask(i));
    placeVersionBits(masked, version);
    const score = penaltyScore(masked);
    if (score < bestScore) {
      bestScore = score;
      best = masked;
    }
  }
  return { matrix: best, size, version };
}

// computeFormatBitsForMask returns the 15-bit format string for (level M,
// maskPattern). Pre-computed via the BCH(15,5) generator + XOR mask.
function computeFormatBitsForMask(maskPattern) {
  // Level M = 0b00; mask is 3 bits.
  const data5 = (0 << 3) | maskPattern;
  let rem = data5;
  for (let i = 0; i < 10; i++) {
    rem <<= 1;
    if (rem & (1 << 10)) rem ^= 0b10100110111;
  }
  return ((data5 << 10) | rem) ^ 0b101010000010010;
}

// --- SVG rendering --------------------------------------------------------

// renderTo paints the QR for `text` into `el` as an inline SVG. `opts`:
//   { moduleSize: px-per-module (default 6), margin: modules (default 4),
//     dark: colour (default '#0a0a0a'), light: colour (default 'transparent') }
export function renderTo(el, text, opts = {}) {
  while (el.firstChild) el.removeChild(el.firstChild);
  let result;
  try {
    result = encode(text);
  } catch (e) {
    const err = document.createElement("div");
    err.className = "qr-placeholder muted small";
    err.textContent = "QR encode failed: " + (e.message ?? e);
    el.appendChild(err);
    return;
  }
  const { matrix, size } = result;
  const moduleSize = opts.moduleSize ?? 6;
  const margin = opts.margin ?? 4;
  const dark = opts.dark ?? "#0a0a0a";
  const light = opts.light ?? "#ffffff";
  const dim = (size + 2 * margin) * moduleSize;

  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("xmlns", SVG_NS);
  svg.setAttribute("viewBox", `0 0 ${dim} ${dim}`);
  svg.setAttribute("width", String(dim));
  svg.setAttribute("height", String(dim));
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Pairing token QR code");
  svg.style.maxWidth = "100%";
  svg.style.height = "auto";
  svg.style.background = light;

  // Group all dark modules into a single SVG path for compactness.
  let d = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] !== 1) continue;
      const x = (c + margin) * moduleSize;
      const y = (r + margin) * moduleSize;
      d += `M${x} ${y}h${moduleSize}v${moduleSize}h-${moduleSize}z`;
    }
  }
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", d);
  path.setAttribute("fill", dark);
  svg.appendChild(path);
  el.appendChild(svg);
}
