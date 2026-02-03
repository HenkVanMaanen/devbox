/** https://github.com/datalog/qrcode-svg under MIT license */
/* eslint-disable @typescript-eslint/no-explicit-any */

interface QROptions {
  msg: string;
  dim?: number;
  pad?: number;
  ecl?: 'L' | 'M' | 'Q' | 'H';
  pal?: [string, string?];
}

function QRCode(r: QROptions | string): SVGElement {
  let n: number,
    t: [number, number],
    o: number,
    e: number;
  const a: number[][] = [];
  const f: number[][] = [];
  const i = Math.max,
    u = Math.min,
    h = Math.abs,
    v = Math.ceil,
    c = /^[0-9]*$/,
    s = /^[A-Z0-9 $%*+.\/:-]*$/,
    l = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:',
    g = [
      [
        -1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
      ],
      [
        -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
      ],
      [
        -1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
      ],
      [
        -1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
      ],
    ],
    d = [
      [
        -1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18,
        19, 19, 20, 21, 22, 24, 25,
      ],
      [
        -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31,
        33, 35, 37, 38, 40, 43, 45, 47, 49,
      ],
      [
        -1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40,
        43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
      ],
      [
        -1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48,
        51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
      ],
    ],
    m: Record<string, [number, number]> = { L: [0, 1], M: [1, 0], Q: [2, 3], H: [3, 2] },
    p = function (r: number, n: number): number {
      for (let t = 0, o = 8; o--; ) t = (t << 1) ^ (285 * (t >>> 7)) ^ (((n >>> o) & 1) * r);
      return t;
    },
    C = function (r: number[], n: number[]): number[] {
      const t: number[] = [];
      let o = r.length;
      let e = o;
      while (e) {
        const a = r[o - e--] ^ (t.shift() ?? 0);
        for (let f = n.length; f--; ) t[f] = (t[f] ?? 0) ^ p(n[f], a);
      }
      return t;
    },
    w = function (r: number): void {
      const fn = [
        function () {
          return 0 == (tt + oo) % 2;
        },
        function () {
          return 0 == tt % 2;
        },
        function () {
          return 0 == oo % 3;
        },
        function () {
          return 0 == (tt + oo) % 3;
        },
        function () {
          return 0 == (((tt / 2) | 0) + ((oo / 3) | 0)) % 2;
        },
        function () {
          return 0 == (tt * oo) % 2 + (tt * oo) % 3;
        },
        function () {
          return 0 == ((tt * oo) % 2 + (tt * oo) % 3) % 2;
        },
        function () {
          return 0 == (((tt + oo) % 2) + (tt * oo) % 3) % 2;
        },
      ][r];
      let tt = e;
      while (tt--) {
        let oo = e;
        while (oo--) {
          if (!f[tt][oo]) a[tt][oo] ^= fn() ? 1 : 0;
        }
      }
    },
    b = function (): number {
      const rr = function (rVal: number, nArr: number[]): void {
        if (!nArr[6]) rVal += e;
        nArr.shift();
        nArr.push(rVal);
      };
      const nn = function (nVal: boolean, oVal: number, aArr: number[]): number {
        if (nVal) {
          rr(oVal, aArr);
          oVal = 0;
        }
        rr((oVal += e), aArr);
        return ttt(aArr);
      };
      const ttt = function (rArr: number[]): number {
        const nVal = rArr[5];
        const tVal = nVal > 0 && rArr[4] == nVal && rArr[3] == 3 * nVal && rArr[2] == nVal && rArr[1] == nVal;
        return (tVal && rArr[6] >= 4 * nVal && rArr[0] >= nVal ? 1 : 0) + (tVal && rArr[0] >= 4 * nVal && rArr[6] >= nVal ? 1 : 0);
      };
      let ooo = 0;
      const fff = e * e;
      let iii = 0;
      let uuu = e;
      while (uuu--) {
        const cc = [0, 0, 0, 0, 0, 0, 0];
        const ss = [0, 0, 0, 0, 0, 0, 0];
        let ll = false;
        let gg = false;
        let dd = 0;
        let mm = 0;
        let pp = e;
        while (pp--) {
          if (a[uuu][pp] == (ll ? 1 : 0)) {
            if (5 == ++dd) ooo += 3;
            else if (dd > 5) ooo++;
          } else {
            rr(dd, cc);
            ooo += 40 * ttt(cc);
            dd = 1;
            ll = !!a[uuu][pp];
          }
          if (a[pp][uuu] == (gg ? 1 : 0)) {
            if (5 == ++mm) ooo += 3;
            else if (mm > 5) ooo++;
          } else {
            rr(mm, ss);
            ooo += 40 * ttt(ss);
            mm = 1;
            gg = !!a[pp][uuu];
          }
          const CC = a[uuu][pp];
          if (CC) iii++;
          if (pp && uuu && CC == a[uuu][pp - 1] && CC == a[uuu - 1][pp] && CC == a[uuu - 1][pp - 1]) ooo += 3;
        }
        ooo += 40 * nn(ll, dd, cc) + 40 * nn(gg, mm, ss);
      }
      return (ooo += 10 * (v(h((20 * iii - 10 * fff) / fff)) - 1));
    },
    A = function (r: number, n: number, t: number[]): void {
      for (; n--; ) t.push((r >>> n) & 1);
    },
    M = function (r: any, n: number): number {
      return r.numBitsCharCount[((n + 7) / 17) | 0];
    },
    B = function (r: number, n: number): number {
      return (r >>> n) & 1;
    },
    x = function (r: any[], n: number): number {
      let t = 0;
      let o = r.length;
      while (o--) {
        const e = r[o];
        const a = M(e, n);
        if (1 << a <= e.numChars) return 1 / 0;
        t += 4 + a + e.bitData.length;
      }
      return t;
    },
    D = function (r: number): number {
      if (r < 1 || r > 40) throw 'Version number out of range';
      let n = (16 * r + 128) * r + 64;
      if (r >= 2) {
        const t = (r / 7) | 2;
        n -= (25 * t - 10) * t - 55;
        if (r >= 7) n -= 36;
      }
      return n;
    },
    I = function (r: number, n: number): void {
      for (let t = 2; -2 <= t; t--)
        for (let o = 2; -2 <= o; o--) E(r + o, n + t, 1 != i(h(o), h(t)));
    },
    H = function (r: number, n: number): void {
      for (let t = 4; -4 <= t; t--)
        for (let o = 4; -4 <= o; o--) {
          const a = i(h(o), h(t));
          const f = r + o;
          const u = n + t;
          if (0 <= f && f < e && 0 <= u && u < e) E(f, u, 2 != a && 4 != a);
        }
    },
    $ = function (r: number): void {
      const n = t[1] << 3 | r;
      let o = n;
      for (let a = 10; a--; ) o = (o << 1) ^ (1335 * (o >>> 9));
      const f = 21522 ^ ((n << 10) | o);
      if (f >>> 15 != 0) throw 'Assertion error';
      for (let a = 0; a <= 5; a++) E(8, a, !!B(f, a));
      E(8, 7, !!B(f, 6));
      E(8, 8, !!B(f, 7));
      E(7, 8, !!B(f, 8));
      for (let a = 9; a < 15; a++) E(14 - a, 8, !!B(f, a));
      for (let a = 0; a < 8; a++) E(e - 1 - a, 8, !!B(f, a));
      for (let a = 8; a < 15; a++) E(8, e - 15 + a, !!B(f, a));
      E(8, e - 8, true);
    },
    O = function (): void {
      for (let r = e; r--; ) {
        E(6, r, 0 == r % 2);
        E(r, 6, 0 == r % 2);
      }
      const tt = (function (): number[] {
        const r: number[] = [];
        if (n > 1) {
          const t = 2 + ((n / 7) | 0);
          const o = 32 == n ? 26 : 2 * v((e - 13) / (2 * t - 2));
          for (let i = t; i--; ) r[i] = i * o + 6;
        }
        return r;
      })();
      const oo = tt.length;
      let rr = oo;
      while (rr--) {
        let aa = oo;
        while (aa--) {
          if ((0 == aa && 0 == rr) || (0 == aa && rr == oo - 1) || (aa == oo - 1 && 0 == rr)) continue;
          I(tt[aa], tt[rr]);
        }
      }
      H(3, 3);
      H(e - 4, 3);
      H(3, e - 4);
      $(0);
      (function (): void {
        if (7 > n) return;
        let r = n;
        for (let t = 12; t--; ) r = (r << 1) ^ (7973 * (r >>> 11));
        const o = (n << 12) | r;
        let t = 18;
        if (o >>> 18 != 0) throw 'Assertion error';
        while (t--) {
          const a = e - 11 + (t % 3);
          const f = (t / 3) | 0;
          const i = !!B(o, t);
          E(a, f, i);
          E(f, a, i);
        }
      })();
    },
    Q = function (r: number[]): number[] {
      if (r.length != V(n, t)) throw 'Invalid argument';
      const o = d[t[0]][n];
      const ee = g[t[0]][n];
      const a = (D(n) / 8) | 0;
      const f = o - (a % o);
      const ii = (a / o) | 0;
      const uu: number[][] = [];
      const hh = (function (r: number): number[] {
        let n = 1;
        const t: number[] = [];
        t[r - 1] = 1;
        for (let o = 0; o < r; o++) {
          for (let e = 0; e < r; e++) t[e] = p(t[e], n) ^ (t[e + 1] ?? 0);
          n = p(n, 2);
        }
        return t;
      })(ee);
      let vv = 0;
      let cc = 0;
      while (vv < o) {
        const s = r.slice(cc, cc + ii - ee + (vv < f ? 0 : 1));
        cc += s.length;
        const l = C(s, hh);
        if (vv < f) s.push(0);
        uu.push(s.concat(l));
        vv++;
      }
      const m: number[] = [];
      for (vv = 0; vv < uu[0].length; vv++)
        for (let w = 0; w < uu.length; w++)
          if (vv != ii - ee || w >= f) m.push(uu[w][vv]);
      return m;
    },
    S = function (r: string): number[] {
      const n: number[] = [];
      r = encodeURI(r);
      let t = 0;
      while (t < r.length) {
        if ('%' != r.charAt(t)) n.push(r.charCodeAt(t));
        else {
          n.push(parseInt(r.substr(t + 1, 2), 16));
          t += 2;
        }
        t++;
      }
      return n;
    },
    V = function (r: number, n: [number, number]): number {
      return ((D(r) / 8) | 0) - g[n[0]][r] * d[n[0]][r];
    },
    E = function (r: number, n: number, t: boolean): void {
      a[n][r] = t ? 1 : 0;
      f[n][r] = 1;
    },
    R = function (r: number[]): any {
      const n: number[] = [];
      for (let t = 0; t < r.length; t++) {
        const e = r[t];
        A(e, 8, n);
      }
      return { modeBits: 4, numBitsCharCount: [8, 16, 16], numChars: r.length, bitData: n };
    },
    Z = function (r: string): any {
      if (!c.test(r)) throw 'String contains non-numeric characters';
      const n: number[] = [];
      let t = 0;
      while (t < r.length) {
        const o = u(r.length - t, 3);
        A(parseInt(r.substr(t, o), 10), 3 * o + 1, n);
        t += o;
      }
      return { modeBits: 1, numBitsCharCount: [10, 12, 14], numChars: r.length, bitData: n };
    },
    z = function (r: string): any {
      if (!s.test(r)) throw 'String contains unencodable characters in alphanumeric mode';
      const n: number[] = [];
      let nn = 0;
      while (nn + 2 <= r.length) {
        let o = 45 * l.indexOf(r.charAt(nn));
        o += l.indexOf(r.charAt(nn + 1));
        A(o, 11, n);
        nn += 2;
      }
      if (nn < r.length) A(l.indexOf(r.charAt(nn)), 6, n);
      return { modeBits: 2, numBitsCharCount: [9, 11, 13], numChars: r.length, bitData: n };
    },
    L = function (r: string, n: [number, number], _t: number, o: number): void {
      const e = (function (r: string): any[] {
        if ('' == r) return [];
        if (c.test(r)) return [Z(r)];
        if (s.test(r)) return [z(r)];
        return [R(S(r))];
      })(r);
      U(e, n, _t != 0, o);
    },
    N = function (r: number, i: [number, number], u: number[], hh: number): void {
      t = i;
      o = hh;
      n = r;
      e = 4 * n + 17;
      for (let vv = e; vv--; ) {
        a[vv] = [];
        f[vv] = [];
      }
      O();
      (function (r: number[]): void {
        let n = 0;
        let t = 1;
        let o = e - 1;
        const i = o;
        for (let ii = i; ii > 0; ii -= 2) {
          if (6 == ii) --ii;
          for (let u = 0, h = 0 > (t = -t) ? i : 0; u < e; ++u) {
            for (let v = ii; v > ii - 2; --v)
              if (!f[h][v]) {
                a[h][v] = B(r[n >>> 3], 7 - (7 & n));
                ++n;
              }
            h += t;
          }
        }
      })(Q(u));
      if (0 > o) {
        let c = 1e9;
        for (let vv = 8; vv--; ) {
          w(vv);
          $(vv);
          const s = b();
          if (c > s) {
            c = s;
            o = vv;
          }
          w(vv);
        }
      }
      w(o);
      $(o);
      f.length = 0;
    },
    U = function (r: any[], n: [number, number], t?: boolean, o?: number, ee?: number, aa?: number): void {
      if (void 0 === ee) ee = 1;
      if (void 0 === aa) aa = 40;
      if (void 0 === o) o = -1;
      if (void 0 === t) t = true;
      if (!(1 <= ee && ee <= aa && aa <= 40) || o < -1 || o > 7) throw 'Invalid value';
      const ff: number[] = [];
      let ii = 236;
      const hh: number[] = [];
      let vv = ee;
      for (;;) {
        const c = x(r, vv);
        if (c <= 8 * V(vv, n)) break;
        if (vv >= aa) throw 'Data too long';
        vv++;
      }
      if (t) {
        const ll: [number, number][] = [m.H, m.Q, m.M];
        for (let s = ll.length; s--; ) {
          const c = x(r, vv);
          if (c <= 8 * V(vv, ll[s])) n = ll[s];
        }
      }
      for (let l = 0; l < r.length; l++) {
        const gg = r[l];
        A(gg.modeBits, 4, ff);
        A(gg.numChars, M(gg, vv), ff);
        for (let d = 0; d < gg.bitData.length; d++) ff.push(gg.bitData[d]);
      }
      const c = x(r, vv);
      if (ff.length != c) throw 'Assertion error';
      const C = 8 * V(vv, n);
      if (ff.length > C) throw 'Assertion error';
      A(0, u(4, C - ff.length), ff);
      A(0, (8 - (ff.length % 8)) % 8, ff);
      if (ff.length % 8 != 0) throw 'Assertion error';
      while (ff.length < C) {
        A(ii, 8, ff);
        ii ^= 253;
      }
      for (let s = ff.length; s--; ) hh[s >>> 3] = (hh[s >>> 3] ?? 0) | (ff[s] << (7 - (7 & s)));
      N(vv, n, hh, o);
    };

  const svgNs = 'http://www.w3.org/2000/svg';

  function isHex(r: string): boolean {
    return /^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(r);
  }

  function createEl(r: string, n?: Record<string, any>): SVGElement {
    const el = document.createElementNS(svgNs, r);
    for (const t in n || {}) el.setAttribute(t, n![t]);
    return el;
  }

  let ll = '';
  const gg: QROptions = typeof r === 'string' ? { msg: r } : r || { msg: '' };
  const dd = gg.pal || ['#000'];
  const pp = h(gg.dim ?? 256);
  let cc = h(gg.pad ?? 4);
  if (!(cc > -1)) cc = 4;
  const CC = [1, 0, 0, 1, cc, cc];
  let ww = dd[0];
  if (!isHex(ww)) ww = '#000';
  let bb = dd[1];
  if (!isHex(bb ?? '')) bb = undefined;
  const AA = 1;

  L(gg.msg || '', m[gg.ecl ?? 'M'] || m.M, 0, -1);
  const vv = e + 2 * cc;
  let ii = e;
  while (ii--) {
    let uu = 0;
    let ff = e;
    while (ff--) {
      if (a[ii][ff]) {
        if (AA) {
          uu++;
          if (!a[ii][ff - 1]) {
            ll += 'M' + ff + ',' + ii + 'h' + uu + 'v1h-' + uu + 'v-1z';
            uu = 0;
          }
        } else {
          ll += 'M' + ff + ',' + ii + 'h1v1h-1v-1z';
        }
      }
    }
  }

  const oo = createEl('svg', {
    viewBox: [0, 0, vv, vv].join(' '),
    width: pp,
    height: pp,
    fill: ww,
    'shape-rendering': 'crispEdges',
    xmlns: svgNs,
    version: '1.1',
  });

  if (bb) oo.appendChild(createEl('path', { fill: bb, d: 'M0,0V' + vv + 'H' + vv + 'V0H0Z' }));
  oo.appendChild(createEl('path', { transform: 'matrix(' + CC + ')', d: ll }));

  return oo;
}

export function generateQR(text: string): string {
  const svg = QRCode({ msg: text, dim: 256, pad: 4, ecl: 'M' });
  return svg.outerHTML;
}
