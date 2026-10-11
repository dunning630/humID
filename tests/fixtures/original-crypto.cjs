(() => {
  var an = BigInt(4294967295),
    Ro = BigInt(32);
  function As(t, e = !1) {
    return e
      ? { h: Number(t & an), l: Number((t >> Ro) & an) }
      : { h: Number((t >> Ro) & an) | 0, l: Number(t & an) | 0 };
  }
  function fn(t, e = !1) {
    let n = t.length,
      o = new Uint32Array(n),
      r = new Uint32Array(n);
    for (let s = 0; s < n; s++) {
      let { h: i, l: c } = As(t[s], e);
      [o[s], r[s]] = [i, c];
    }
    return [o, r];
  }
  var Gn = (t, e, n) => t >>> n,
    Fn = (t, e, n) => (t << (32 - n)) | (e >>> n),
    he = (t, e, n) => (t >>> n) | (e << (32 - n)),
    pe = (t, e, n) => (t << (32 - n)) | (e >>> n),
    Ke = (t, e, n) => (t << (64 - n)) | (e >>> (n - 32)),
    qe = (t, e, n) => (t >>> (n - 32)) | (e << (64 - n));
  var Ko = (t, e, n) => (t << n) | (e >>> (32 - n)),
    qo = (t, e, n) => (e << n) | (t >>> (32 - n)),
    Go = (t, e, n) => (e << (n - 32)) | (t >>> (64 - n)),
    Fo = (t, e, n) => (t << (n - 32)) | (e >>> (64 - n));
  function Pt(t, e, n, o) {
    let r = (e >>> 0) + (o >>> 0);
    return { h: (t + n + ((r / 2 ** 32) | 0)) | 0, l: r | 0 };
  }
  var jo = (t, e, n) => (t >>> 0) + (e >>> 0) + (n >>> 0),
    Vo = (t, e, n, o) => (e + n + o + ((t / 2 ** 32) | 0)) | 0,
    Zo = (t, e, n, o) => (t >>> 0) + (e >>> 0) + (n >>> 0) + (o >>> 0),
    $o = (t, e, n, o, r) => (e + n + o + r + ((t / 2 ** 32) | 0)) | 0,
    Xo = (t, e, n, o, r) =>
      (t >>> 0) + (e >>> 0) + (n >>> 0) + (o >>> 0) + (r >>> 0),
    Yo = (t, e, n, o, r, s) => (e + n + o + r + s + ((t / 2 ** 32) | 0)) | 0;
  var me =
    typeof globalThis == "object" && "crypto" in globalThis
      ? globalThis.crypto
      : void 0;
  function ye(t) {
    return (
      t instanceof Uint8Array ||
      (ArrayBuffer.isView(t) && t.constructor.name === "Uint8Array")
    );
  }
  function Rt(t) {
    if (!Number.isSafeInteger(t) || t < 0)
      throw new Error("positive integer expected, got " + t);
  }
  function $(t, ...e) {
    if (!ye(t)) throw new Error("Uint8Array expected");
    if (e.length > 0 && !e.includes(t.length))
      throw new Error(
        "Uint8Array expected of length " + e + ", got length=" + t.length,
      );
  }
  function Ge(t) {
    if (typeof t != "function" || typeof t.create != "function")
      throw new Error("Hash should be wrapped by utils.createHasher");
    (Rt(t.outputLen), Rt(t.blockLen));
  }
  function jt(t, e = !0) {
    if (t.destroyed) throw new Error("Hash instance has been destroyed");
    if (e && t.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function dn(t, e) {
    $(t);
    let n = e.outputLen;
    if (t.length < n)
      throw new Error(
        "digestInto() expects output buffer of length at least " + n,
      );
  }
  function ln(t) {
    return new Uint32Array(
      t.buffer,
      t.byteOffset,
      Math.floor(t.byteLength / 4),
    );
  }
  function gt(...t) {
    for (let e = 0; e < t.length; e++) t[e].fill(0);
  }
  function un(t) {
    return new DataView(t.buffer, t.byteOffset, t.byteLength);
  }
  function Lt(t, e) {
    return (t << (32 - e)) | (t >>> e);
  }
  var ks = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
  function vs(t) {
    return (
      ((t << 24) & 4278190080) |
      ((t << 8) & 16711680) |
      ((t >>> 8) & 65280) |
      ((t >>> 24) & 255)
    );
  }
  function _s(t) {
    for (let e = 0; e < t.length; e++) t[e] = vs(t[e]);
    return t;
  }
  var jn = ks ? (t) => t : _s,
    Wo =
      typeof Uint8Array.from([]).toHex == "function" &&
      typeof Uint8Array.fromHex == "function",
    Is = Array.from({ length: 256 }, (t, e) => e.toString(16).padStart(2, "0"));
  function xe(t) {
    if (($(t), Wo)) return t.toHex();
    let e = "";
    for (let n = 0; n < t.length; n++) e += Is[t[n]];
    return e;
  }
  var Ft = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
  function zo(t) {
    if (t >= Ft._0 && t <= Ft._9) return t - Ft._0;
    if (t >= Ft.A && t <= Ft.F) return t - (Ft.A - 10);
    if (t >= Ft.a && t <= Ft.f) return t - (Ft.a - 10);
  }
  function st(t) {
    if (typeof t != "string")
      throw new Error("hex string expected, got " + typeof t);
    if (Wo) return Uint8Array.fromHex(t);
    let e = t.length,
      n = e / 2;
    if (e % 2)
      throw new Error("hex string expected, got unpadded hex of length " + e);
    let o = new Uint8Array(n);
    for (let r = 0, s = 0; r < n; r++, s += 2) {
      let i = zo(t.charCodeAt(s)),
        c = zo(t.charCodeAt(s + 1));
      if (i === void 0 || c === void 0) {
        let a = t[s] + t[s + 1];
        throw new Error(
          'hex string expected, got non-hex character "' +
            a +
            '" at index ' +
            s,
        );
      }
      o[r] = i * 16 + c;
    }
    return o;
  }
  function hn(t) {
    if (typeof t != "string") throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(t));
  }
  function Ht(t) {
    return (typeof t == "string" && (t = hn(t)), $(t), t);
  }
  function Vt(...t) {
    let e = 0;
    for (let o = 0; o < t.length; o++) {
      let r = t[o];
      ($(r), (e += r.length));
    }
    let n = new Uint8Array(e);
    for (let o = 0, r = 0; o < t.length; o++) {
      let s = t[o];
      (n.set(s, r), (r += s.length));
    }
    return n;
  }
  var oe = class {};
  function Zt(t) {
    let e = (o) => t().update(Ht(o)).digest(),
      n = t();
    return (
      (e.outputLen = n.outputLen),
      (e.blockLen = n.blockLen),
      (e.create = () => t()),
      e
    );
  }
  function Qo(t) {
    let e = (o, r) => t(r).update(Ht(o)).digest(),
      n = t({});
    return (
      (e.outputLen = n.outputLen),
      (e.blockLen = n.blockLen),
      (e.create = (o) => t(o)),
      e
    );
  }
  function ge(t = 32) {
    if (me && typeof me.getRandomValues == "function")
      return me.getRandomValues(new Uint8Array(t));
    if (me && typeof me.randomBytes == "function")
      return Uint8Array.from(me.randomBytes(t));
    throw new Error("crypto.getRandomValues must be defined");
  }
  var Ts = BigInt(0),
    Fe = BigInt(1),
    Cs = BigInt(2),
    Ls = BigInt(7),
    Hs = BigInt(256),
    Us = BigInt(113),
    er = [],
    nr = [],
    or = [];
  for (let t = 0, e = Fe, n = 1, o = 0; t < 24; t++) {
    (([n, o] = [o, (2 * n + 3 * o) % 5]),
      er.push(2 * (5 * o + n)),
      nr.push((((t + 1) * (t + 2)) / 2) % 64));
    let r = Ts;
    for (let s = 0; s < 7; s++)
      ((e = ((e << Fe) ^ ((e >> Ls) * Us)) % Hs),
        e & Cs && (r ^= Fe << ((Fe << BigInt(s)) - Fe)));
    or.push(r);
  }
  var rr = fn(or, !0),
    Ms = rr[0],
    Os = rr[1],
    Jo = (t, e, n) => (n > 32 ? Go(t, e, n) : Ko(t, e, n)),
    tr = (t, e, n) => (n > 32 ? Fo(t, e, n) : qo(t, e, n));
  function Ds(t, e = 24) {
    let n = new Uint32Array(10);
    for (let o = 24 - e; o < 24; o++) {
      for (let i = 0; i < 10; i++)
        n[i] = t[i] ^ t[i + 10] ^ t[i + 20] ^ t[i + 30] ^ t[i + 40];
      for (let i = 0; i < 10; i += 2) {
        let c = (i + 8) % 10,
          a = (i + 2) % 10,
          l = n[a],
          u = n[a + 1],
          d = Jo(l, u, 1) ^ n[c],
          f = tr(l, u, 1) ^ n[c + 1];
        for (let m = 0; m < 50; m += 10) ((t[i + m] ^= d), (t[i + m + 1] ^= f));
      }
      let r = t[2],
        s = t[3];
      for (let i = 0; i < 24; i++) {
        let c = nr[i],
          a = Jo(r, s, c),
          l = tr(r, s, c),
          u = er[i];
        ((r = t[u]), (s = t[u + 1]), (t[u] = a), (t[u + 1] = l));
      }
      for (let i = 0; i < 50; i += 10) {
        for (let c = 0; c < 10; c++) n[c] = t[i + c];
        for (let c = 0; c < 10; c++)
          t[i + c] ^= ~n[(c + 2) % 10] & n[(c + 4) % 10];
      }
      ((t[0] ^= Ms[o]), (t[1] ^= Os[o]));
    }
    gt(n);
  }
  var pn = class t extends oe {
      constructor(e, n, o, r = !1, s = 24) {
        if (
          (super(),
          (this.pos = 0),
          (this.posOut = 0),
          (this.finished = !1),
          (this.destroyed = !1),
          (this.enableXOF = !1),
          (this.blockLen = e),
          (this.suffix = n),
          (this.outputLen = o),
          (this.enableXOF = r),
          (this.rounds = s),
          Rt(o),
          !(0 < e && e < 200))
        )
          throw new Error("only keccak-f1600 function is supported");
        ((this.state = new Uint8Array(200)), (this.state32 = ln(this.state)));
      }
      clone() {
        return this._cloneInto();
      }
      keccak() {
        (jn(this.state32),
          Ds(this.state32, this.rounds),
          jn(this.state32),
          (this.posOut = 0),
          (this.pos = 0));
      }
      update(e) {
        (jt(this), (e = Ht(e)), $(e));
        let { blockLen: n, state: o } = this,
          r = e.length;
        for (let s = 0; s < r;) {
          let i = Math.min(n - this.pos, r - s);
          for (let c = 0; c < i; c++) o[this.pos++] ^= e[s++];
          this.pos === n && this.keccak();
        }
        return this;
      }
      finish() {
        if (this.finished) return;
        this.finished = !0;
        let { state: e, suffix: n, pos: o, blockLen: r } = this;
        ((e[o] ^= n),
          (n & 128) !== 0 && o === r - 1 && this.keccak(),
          (e[r - 1] ^= 128),
          this.keccak());
      }
      writeInto(e) {
        (jt(this, !1), $(e), this.finish());
        let n = this.state,
          { blockLen: o } = this;
        for (let r = 0, s = e.length; r < s;) {
          this.posOut >= o && this.keccak();
          let i = Math.min(o - this.posOut, s - r);
          (e.set(n.subarray(this.posOut, this.posOut + i), r),
            (this.posOut += i),
            (r += i));
        }
        return e;
      }
      xofInto(e) {
        if (!this.enableXOF)
          throw new Error("XOF is not possible for this instance");
        return this.writeInto(e);
      }
      xof(e) {
        return (Rt(e), this.xofInto(new Uint8Array(e)));
      }
      digestInto(e) {
        if ((dn(e, this), this.finished))
          throw new Error("digest() was already called");
        return (this.writeInto(e), this.destroy(), e);
      }
      digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
      }
      destroy() {
        ((this.destroyed = !0), gt(this.state));
      }
      _cloneInto(e) {
        let {
          blockLen: n,
          suffix: o,
          outputLen: r,
          rounds: s,
          enableXOF: i,
        } = this;
        return (
          e || (e = new t(n, o, r, i, s)),
          e.state32.set(this.state32),
          (e.pos = this.pos),
          (e.posOut = this.posOut),
          (e.finished = this.finished),
          (e.rounds = s),
          (e.suffix = o),
          (e.outputLen = r),
          (e.enableXOF = i),
          (e.destroyed = this.destroyed),
          e
        );
      }
    },
    mn = (t, e, n) => Zt(() => new pn(e, t, n)),
    sr = mn(6, 144, 224 / 8),
    Ut = mn(6, 136, 256 / 8),
    ir = mn(6, 104, 384 / 8),
    vt = mn(6, 72, 512 / 8);
  var cr = (t, e, n) =>
      Qo((o = {}) => new pn(e, t, o.dkLen === void 0 ? n : o.dkLen, !0)),
    yn = cr(31, 168, 128 / 8),
    J = cr(31, 136, 256 / 8);
  function Ns(t, e, n, o) {
    if (typeof t.setBigUint64 == "function") return t.setBigUint64(e, n, o);
    let r = BigInt(32),
      s = BigInt(4294967295),
      i = Number((n >> r) & s),
      c = Number(n & s),
      a = o ? 4 : 0,
      l = o ? 0 : 4;
    (t.setUint32(e + a, i, o), t.setUint32(e + l, c, o));
  }
  function ar(t, e, n) {
    return (t & e) ^ (~t & n);
  }
  function fr(t, e, n) {
    return (t & e) ^ (t & n) ^ (e & n);
  }
  var je = class extends oe {
      constructor(e, n, o, r) {
        (super(),
          (this.finished = !1),
          (this.length = 0),
          (this.pos = 0),
          (this.destroyed = !1),
          (this.blockLen = e),
          (this.outputLen = n),
          (this.padOffset = o),
          (this.isLE = r),
          (this.buffer = new Uint8Array(e)),
          (this.view = un(this.buffer)));
      }
      update(e) {
        (jt(this), (e = Ht(e)), $(e));
        let { view: n, buffer: o, blockLen: r } = this,
          s = e.length;
        for (let i = 0; i < s;) {
          let c = Math.min(r - this.pos, s - i);
          if (c === r) {
            let a = un(e);
            for (; r <= s - i; i += r) this.process(a, i);
            continue;
          }
          (o.set(e.subarray(i, i + c), this.pos),
            (this.pos += c),
            (i += c),
            this.pos === r && (this.process(n, 0), (this.pos = 0)));
        }
        return ((this.length += e.length), this.roundClean(), this);
      }
      digestInto(e) {
        (jt(this), dn(e, this), (this.finished = !0));
        let { buffer: n, view: o, blockLen: r, isLE: s } = this,
          { pos: i } = this;
        ((n[i++] = 128),
          gt(this.buffer.subarray(i)),
          this.padOffset > r - i && (this.process(o, 0), (i = 0)));
        for (let d = i; d < r; d++) n[d] = 0;
        (Ns(o, r - 8, BigInt(this.length * 8), s), this.process(o, 0));
        let c = un(e),
          a = this.outputLen;
        if (a % 4)
          throw new Error("_sha2: outputLen should be aligned to 32bit");
        let l = a / 4,
          u = this.get();
        if (l > u.length) throw new Error("_sha2: outputLen bigger than state");
        for (let d = 0; d < l; d++) c.setUint32(4 * d, u[d], s);
      }
      digest() {
        let { buffer: e, outputLen: n } = this;
        this.digestInto(e);
        let o = e.slice(0, n);
        return (this.destroy(), o);
      }
      _cloneInto(e) {
        (e || (e = new this.constructor()), e.set(...this.get()));
        let {
          blockLen: n,
          buffer: o,
          length: r,
          finished: s,
          destroyed: i,
          pos: c,
        } = this;
        return (
          (e.destroyed = i),
          (e.finished = s),
          (e.length = r),
          (e.pos = c),
          r % n && e.buffer.set(o),
          e
        );
      }
      clone() {
        return this._cloneInto();
      }
    },
    $t = Uint32Array.from([
      1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924,
      528734635, 1541459225,
    ]),
    Xt = Uint32Array.from([
      3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025,
      1694076839, 3204075428,
    ]),
    it = Uint32Array.from([
      3418070365, 3238371032, 1654270250, 914150663, 2438529370, 812702999,
      355462360, 4144912697, 1731405415, 4290775857, 2394180231, 1750603025,
      3675008525, 1694076839, 1203062813, 3204075428,
    ]),
    ct = Uint32Array.from([
      1779033703, 4089235720, 3144134277, 2227873595, 1013904242, 4271175723,
      2773480762, 1595750129, 1359893119, 2917565137, 2600822924, 725511199,
      528734635, 4215389547, 1541459225, 327033209,
    ]);
  var Ps = Uint32Array.from([
      1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993,
      2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987,
      1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,
      264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
      2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
      113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
      1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411,
      3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
      430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
      1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
      2428436474, 2756734187, 3204031479, 3329325298,
    ]),
    re = new Uint32Array(64),
    xn = class extends je {
      constructor(e = 32) {
        (super(64, e, 8, !1),
          (this.A = $t[0] | 0),
          (this.B = $t[1] | 0),
          (this.C = $t[2] | 0),
          (this.D = $t[3] | 0),
          (this.E = $t[4] | 0),
          (this.F = $t[5] | 0),
          (this.G = $t[6] | 0),
          (this.H = $t[7] | 0));
      }
      get() {
        let { A: e, B: n, C: o, D: r, E: s, F: i, G: c, H: a } = this;
        return [e, n, o, r, s, i, c, a];
      }
      set(e, n, o, r, s, i, c, a) {
        ((this.A = e | 0),
          (this.B = n | 0),
          (this.C = o | 0),
          (this.D = r | 0),
          (this.E = s | 0),
          (this.F = i | 0),
          (this.G = c | 0),
          (this.H = a | 0));
      }
      process(e, n) {
        for (let d = 0; d < 16; d++, n += 4) re[d] = e.getUint32(n, !1);
        for (let d = 16; d < 64; d++) {
          let f = re[d - 15],
            m = re[d - 2],
            x = Lt(f, 7) ^ Lt(f, 18) ^ (f >>> 3),
            B = Lt(m, 17) ^ Lt(m, 19) ^ (m >>> 10);
          re[d] = (B + re[d - 7] + x + re[d - 16]) | 0;
        }
        let { A: o, B: r, C: s, D: i, E: c, F: a, G: l, H: u } = this;
        for (let d = 0; d < 64; d++) {
          let f = Lt(c, 6) ^ Lt(c, 11) ^ Lt(c, 25),
            m = (u + f + ar(c, a, l) + Ps[d] + re[d]) | 0,
            B = ((Lt(o, 2) ^ Lt(o, 13) ^ Lt(o, 22)) + fr(o, r, s)) | 0;
          ((u = l),
            (l = a),
            (a = c),
            (c = (i + m) | 0),
            (i = s),
            (s = r),
            (r = o),
            (o = (m + B) | 0));
        }
        ((o = (o + this.A) | 0),
          (r = (r + this.B) | 0),
          (s = (s + this.C) | 0),
          (i = (i + this.D) | 0),
          (c = (c + this.E) | 0),
          (a = (a + this.F) | 0),
          (l = (l + this.G) | 0),
          (u = (u + this.H) | 0),
          this.set(o, r, s, i, c, a, l, u));
      }
      roundClean() {
        gt(re);
      }
      destroy() {
        (this.set(0, 0, 0, 0, 0, 0, 0, 0), gt(this.buffer));
      }
    },
    Vn = class extends xn {
      constructor() {
        (super(28),
          (this.A = Xt[0] | 0),
          (this.B = Xt[1] | 0),
          (this.C = Xt[2] | 0),
          (this.D = Xt[3] | 0),
          (this.E = Xt[4] | 0),
          (this.F = Xt[5] | 0),
          (this.G = Xt[6] | 0),
          (this.H = Xt[7] | 0));
      }
    },
    dr = fn(
      [
        "0x428a2f98d728ae22",
        "0x7137449123ef65cd",
        "0xb5c0fbcfec4d3b2f",
        "0xe9b5dba58189dbbc",
        "0x3956c25bf348b538",
        "0x59f111f1b605d019",
        "0x923f82a4af194f9b",
        "0xab1c5ed5da6d8118",
        "0xd807aa98a3030242",
        "0x12835b0145706fbe",
        "0x243185be4ee4b28c",
        "0x550c7dc3d5ffb4e2",
        "0x72be5d74f27b896f",
        "0x80deb1fe3b1696b1",
        "0x9bdc06a725c71235",
        "0xc19bf174cf692694",
        "0xe49b69c19ef14ad2",
        "0xefbe4786384f25e3",
        "0x0fc19dc68b8cd5b5",
        "0x240ca1cc77ac9c65",
        "0x2de92c6f592b0275",
        "0x4a7484aa6ea6e483",
        "0x5cb0a9dcbd41fbd4",
        "0x76f988da831153b5",
        "0x983e5152ee66dfab",
        "0xa831c66d2db43210",
        "0xb00327c898fb213f",
        "0xbf597fc7beef0ee4",
        "0xc6e00bf33da88fc2",
        "0xd5a79147930aa725",
        "0x06ca6351e003826f",
        "0x142929670a0e6e70",
        "0x27b70a8546d22ffc",
        "0x2e1b21385c26c926",
        "0x4d2c6dfc5ac42aed",
        "0x53380d139d95b3df",
        "0x650a73548baf63de",
        "0x766a0abb3c77b2a8",
        "0x81c2c92e47edaee6",
        "0x92722c851482353b",
        "0xa2bfe8a14cf10364",
        "0xa81a664bbc423001",
        "0xc24b8b70d0f89791",
        "0xc76c51a30654be30",
        "0xd192e819d6ef5218",
        "0xd69906245565a910",
        "0xf40e35855771202a",
        "0x106aa07032bbd1b8",
        "0x19a4c116b8d2d0c8",
        "0x1e376c085141ab53",
        "0x2748774cdf8eeb99",
        "0x34b0bcb5e19b48a8",
        "0x391c0cb3c5c95a63",
        "0x4ed8aa4ae3418acb",
        "0x5b9cca4f7763e373",
        "0x682e6ff3d6b2b8a3",
        "0x748f82ee5defb2fc",
        "0x78a5636f43172f60",
        "0x84c87814a1f0ab72",
        "0x8cc702081a6439ec",
        "0x90befffa23631e28",
        "0xa4506cebde82bde9",
        "0xbef9a3f7b2c67915",
        "0xc67178f2e372532b",
        "0xca273eceea26619c",
        "0xd186b8c721c0c207",
        "0xeada7dd6cde0eb1e",
        "0xf57d4f7fee6ed178",
        "0x06f067aa72176fba",
        "0x0a637dc5a2c898a6",
        "0x113f9804bef90dae",
        "0x1b710b35131c471b",
        "0x28db77f523047d84",
        "0x32caab7b40c72493",
        "0x3c9ebe0a15c9bebc",
        "0x431d67c49c100d4c",
        "0x4cc5d4becb3e42b6",
        "0x597f299cfc657e2a",
        "0x5fcb6fab3ad6faec",
        "0x6c44198c4a475817",
      ].map((t) => BigInt(t)),
    ),
    Rs = dr[0],
    Ks = dr[1],
    se = new Uint32Array(80),
    ie = new Uint32Array(80),
    Le = class extends je {
      constructor(e = 64) {
        (super(128, e, 16, !1),
          (this.Ah = ct[0] | 0),
          (this.Al = ct[1] | 0),
          (this.Bh = ct[2] | 0),
          (this.Bl = ct[3] | 0),
          (this.Ch = ct[4] | 0),
          (this.Cl = ct[5] | 0),
          (this.Dh = ct[6] | 0),
          (this.Dl = ct[7] | 0),
          (this.Eh = ct[8] | 0),
          (this.El = ct[9] | 0),
          (this.Fh = ct[10] | 0),
          (this.Fl = ct[11] | 0),
          (this.Gh = ct[12] | 0),
          (this.Gl = ct[13] | 0),
          (this.Hh = ct[14] | 0),
          (this.Hl = ct[15] | 0));
      }
      get() {
        let {
          Ah: e,
          Al: n,
          Bh: o,
          Bl: r,
          Ch: s,
          Cl: i,
          Dh: c,
          Dl: a,
          Eh: l,
          El: u,
          Fh: d,
          Fl: f,
          Gh: m,
          Gl: x,
          Hh: B,
          Hl: p,
        } = this;
        return [e, n, o, r, s, i, c, a, l, u, d, f, m, x, B, p];
      }
      set(e, n, o, r, s, i, c, a, l, u, d, f, m, x, B, p) {
        ((this.Ah = e | 0),
          (this.Al = n | 0),
          (this.Bh = o | 0),
          (this.Bl = r | 0),
          (this.Ch = s | 0),
          (this.Cl = i | 0),
          (this.Dh = c | 0),
          (this.Dl = a | 0),
          (this.Eh = l | 0),
          (this.El = u | 0),
          (this.Fh = d | 0),
          (this.Fl = f | 0),
          (this.Gh = m | 0),
          (this.Gl = x | 0),
          (this.Hh = B | 0),
          (this.Hl = p | 0));
      }
      process(e, n) {
        for (let y = 0; y < 16; y++, n += 4)
          ((se[y] = e.getUint32(n)), (ie[y] = e.getUint32((n += 4))));
        for (let y = 16; y < 80; y++) {
          let k = se[y - 15] | 0,
            E = ie[y - 15] | 0,
            H = he(k, E, 1) ^ he(k, E, 8) ^ Gn(k, E, 7),
            O = pe(k, E, 1) ^ pe(k, E, 8) ^ Fn(k, E, 7),
            U = se[y - 2] | 0,
            b = ie[y - 2] | 0,
            A = he(U, b, 19) ^ Ke(U, b, 61) ^ Gn(U, b, 6),
            _ = pe(U, b, 19) ^ qe(U, b, 61) ^ Fn(U, b, 6),
            P = Zo(O, _, ie[y - 7], ie[y - 16]),
            I = $o(P, H, A, se[y - 7], se[y - 16]);
          ((se[y] = I | 0), (ie[y] = P | 0));
        }
        let {
          Ah: o,
          Al: r,
          Bh: s,
          Bl: i,
          Ch: c,
          Cl: a,
          Dh: l,
          Dl: u,
          Eh: d,
          El: f,
          Fh: m,
          Fl: x,
          Gh: B,
          Gl: p,
          Hh: h,
          Hl: g,
        } = this;
        for (let y = 0; y < 80; y++) {
          let k = he(d, f, 14) ^ he(d, f, 18) ^ Ke(d, f, 41),
            E = pe(d, f, 14) ^ pe(d, f, 18) ^ qe(d, f, 41),
            H = (d & m) ^ (~d & B),
            O = (f & x) ^ (~f & p),
            U = Xo(g, E, O, Ks[y], ie[y]),
            b = Yo(U, h, k, H, Rs[y], se[y]),
            A = U | 0,
            _ = he(o, r, 28) ^ Ke(o, r, 34) ^ Ke(o, r, 39),
            P = pe(o, r, 28) ^ qe(o, r, 34) ^ qe(o, r, 39),
            I = (o & s) ^ (o & c) ^ (s & c),
            M = (r & i) ^ (r & a) ^ (i & a);
          ((h = B | 0),
            (g = p | 0),
            (B = m | 0),
            (p = x | 0),
            (m = d | 0),
            (x = f | 0),
            ({ h: d, l: f } = Pt(l | 0, u | 0, b | 0, A | 0)),
            (l = c | 0),
            (u = a | 0),
            (c = s | 0),
            (a = i | 0),
            (s = o | 0),
            (i = r | 0));
          let K = jo(A, P, M);
          ((o = Vo(K, b, _, I)), (r = K | 0));
        }
        (({ h: o, l: r } = Pt(this.Ah | 0, this.Al | 0, o | 0, r | 0)),
          ({ h: s, l: i } = Pt(this.Bh | 0, this.Bl | 0, s | 0, i | 0)),
          ({ h: c, l: a } = Pt(this.Ch | 0, this.Cl | 0, c | 0, a | 0)),
          ({ h: l, l: u } = Pt(this.Dh | 0, this.Dl | 0, l | 0, u | 0)),
          ({ h: d, l: f } = Pt(this.Eh | 0, this.El | 0, d | 0, f | 0)),
          ({ h: m, l: x } = Pt(this.Fh | 0, this.Fl | 0, m | 0, x | 0)),
          ({ h: B, l: p } = Pt(this.Gh | 0, this.Gl | 0, B | 0, p | 0)),
          ({ h, l: g } = Pt(this.Hh | 0, this.Hl | 0, h | 0, g | 0)),
          this.set(o, r, s, i, c, a, l, u, d, f, m, x, B, p, h, g));
      }
      roundClean() {
        gt(se, ie);
      }
      destroy() {
        (gt(this.buffer),
          this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
      }
    },
    Zn = class extends Le {
      constructor() {
        (super(48),
          (this.Ah = it[0] | 0),
          (this.Al = it[1] | 0),
          (this.Bh = it[2] | 0),
          (this.Bl = it[3] | 0),
          (this.Ch = it[4] | 0),
          (this.Cl = it[5] | 0),
          (this.Dh = it[6] | 0),
          (this.Dl = it[7] | 0),
          (this.Eh = it[8] | 0),
          (this.El = it[9] | 0),
          (this.Fh = it[10] | 0),
          (this.Fl = it[11] | 0),
          (this.Gh = it[12] | 0),
          (this.Gl = it[13] | 0),
          (this.Hh = it[14] | 0),
          (this.Hl = it[15] | 0));
      }
    },
    ft = Uint32Array.from([
      2352822216, 424955298, 1944164710, 2312950998, 502970286, 855612546,
      1738396948, 1479516111, 258812777, 2077511080, 2011393907, 79989058,
      1067287976, 1780299464, 286451373, 2446758561,
    ]),
    dt = Uint32Array.from([
      573645204, 4230739756, 2673172387, 3360449730, 596883563, 1867755857,
      2520282905, 1497426621, 2519219938, 2827943907, 3193839141, 1401305490,
      721525244, 746961066, 246885852, 2177182882,
    ]),
    $n = class extends Le {
      constructor() {
        (super(28),
          (this.Ah = ft[0] | 0),
          (this.Al = ft[1] | 0),
          (this.Bh = ft[2] | 0),
          (this.Bl = ft[3] | 0),
          (this.Ch = ft[4] | 0),
          (this.Cl = ft[5] | 0),
          (this.Dh = ft[6] | 0),
          (this.Dl = ft[7] | 0),
          (this.Eh = ft[8] | 0),
          (this.El = ft[9] | 0),
          (this.Fh = ft[10] | 0),
          (this.Fl = ft[11] | 0),
          (this.Gh = ft[12] | 0),
          (this.Gl = ft[13] | 0),
          (this.Hh = ft[14] | 0),
          (this.Hl = ft[15] | 0));
      }
    },
    Xn = class extends Le {
      constructor() {
        (super(32),
          (this.Ah = dt[0] | 0),
          (this.Al = dt[1] | 0),
          (this.Bh = dt[2] | 0),
          (this.Bl = dt[3] | 0),
          (this.Ch = dt[4] | 0),
          (this.Cl = dt[5] | 0),
          (this.Dh = dt[6] | 0),
          (this.Dl = dt[7] | 0),
          (this.Eh = dt[8] | 0),
          (this.El = dt[9] | 0),
          (this.Fh = dt[10] | 0),
          (this.Fl = dt[11] | 0),
          (this.Gh = dt[12] | 0),
          (this.Gl = dt[13] | 0),
          (this.Hh = dt[14] | 0),
          (this.Hl = dt[15] | 0));
      }
    },
    lr = Zt(() => new xn()),
    ur = Zt(() => new Vn()),
    gn = Zt(() => new Le()),
    hr = Zt(() => new Zn()),
    pr = Zt(() => new Xn()),
    mr = Zt(() => new $n());
  var ot = $,
    Ve = ge;
  function Ze(t, e) {
    if (t.length !== e.length) return !1;
    let n = 0;
    for (let o = 0; o < t.length; o++) n |= t[o] ^ e[o];
    return n === 0;
  }
  function Kt(...t) {
    let e = (o) => (typeof o == "number" ? o : o.bytesLen),
      n = t.reduce((o, r) => o + e(r), 0);
    return {
      bytesLen: n,
      encode: (o) => {
        let r = new Uint8Array(n);
        for (let s = 0, i = 0; s < t.length; s++) {
          let c = t[s],
            a = e(c),
            l = typeof c == "number" ? o[s] : c.encode(o[s]);
          (ot(l, a), r.set(l, i), typeof c != "number" && l.fill(0), (i += a));
        }
        return r;
      },
      decode: (o) => {
        ot(o, n);
        let r = [];
        for (let s of t) {
          let i = e(s),
            c = o.subarray(0, i);
          (r.push(typeof s == "number" ? c : s.decode(c)), (o = o.subarray(i)));
        }
        return r;
      },
    };
  }
  function Mt(t, e) {
    let n = e * t.bytesLen;
    return {
      bytesLen: n,
      encode: (o) => {
        if (o.length !== e)
          throw new Error(
            `vecCoder.encode: wrong length=${o.length}. Expected: ${e}`,
          );
        let r = new Uint8Array(n);
        for (let s = 0, i = 0; s < o.length; s++) {
          let c = t.encode(o[s]);
          (r.set(c, i), c.fill(0), (i += c.length));
        }
        return r;
      },
      decode: (o) => {
        ot(o, n);
        let r = [];
        for (let s = 0; s < o.length; s += t.bytesLen)
          r.push(t.decode(o.subarray(s, s + t.bytesLen)));
        return r;
      },
    };
  }
  function Ot(...t) {
    for (let e of t)
      if (Array.isArray(e)) for (let n of e) n.fill(0);
      else e.fill(0);
  }
  function Yn(t) {
    return (1 << t) - 1;
  }
  var be = new Uint8Array(0);
  function zn(t, e = be) {
    if ((ot(t), ot(e), e.length > 255))
      throw new Error("context should be less than 255 bytes");
    return Vt(new Uint8Array([0, e.length]), e, t);
  }
  var yr = {
    "SHA2-256": { oid: st("0609608648016503040201"), hash: lr },
    "SHA2-384": { oid: st("0609608648016503040202"), hash: hr },
    "SHA2-512": { oid: st("0609608648016503040203"), hash: gn },
    "SHA2-224": { oid: st("0609608648016503040204"), hash: ur },
    "SHA2-512/224": { oid: st("0609608648016503040205"), hash: mr },
    "SHA2-512/256": { oid: st("0609608648016503040206"), hash: pr },
    "SHA3-224": { oid: st("0609608648016503040207"), hash: sr },
    "SHA3-256": { oid: st("0609608648016503040208"), hash: Ut },
    "SHA3-384": { oid: st("0609608648016503040209"), hash: ir },
    "SHA3-512": { oid: st("060960864801650304020A"), hash: vt },
    "SHAKE-128": {
      oid: st("060960864801650304020B"),
      hash: (t) => yn(t, { dkLen: 32 }),
    },
    "SHAKE-256": {
      oid: st("060960864801650304020C"),
      hash: (t) => J(t, { dkLen: 64 }),
    },
  };
  function Wn(t, e, n = be) {
    if ((ot(e), ot(n), n.length > 255))
      throw new Error("context should be less than 255 bytes");
    if (!yr[t]) throw new Error("unknown hash: " + t);
    let { oid: o, hash: r } = yr[t],
      s = r(e);
    return Vt(new Uint8Array([1, n.length]), n, o, s);
  }
  function qs(t, e = 8) {
    let r = t
      .toString(2)
      .padStart(8, "0")
      .slice(-e)
      .padStart(7, "0")
      .split("")
      .reverse()
      .join("");
    return Number.parseInt(r, 2);
  }
  var bn = (t) => {
      let {
          newPoly: e,
          N: n,
          Q: o,
          F: r,
          ROOT_OF_UNITY: s,
          brvBits: i,
          isKyber: c,
        } = t,
        a = (p, h = o) => {
          let g = (p % h) | 0;
          return (g >= 0 ? g | 0 : (h + g) | 0) | 0;
        },
        l = (p, h = o) => {
          let g = a(p, h) | 0;
          return (g > h >> 1 ? (g - h) | 0 : g) | 0;
        };
      function u() {
        let p = e(n);
        for (let h = 0; h < n; h++) {
          let g = qs(h, i),
            y = BigInt(s) ** BigInt(g) % BigInt(o);
          p[h] = Number(y) | 0;
        }
        return p;
      }
      let d = u(),
        f = c ? 128 : n,
        m = c ? 1 : 0;
      return {
        mod: a,
        smod: l,
        nttZetas: d,
        NTT: {
          encode: (p) => {
            for (let h = 1, g = 128; g > m; g >>= 1)
              for (let y = 0; y < n; y += 2 * g) {
                let k = d[h++];
                for (let E = y; E < y + g; E++) {
                  let H = a(k * p[E + g]);
                  ((p[E + g] = a(p[E] - H) | 0), (p[E] = a(p[E] + H) | 0));
                }
              }
            return p;
          },
          decode: (p) => {
            for (let h = f - 1, g = 1 + m; g < f + m; g <<= 1)
              for (let y = 0; y < n; y += 2 * g) {
                let k = d[h--];
                for (let E = y; E < y + g; E++) {
                  let H = p[E];
                  ((p[E] = a(H + p[E + g])),
                    (p[E + g] = a(k * (p[E + g] - H))));
                }
              }
            for (let h = 0; h < p.length; h++) p[h] = a(r * p[h]);
            return p;
          },
        },
        bitsCoder: (p, h) => {
          let g = Yn(p),
            y = p * (n / 8);
          return {
            bytesLen: y,
            encode: (k) => {
              let E = new Uint8Array(y);
              for (let H = 0, O = 0, U = 0, b = 0; H < k.length; H++)
                for (
                  O |= (h.encode(k[H]) & g) << U, U += p;
                  U >= 8;
                  U -= 8, O >>= 8
                )
                  E[b++] = O & Yn(U);
              return E;
            },
            decode: (k) => {
              let E = e(n);
              for (let H = 0, O = 0, U = 0, b = 0; H < k.length; H++)
                for (O |= k[H] << U, U += 8; U >= p; U -= p, O >>= p)
                  E[b++] = h.decode(O & g);
              return E;
            },
          };
        },
      };
    },
    xr = (t) => (e, n) => {
      n || (n = t.blockLen);
      let o = new Uint8Array(e.length + 2);
      o.set(e);
      let r = e.length,
        s = new Uint8Array(n),
        i = t.create({}),
        c = 0,
        a = 0;
      return {
        stats: () => ({ calls: c, xofs: a }),
        get: (l, u) => (
          (o[r + 0] = l),
          (o[r + 1] = u),
          i.destroy(),
          (i = t.create({}).update(o)),
          c++,
          () => (a++, i.xofInto(s))
        ),
        clean: () => {
          (i.destroy(), s.fill(0), o.fill(0));
        },
      };
    },
    He = xr(yn),
    wn = xr(J);
  var lt = 256,
    Yt = 3329,
    Gs = 3303,
    Fs = 17,
    {
      mod: Ye,
      nttZetas: js,
      NTT: we,
      bitsCoder: Vs,
    } = bn({
      N: lt,
      Q: Yt,
      F: Gs,
      ROOT_OF_UNITY: Fs,
      newPoly: (t) => new Uint16Array(t),
      brvBits: 7,
      isKyber: !0,
    }),
    Qn = {
      512: {
        N: lt,
        Q: Yt,
        K: 2,
        ETA1: 3,
        ETA2: 2,
        du: 10,
        dv: 4,
        RBGstrength: 128,
      },
      768: {
        N: lt,
        Q: Yt,
        K: 3,
        ETA1: 2,
        ETA2: 2,
        du: 10,
        dv: 4,
        RBGstrength: 192,
      },
      1024: {
        N: lt,
        Q: Yt,
        K: 4,
        ETA1: 2,
        ETA2: 2,
        du: 11,
        dv: 5,
        RBGstrength: 256,
      },
    },
    Zs = (t) => {
      if (t >= 12) return { encode: (n) => n, decode: (n) => n };
      let e = 2 ** (t - 1);
      return {
        encode: (n) => ((n << t) + Yt / 2) / Yt,
        decode: (n) => (n * Yt + e) >>> t,
      };
    },
    $e = (t) => Vs(t, Zs(t));
  function Be(t, e) {
    for (let n = 0; n < lt; n++) t[n] = Ye(t[n] + e[n]);
  }
  function $s(t, e) {
    for (let n = 0; n < lt; n++) t[n] = Ye(t[n] - e[n]);
  }
  function Xs(t, e, n, o, r) {
    let s = Ye(e * o * r + t * n),
      i = Ye(t * o + e * n);
    return { c0: s, c1: i };
  }
  function Bn(t, e) {
    for (let n = 0; n < lt / 2; n++) {
      let o = js[64 + (n >> 1)];
      n & 1 && (o = -o);
      let { c0: r, c1: s } = Xs(
        t[2 * n + 0],
        t[2 * n + 1],
        e[2 * n + 0],
        e[2 * n + 1],
        o,
      );
      ((t[2 * n + 0] = r), (t[2 * n + 1] = s));
    }
    return t;
  }
  function gr(t) {
    let e = new Uint16Array(lt);
    for (let n = 0; n < lt;) {
      let o = t();
      if (o.length % 3) throw new Error("SampleNTT: unaligned block");
      for (let r = 0; n < lt && r + 3 <= o.length; r += 3) {
        let s = ((o[r + 0] >> 0) | (o[r + 1] << 8)) & 4095,
          i = ((o[r + 1] >> 4) | (o[r + 2] << 4)) & 4095;
        (s < Yt && (e[n++] = s), n < lt && i < Yt && (e[n++] = i));
      }
    }
    return e;
  }
  function Xe(t, e, n, o) {
    let r = t((o * lt) / 4, e, n),
      s = new Uint16Array(lt),
      i = ln(r),
      c = 0;
    for (let a = 0, l = 0, u = 0, d = 0; a < i.length; a++) {
      let f = i[a];
      for (let m = 0; m < 32; m++)
        ((u += f & 1),
          (f >>= 1),
          (c += 1),
          c === o
            ? ((d = u), (u = 0))
            : c === 2 * o && ((s[l++] = Ye(d - u)), (u = 0), (c = 0)));
    }
    if (c) throw new Error(`sampleCBD: leftover bits: ${c}`);
    return s;
  }
  var Ys = (t) => {
    let {
        K: e,
        PRF: n,
        XOF: o,
        HASH512: r,
        ETA1: s,
        ETA2: i,
        du: c,
        dv: a,
      } = t,
      l = $e(1),
      u = $e(a),
      d = $e(c),
      f = Kt(Mt($e(12), e), 32),
      m = Mt($e(12), e),
      x = Kt(Mt(d, e), u),
      B = Kt(32, 32);
    return {
      secretCoder: m,
      secretKeyLen: m.bytesLen,
      publicKeyLen: f.bytesLen,
      cipherTextLen: x.bytesLen,
      keygen: (p) => {
        ot(p, 32);
        let h = new Uint8Array(33);
        (h.set(p), (h[32] = e));
        let g = r(h),
          [y, k] = B.decode(g),
          E = [],
          H = [];
        for (let b = 0; b < e; b++) E.push(we.encode(Xe(n, k, b, s)));
        let O = o(y);
        for (let b = 0; b < e; b++) {
          let A = we.encode(Xe(n, k, e + b, s));
          for (let _ = 0; _ < e; _++) {
            let P = gr(O.get(_, b));
            Be(A, Bn(P, E[_]));
          }
          H.push(A);
        }
        O.clean();
        let U = { publicKey: f.encode([H, y]), secretKey: m.encode(E) };
        return (Ot(y, k, E, H, h, g), U);
      },
      encrypt: (p, h, g) => {
        let [y, k] = f.decode(p),
          E = [];
        for (let _ = 0; _ < e; _++) E.push(we.encode(Xe(n, g, _, s)));
        let H = o(k),
          O = new Uint16Array(lt),
          U = [];
        for (let _ = 0; _ < e; _++) {
          let P = Xe(n, g, e + _, i),
            I = new Uint16Array(lt);
          for (let M = 0; M < e; M++) {
            let K = gr(H.get(_, M));
            Be(I, Bn(K, E[M]));
          }
          (Be(P, we.decode(I)), U.push(P), Be(O, Bn(y[_], E[_])), I.fill(0));
        }
        H.clean();
        let b = Xe(n, g, 2 * e, i);
        Be(b, we.decode(O));
        let A = l.decode(h);
        return (Be(A, b), Ot(y, E, O, b), x.encode([U, A]));
      },
      decrypt: (p, h) => {
        let [g, y] = x.decode(p),
          k = m.decode(h),
          E = new Uint16Array(lt);
        for (let H = 0; H < e; H++) Be(E, Bn(k[H], we.encode(g[H])));
        return ($s(y, we.decode(E)), Ot(E, k, g), l.encode(y));
      },
    };
  };
  function Jn(t) {
    let e = Ys(t),
      { HASH256: n, HASH512: o, KDF: r } = t,
      { secretCoder: s, cipherTextLen: i } = e,
      c = e.publicKeyLen,
      a = Kt(e.secretKeyLen, e.publicKeyLen, 32, 32),
      l = a.bytesLen,
      u = 32;
    return {
      publicKeyLen: c,
      msgLen: u,
      keygen: (d = Ve(64)) => {
        ot(d, 64);
        let { publicKey: f, secretKey: m } = e.keygen(d.subarray(0, 32)),
          x = n(f),
          B = a.encode([m, f, x, d.subarray(32)]);
        return (Ot(m, x), { publicKey: f, secretKey: B });
      },
      encapsulate: (d, f = Ve(32)) => {
        (ot(d, c), ot(f, u));
        let m = d.subarray(0, 384 * t.K),
          x = s.encode(s.decode(m.slice()));
        if (!Ze(x, m))
          throw (
            Ot(x),
            new Error("ML-KEM.encapsulate: wrong publicKey modulus")
          );
        Ot(x);
        let B = o.create().update(f).update(n(d)).digest(),
          p = e.encrypt(d, f, B.subarray(32, 64));
        return (
          B.subarray(32).fill(0),
          { cipherText: p, sharedSecret: B.subarray(0, 32) }
        );
      },
      decapsulate: (d, f) => {
        (ot(f, l), ot(d, i));
        let [m, x, B, p] = a.decode(f),
          h = e.decrypt(d, m),
          g = o.create().update(h).update(B).digest(),
          y = g.subarray(0, 32),
          k = e.encrypt(x, h, g.subarray(32, 64)),
          E = Ze(d, k),
          H = r.create({ dkLen: 32 }).update(p).update(d).digest();
        return (Ot(h, k, E ? H : y), E ? y : H);
      },
    };
  }
  function zs(t, e, n) {
    return J.create({ dkLen: t })
      .update(e)
      .update(new Uint8Array([n]))
      .digest();
  }
  var to = { HASH256: Ut, HASH512: vt, KDF: J, XOF: He, PRF: zs },
    Ec = Jn({ ...to, ...Qn[512] }),
    Ac = Jn({ ...to, ...Qn[768] }),
    En = Jn({ ...to, ...Qn[1024] });
  var F = 256,
    ce = 8380417,
    Ws = 1753,
    Qs = 8347681,
    Se = 13,
    no = Math.floor((ce - 1) / 88) | 0,
    oo = Math.floor((ce - 1) / 32) | 0,
    ro = {
      2: {
        K: 4,
        L: 4,
        D: Se,
        GAMMA1: 2 ** 17,
        GAMMA2: no,
        TAU: 39,
        ETA: 2,
        OMEGA: 80,
      },
      3: {
        K: 6,
        L: 5,
        D: Se,
        GAMMA1: 2 ** 19,
        GAMMA2: oo,
        TAU: 49,
        ETA: 4,
        OMEGA: 55,
      },
      5: {
        K: 8,
        L: 7,
        D: Se,
        GAMMA1: 2 ** 19,
        GAMMA2: oo,
        TAU: 60,
        ETA: 2,
        OMEGA: 75,
      },
    },
    _t = (t) => new Int32Array(t),
    {
      mod: Ae,
      smod: An,
      NTT: mt,
      bitsCoder: Js,
    } = bn({
      N: F,
      Q: ce,
      F: Qs,
      ROOT_OF_UNITY: Ws,
      newPoly: _t,
      isKyber: !1,
      brvBits: 8,
    }),
    br = (t) => t,
    ze = (t, e = br, n = br) =>
      Js(t, { encode: (o) => e(n(o)), decode: (o) => n(e(o)) }),
    Ue = (t, e) => {
      for (let n = 0; n < t.length; n++) t[n] = Ae(t[n] + e[n]);
      return t;
    },
    wr = (t, e) => {
      for (let n = 0; n < t.length; n++) t[n] = Ae(t[n] - e[n]);
      return t;
    },
    ti = (t) => {
      for (let e = 0; e < F; e++) t[e] <<= Se;
      return t;
    },
    We = (t, e) => {
      for (let n = 0; n < F; n++) if (Math.abs(An(t[n])) >= e) return !0;
      return !1;
    },
    Ee = (t, e) => {
      let n = _t(F);
      for (let o = 0; o < t.length; o++) n[o] = Ae(t[o] * e[o]);
      return n;
    };
  function eo(t) {
    let e = _t(F);
    for (let n = 0; n < F;) {
      let o = t();
      if (o.length % 3) throw new Error("RejNTTPoly: unaligned block");
      for (let r = 0; n < F && r <= o.length - 3; r += 3) {
        let s = (o[r + 0] | (o[r + 1] << 8) | (o[r + 2] << 16)) & 8388607;
        s < ce && (e[n++] = s);
      }
    }
    return e;
  }
  function so(t) {
    let { K: e, L: n, GAMMA1: o, GAMMA2: r, TAU: s, ETA: i, OMEGA: c } = t,
      { CRH_BYTES: a, TR_BYTES: l, C_TILDE_BYTES: u, XOF128: d, XOF256: f } = t;
    if (![2, 4].includes(i)) throw new Error("Wrong ETA");
    if (![1 << 17, 1 << 19].includes(o)) throw new Error("Wrong GAMMA1");
    if (![no, oo].includes(r)) throw new Error("Wrong GAMMA2");
    let m = s * i,
      x = (w) => {
        let C = Ae(w),
          S = An(C, 2 * r) | 0;
        return C - S === ce - 1
          ? { r1: 0, r0: (S - 1) | 0 }
          : { r1: Math.floor((C - S) / (2 * r)) | 0, r0: S };
      },
      B = (w) => x(w).r1,
      p = (w) => x(w).r0,
      h = (w, C) => (w <= r || w > ce - r || (w === ce - r && C === 0) ? 0 : 1),
      g = (w, C) => {
        let S = Math.floor((ce - 1) / (2 * r)),
          { r1: L, r0: D } = x(C);
        return w === 1 ? (D > 0 ? Ae(L + 1, S) | 0 : Ae(L - 1, S) | 0) : L | 0;
      },
      y = (w) => {
        let C = Ae(w),
          S = An(C, 2 ** Se) | 0;
        return { r1: Math.floor((C - S) / 2 ** Se) | 0, r0: S };
      },
      k = {
        bytesLen: c + e,
        encode: (w) => {
          if (w === !1) throw new Error("hint.encode: hint is false");
          let C = new Uint8Array(c + e);
          for (let S = 0, L = 0; S < e; S++) {
            for (let D = 0; D < F; D++) w[S][D] !== 0 && (C[L++] = D);
            C[c + S] = L;
          }
          return C;
        },
        decode: (w) => {
          let C = [],
            S = 0;
          for (let L = 0; L < e; L++) {
            let D = _t(F);
            if (w[c + L] < S || w[c + L] > c) return !1;
            for (let R = S; R < w[c + L]; R++) {
              if (R > S && w[R] <= w[R - 1]) return !1;
              D[w[R]] = 1;
            }
            ((S = w[c + L]), C.push(D));
          }
          for (let L = S; L < c; L++) if (w[L] !== 0) return !1;
          return C;
        },
      },
      E = ze(
        i === 2 ? 3 : 4,
        (w) => i - w,
        (w) => {
          if (!(-i <= w && w <= i))
            throw new Error(
              `malformed key s1/s3 ${w} outside of ETA range [${-i}, ${i}]`,
            );
          return w;
        },
      ),
      H = ze(13, (w) => (1 << (Se - 1)) - w),
      O = ze(10),
      U = ze(o === 1 << 17 ? 18 : 20, (w) => An(o - w)),
      b = ze(r === no ? 6 : 4),
      A = Mt(b, e),
      _ = Kt(32, Mt(O, e)),
      P = Kt(32, 32, l, Mt(E, n), Mt(E, e), Mt(H, e)),
      I = Kt(u, Mt(U, n), k),
      M =
        i === 2
          ? (w) => (w < 15 ? 2 - (w % 5) : !1)
          : (w) => (w < 9 ? 4 - w : !1);
    function K(w) {
      let C = _t(F);
      for (let S = 0; S < F;) {
        let L = w();
        for (let D = 0; S < F && D < L.length; D += 1) {
          let R = M(L[D] & 15),
            Q = M((L[D] >> 4) & 15);
          (R !== !1 && (C[S++] = R), S < F && Q !== !1 && (C[S++] = Q));
        }
      }
      return C;
    }
    let Z = (w) => {
        let C = _t(F),
          S = J.create({}).update(w),
          L = new Uint8Array(J.blockLen);
        S.xofInto(L);
        let D = L.slice(0, 8);
        for (let R = F - s, Q = 8, at = 0, et = 0; R < F; R++) {
          let nt = R + 1;
          for (; nt > R;)
            ((nt = L[Q++]), !(Q < J.blockLen) && (S.xofInto(L), (Q = 0)));
          ((C[R] = C[nt]),
            (C[nt] = 1 - (((D[at] >> et++) & 1) << 1)),
            et >= 8 && (at++, (et = 0)));
        }
        return C;
      },
      z = (w) => {
        let C = _t(F),
          S = _t(F);
        for (let L = 0; L < w.length; L++) {
          let { r0: D, r1: R } = y(w[L]);
          ((C[L] = D), (S[L] = R));
        }
        return { r0: C, r1: S };
      },
      tt = (w, C) => {
        for (let S = 0; S < F; S++) w[S] = g(C[S], w[S]);
        return w;
      },
      W = (w, C) => {
        let S = _t(F),
          L = 0;
        for (let D = 0; D < F; D++) {
          let R = h(w[D], C[D]);
          ((S[D] = R), (L += R));
        }
        return { v: S, cnt: L };
      },
      pt = 32,
      xt = Kt(32, 64, 32),
      Bt = {
        signRandBytes: pt,
        keygen: (w) => {
          let C = new Uint8Array(34),
            S = w === void 0;
          (S && (w = Ve(32)),
            ot(w, 32),
            C.set(w),
            S && w.fill(0),
            (C[32] = e),
            (C[33] = n));
          let [L, D, R] = xt.decode(J(C, { dkLen: xt.bytesLen })),
            Q = f(D),
            at = [];
          for (let q = 0; q < n; q++)
            at.push(K(Q.get(q & 255, (q >> 8) & 255)));
          let et = [];
          for (let q = n; q < n + e; q++)
            et.push(K(Q.get(q & 255, (q >> 8) & 255)));
          let nt = at.map((q) => mt.encode(q.slice())),
            St = [],
            Tt = [],
            kt = d(L),
            Ct = _t(F);
          for (let q = 0; q < e; q++) {
            Ct.fill(0);
            for (let At = 0; At < n; At++) {
              let ue = eo(kt.get(At, q));
              Ue(Ct, Ee(ue, nt[At]));
            }
            mt.decode(Ct);
            let { r0: Et, r1: Nt } = z(Ue(Ct, et[q]));
            (St.push(Et), Tt.push(Nt));
          }
          let Gt = _.encode([L, Tt]),
            le = J(Gt, { dkLen: l }),
            N = P.encode([L, R, le, at, et, St]);
          return (
            kt.clean(),
            Q.clean(),
            Ot(L, D, R, at, et, nt, Ct, St, Tt, le, C),
            { publicKey: Gt, secretKey: N }
          );
        },
        sign: (w, C, S, L = !1) => {
          let [D, R, Q, at, et, nt] = P.decode(w),
            St = [],
            Tt = d(D);
          for (let N = 0; N < e; N++) {
            let q = [];
            for (let Et = 0; Et < n; Et++) q.push(eo(Tt.get(Et, N)));
            St.push(q);
          }
          Tt.clean();
          for (let N = 0; N < n; N++) mt.encode(at[N]);
          for (let N = 0; N < e; N++) (mt.encode(et[N]), mt.encode(nt[N]));
          let kt = L ? C : J.create({ dkLen: a }).update(Q).update(C).digest(),
            Ct = S || new Uint8Array(32);
          ot(Ct);
          let Gt = J.create({ dkLen: a })
            .update(R)
            .update(Ct)
            .update(kt)
            .digest();
          ot(Gt, a);
          let le = f(Gt, U.bytesLen);
          t: for (let N = 0; ;) {
            let q = [];
            for (let G = 0; G < n; G++, N++)
              q.push(U.decode(le.get(N & 255, N >> 8)()));
            let Et = q.map((G) => mt.encode(G.slice())),
              Nt = [];
            for (let G = 0; G < e; G++) {
              let Re = _t(F);
              for (let ne = 0; ne < n; ne++) Ue(Re, Ee(St[G][ne], Et[ne]));
              (mt.decode(Re), Nt.push(Re));
            }
            let At = Nt.map((G) => G.map(B)),
              ue = J.create({ dkLen: u })
                .update(kt)
                .update(A.encode(At))
                .digest(),
              sn = mt.encode(Z(ue)),
              cn = at.map((G) => Ee(G, sn));
            for (let G = 0; G < n; G++)
              if ((Ue(mt.decode(cn[G]), q[G]), We(cn[G], o - m))) continue t;
            let Do = 0,
              qn = [];
            for (let G = 0; G < e; G++) {
              let Re = mt.decode(Ee(et[G], sn)),
                ne = wr(Nt[G], Re).map(p);
              if (We(ne, r - m)) continue t;
              let No = mt.decode(Ee(nt[G], sn));
              if (We(No, r)) continue t;
              Ue(ne, No);
              let Po = W(ne, At[G]);
              (qn.push(Po.v), (Do += Po.cnt));
            }
            if (Do > c) continue;
            le.clean();
            let Es = I.encode([ue, cn, qn]);
            return (
              Ot(ue, cn, qn, sn, At, Nt, Et, q, Gt, kt, at, et, nt, ...St),
              Es
            );
          }
          throw new Error("Unreachable code path reached, report this error");
        },
        verify: (w, C, S, L = !1) => {
          let [D, R] = _.decode(w),
            Q = J(w, { dkLen: l });
          if (S.length !== I.bytesLen) return !1;
          let [at, et, nt] = I.decode(S);
          if (nt === !1) return !1;
          for (let N = 0; N < n; N++) if (We(et[N], o - m)) return !1;
          let St = L ? C : J.create({ dkLen: a }).update(Q).update(C).digest(),
            Tt = mt.encode(Z(at)),
            kt = et.map((N) => N.slice());
          for (let N = 0; N < n; N++) mt.encode(kt[N]);
          let Ct = [],
            Gt = d(D);
          for (let N = 0; N < e; N++) {
            let q = Ee(mt.encode(ti(R[N])), Tt),
              Et = _t(F);
            for (let At = 0; At < n; At++) {
              let ue = eo(Gt.get(At, N));
              Ue(Et, Ee(ue, kt[At]));
            }
            let Nt = mt.decode(wr(Et, q));
            Ct.push(tt(Nt, nt[N]));
          }
          Gt.clean();
          let le = J.create({ dkLen: u })
            .update(St)
            .update(A.encode(Ct))
            .digest();
          for (let N of nt)
            if (!(N.reduce((Et, Nt) => Et + Nt, 0) <= c)) return !1;
          for (let N of et) if (We(N, o - m)) return !1;
          return Ze(at, le);
        },
      };
    return {
      internal: Bt,
      keygen: Bt.keygen,
      signRandBytes: Bt.signRandBytes,
      sign: (w, C, S = be, L) => {
        let D = zn(C, S),
          R = Bt.sign(w, D, L);
        return (D.fill(0), R);
      },
      verify: (w, C, S, L = be) => Bt.verify(w, zn(C, L), S),
      prehash: (w) => ({
        sign: (C, S, L = be, D) => {
          let R = Wn(w, S, L),
            Q = Bt.sign(C, R, D);
          return (R.fill(0), Q);
        },
        verify: (C, S, L, D = be) => Bt.verify(C, Wn(w, S, D), L),
      }),
    };
  }
  var Ic = so({
      ...ro[2],
      CRH_BYTES: 64,
      TR_BYTES: 64,
      C_TILDE_BYTES: 32,
      XOF128: He,
      XOF256: wn,
    }),
    Tc = so({
      ...ro[3],
      CRH_BYTES: 64,
      TR_BYTES: 64,
      C_TILDE_BYTES: 48,
      XOF128: He,
      XOF256: wn,
    }),
    Sn = so({
      ...ro[5],
      CRH_BYTES: 64,
      TR_BYTES: 64,
      C_TILDE_BYTES: 64,
      XOF128: He,
      XOF256: wn,
    });
  var ao = BigInt(0),
    co = BigInt(1);
  function kn(t, e = "") {
    if (typeof t != "boolean") {
      let n = e && `"${e}"`;
      throw new Error(n + "expected boolean, got type=" + typeof t);
    }
    return t;
  }
  function Qe(t, e, n = "") {
    let o = ye(t),
      r = t?.length,
      s = e !== void 0;
    if (!o || (s && r !== e)) {
      let i = n && `"${n}" `,
        c = s ? ` of length ${e}` : "",
        a = o ? `length=${r}` : `type=${typeof t}`;
      throw new Error(i + "expected Uint8Array" + c + ", got " + a);
    }
    return t;
  }
  function Br(t) {
    if (typeof t != "string")
      throw new Error("hex string expected, got " + typeof t);
    return t === "" ? ao : BigInt("0x" + t);
  }
  function Er(t) {
    return Br(xe(t));
  }
  function Dt(t) {
    return ($(t), Br(xe(Uint8Array.from(t).reverse())));
  }
  function fo(t, e) {
    return st(t.toString(16).padStart(e * 2, "0"));
  }
  function vn(t, e) {
    return fo(t, e).reverse();
  }
  function ut(t, e, n) {
    let o;
    if (typeof e == "string")
      try {
        o = st(e);
      } catch (s) {
        throw new Error(t + " must be hex string or Uint8Array, cause: " + s);
      }
    else if (ye(e)) o = Uint8Array.from(e);
    else throw new Error(t + " must be hex string or Uint8Array");
    let r = o.length;
    if (typeof n == "number" && r !== n)
      throw new Error(t + " of length " + n + " expected, got " + r);
    return o;
  }
  function Ar(t, e) {
    if (t.length !== e.length) return !1;
    let n = 0;
    for (let o = 0; o < t.length; o++) n |= t[o] ^ e[o];
    return n === 0;
  }
  function lo(t) {
    return Uint8Array.from(t);
  }
  var io = (t) => typeof t == "bigint" && ao <= t;
  function ei(t, e, n) {
    return io(t) && io(e) && io(n) && e <= t && t < n;
  }
  function Me(t, e, n, o) {
    if (!ei(e, n, o))
      throw new Error(
        "expected valid " + t + ": " + n + " <= n < " + o + ", got " + e,
      );
  }
  function Sr(t) {
    let e;
    for (e = 0; t > ao; t >>= co, e += 1);
    return e;
  }
  var Je = (t) => (co << BigInt(t)) - co;
  function ke(t, e, n = {}) {
    if (!t || typeof t != "object")
      throw new Error("expected valid options object");
    function o(r, s, i) {
      let c = t[r];
      if (i && c === void 0) return;
      let a = typeof c;
      if (a !== s || c === null)
        throw new Error(`param "${r}" is invalid: expected ${s}, got ${a}`);
    }
    (Object.entries(e).forEach(([r, s]) => o(r, s, !1)),
      Object.entries(n).forEach(([r, s]) => o(r, s, !0)));
  }
  var uo = () => {
    throw new Error("not implemented");
  };
  function ho(t) {
    let e = new WeakMap();
    return (n, ...o) => {
      let r = e.get(n);
      if (r !== void 0) return r;
      let s = t(n, ...o);
      return (e.set(n, s), s);
    };
  }
  var yt = BigInt(0),
    ht = BigInt(1),
    ve = BigInt(2),
    _r = BigInt(3),
    Ir = BigInt(4),
    Tr = BigInt(5),
    ni = BigInt(7),
    Cr = BigInt(8),
    oi = BigInt(9),
    Lr = BigInt(16);
  function j(t, e) {
    let n = t % e;
    return n >= yt ? n : e + n;
  }
  function It(t, e, n) {
    let o = t;
    for (; e-- > yt;) ((o *= o), (o %= n));
    return o;
  }
  function kr(t, e) {
    if (t === yt) throw new Error("invert: expected non-zero number");
    if (e <= yt) throw new Error("invert: expected positive modulus, got " + e);
    let n = j(t, e),
      o = e,
      r = yt,
      s = ht,
      i = ht,
      c = yt;
    for (; n !== yt;) {
      let l = o / n,
        u = o % n,
        d = r - i * l,
        f = s - c * l;
      ((o = n), (n = u), (r = i), (s = c), (i = d), (c = f));
    }
    if (o !== ht) throw new Error("invert: does not exist");
    return j(r, e);
  }
  function po(t, e, n) {
    if (!t.eql(t.sqr(e), n)) throw new Error("Cannot find square root");
  }
  function Hr(t, e) {
    let n = (t.ORDER + ht) / Ir,
      o = t.pow(e, n);
    return (po(t, o, e), o);
  }
  function ri(t, e) {
    let n = (t.ORDER - Tr) / Cr,
      o = t.mul(e, ve),
      r = t.pow(o, n),
      s = t.mul(e, r),
      i = t.mul(t.mul(s, ve), r),
      c = t.mul(s, t.sub(i, t.ONE));
    return (po(t, c, e), c);
  }
  function si(t) {
    let e = Wt(t),
      n = Ur(t),
      o = n(e, e.neg(e.ONE)),
      r = n(e, o),
      s = n(e, e.neg(o)),
      i = (t + ni) / Lr;
    return (c, a) => {
      let l = c.pow(a, i),
        u = c.mul(l, o),
        d = c.mul(l, r),
        f = c.mul(l, s),
        m = c.eql(c.sqr(u), a),
        x = c.eql(c.sqr(d), a);
      ((l = c.cmov(l, u, m)), (u = c.cmov(f, d, x)));
      let B = c.eql(c.sqr(u), a),
        p = c.cmov(l, u, B);
      return (po(c, p, a), p);
    };
  }
  function Ur(t) {
    if (t < _r) throw new Error("sqrt is not defined for small field");
    let e = t - ht,
      n = 0;
    for (; e % ve === yt;) ((e /= ve), n++);
    let o = ve,
      r = Wt(t);
    for (; vr(r, o) === 1;)
      if (o++ > 1e3)
        throw new Error("Cannot find square root: probably non-prime P");
    if (n === 1) return Hr;
    let s = r.pow(o, e),
      i = (e + ht) / ve;
    return function (a, l) {
      if (a.is0(l)) return l;
      if (vr(a, l) !== 1) throw new Error("Cannot find square root");
      let u = n,
        d = a.mul(a.ONE, s),
        f = a.pow(l, e),
        m = a.pow(l, i);
      for (; !a.eql(f, a.ONE);) {
        if (a.is0(f)) return a.ZERO;
        let x = 1,
          B = a.sqr(f);
        for (; !a.eql(B, a.ONE);)
          if ((x++, (B = a.sqr(B)), x === u))
            throw new Error("Cannot find square root");
        let p = ht << BigInt(u - x - 1),
          h = a.pow(d, p);
        ((u = x), (d = a.sqr(h)), (f = a.mul(f, d)), (m = a.mul(m, h)));
      }
      return m;
    };
  }
  function ii(t) {
    return t % Ir === _r
      ? Hr
      : t % Cr === Tr
        ? ri
        : t % Lr === oi
          ? si(t)
          : Ur(t);
  }
  var zt = (t, e) => (j(t, e) & ht) === ht,
    ci = [
      "create",
      "isValid",
      "is0",
      "neg",
      "inv",
      "sqrt",
      "sqr",
      "eql",
      "add",
      "sub",
      "mul",
      "pow",
      "div",
      "addN",
      "subN",
      "mulN",
      "sqrN",
    ];
  function Mr(t) {
    let e = {
        ORDER: "bigint",
        MASK: "bigint",
        BYTES: "number",
        BITS: "number",
      },
      n = ci.reduce((o, r) => ((o[r] = "function"), o), e);
    return (ke(t, n), t);
  }
  function ai(t, e, n) {
    if (n < yt) throw new Error("invalid exponent, negatives unsupported");
    if (n === yt) return t.ONE;
    if (n === ht) return e;
    let o = t.ONE,
      r = e;
    for (; n > yt;) (n & ht && (o = t.mul(o, r)), (r = t.sqr(r)), (n >>= ht));
    return o;
  }
  function _n(t, e, n = !1) {
    let o = new Array(e.length).fill(n ? t.ZERO : void 0),
      r = e.reduce(
        (i, c, a) => (t.is0(c) ? i : ((o[a] = i), t.mul(i, c))),
        t.ONE,
      ),
      s = t.inv(r);
    return (
      e.reduceRight(
        (i, c, a) => (t.is0(c) ? i : ((o[a] = t.mul(i, o[a])), t.mul(i, c))),
        s,
      ),
      o
    );
  }
  function vr(t, e) {
    let n = (t.ORDER - ht) / ve,
      o = t.pow(e, n),
      r = t.eql(o, t.ONE),
      s = t.eql(o, t.ZERO),
      i = t.eql(o, t.neg(t.ONE));
    if (!r && !s && !i) throw new Error("invalid Legendre symbol result");
    return r ? 1 : s ? 0 : -1;
  }
  function Or(t, e) {
    e !== void 0 && Rt(e);
    let n = e !== void 0 ? e : t.toString(2).length,
      o = Math.ceil(n / 8);
    return { nBitLength: n, nByteLength: o };
  }
  function Wt(t, e, n = !1, o = {}) {
    if (t <= yt) throw new Error("invalid field: expected ORDER > 0, got " + t);
    let r,
      s,
      i = !1,
      c;
    if (typeof e == "object" && e != null) {
      if (o.sqrt || n) throw new Error("cannot specify opts in two arguments");
      let f = e;
      (f.BITS && (r = f.BITS),
        f.sqrt && (s = f.sqrt),
        typeof f.isLE == "boolean" && (n = f.isLE),
        typeof f.modFromBytes == "boolean" && (i = f.modFromBytes),
        (c = f.allowedLengths));
    } else (typeof e == "number" && (r = e), o.sqrt && (s = o.sqrt));
    let { nBitLength: a, nByteLength: l } = Or(t, r);
    if (l > 2048)
      throw new Error("invalid field: expected ORDER of <= 2048 bytes");
    let u,
      d = Object.freeze({
        ORDER: t,
        isLE: n,
        BITS: a,
        BYTES: l,
        MASK: Je(a),
        ZERO: yt,
        ONE: ht,
        allowedLengths: c,
        create: (f) => j(f, t),
        isValid: (f) => {
          if (typeof f != "bigint")
            throw new Error(
              "invalid field element: expected bigint, got " + typeof f,
            );
          return yt <= f && f < t;
        },
        is0: (f) => f === yt,
        isValidNot0: (f) => !d.is0(f) && d.isValid(f),
        isOdd: (f) => (f & ht) === ht,
        neg: (f) => j(-f, t),
        eql: (f, m) => f === m,
        sqr: (f) => j(f * f, t),
        add: (f, m) => j(f + m, t),
        sub: (f, m) => j(f - m, t),
        mul: (f, m) => j(f * m, t),
        pow: (f, m) => ai(d, f, m),
        div: (f, m) => j(f * kr(m, t), t),
        sqrN: (f) => f * f,
        addN: (f, m) => f + m,
        subN: (f, m) => f - m,
        mulN: (f, m) => f * m,
        inv: (f) => kr(f, t),
        sqrt: s || ((f) => (u || (u = ii(t)), u(d, f))),
        toBytes: (f) => (n ? vn(f, l) : fo(f, l)),
        fromBytes: (f, m = !0) => {
          if (c) {
            if (!c.includes(f.length) || f.length > l)
              throw new Error(
                "Field.fromBytes: expected " + c + " bytes, got " + f.length,
              );
            let B = new Uint8Array(l);
            (B.set(f, n ? 0 : B.length - f.length), (f = B));
          }
          if (f.length !== l)
            throw new Error(
              "Field.fromBytes: expected " + l + " bytes, got " + f.length,
            );
          let x = n ? Dt(f) : Er(f);
          if ((i && (x = j(x, t)), !m && !d.isValid(x)))
            throw new Error("invalid field element: outside of range 0..ORDER");
          return x;
        },
        invertBatch: (f) => _n(d, f),
        cmov: (f, m, x) => (x ? m : f),
      });
    return Object.freeze(d);
  }
  var In = BigInt(0),
    go = BigInt(1);
  function Dr(t, e) {
    let n = e.negate();
    return t ? n : e;
  }
  function tn(t, e) {
    let n = _n(
      t.Fp,
      e.map((o) => o.Z),
    );
    return e.map((o, r) => t.fromAffine(o.toAffine(n[r])));
  }
  function Kr(t, e) {
    if (!Number.isSafeInteger(t) || t <= 0 || t > e)
      throw new Error(
        "invalid window size, expected [1.." + e + "], got W=" + t,
      );
  }
  function mo(t, e) {
    Kr(t, e);
    let n = Math.ceil(e / t) + 1,
      o = 2 ** (t - 1),
      r = 2 ** t,
      s = Je(t),
      i = BigInt(t);
    return { windows: n, windowSize: o, mask: s, maxNumber: r, shiftBy: i };
  }
  function Nr(t, e, n) {
    let { windowSize: o, mask: r, maxNumber: s, shiftBy: i } = n,
      c = Number(t & r),
      a = t >> i;
    c > o && ((c -= s), (a += go));
    let l = e * o,
      u = l + Math.abs(c) - 1,
      d = c === 0,
      f = c < 0,
      m = e % 2 !== 0;
    return { nextN: a, offset: u, isZero: d, isNeg: f, isNegF: m, offsetF: l };
  }
  function fi(t, e) {
    if (!Array.isArray(t)) throw new Error("array expected");
    t.forEach((n, o) => {
      if (!(n instanceof e)) throw new Error("invalid point at index " + o);
    });
  }
  function di(t, e) {
    if (!Array.isArray(t)) throw new Error("array of scalars expected");
    t.forEach((n, o) => {
      if (!e.isValid(n)) throw new Error("invalid scalar at index " + o);
    });
  }
  var yo = new WeakMap(),
    qr = new WeakMap();
  function xo(t) {
    return qr.get(t) || 1;
  }
  function Pr(t) {
    if (t !== In) throw new Error("invalid wNAF");
  }
  var Tn = class {
    constructor(e, n) {
      ((this.BASE = e.BASE),
        (this.ZERO = e.ZERO),
        (this.Fn = e.Fn),
        (this.bits = n));
    }
    _unsafeLadder(e, n, o = this.ZERO) {
      let r = e;
      for (; n > In;) (n & go && (o = o.add(r)), (r = r.double()), (n >>= go));
      return o;
    }
    precomputeWindow(e, n) {
      let { windows: o, windowSize: r } = mo(n, this.bits),
        s = [],
        i = e,
        c = i;
      for (let a = 0; a < o; a++) {
        ((c = i), s.push(c));
        for (let l = 1; l < r; l++) ((c = c.add(i)), s.push(c));
        i = c.double();
      }
      return s;
    }
    wNAF(e, n, o) {
      if (!this.Fn.isValid(o)) throw new Error("invalid scalar");
      let r = this.ZERO,
        s = this.BASE,
        i = mo(e, this.bits);
      for (let c = 0; c < i.windows; c++) {
        let {
          nextN: a,
          offset: l,
          isZero: u,
          isNeg: d,
          isNegF: f,
          offsetF: m,
        } = Nr(o, c, i);
        ((o = a), u ? (s = s.add(Dr(f, n[m]))) : (r = r.add(Dr(d, n[l]))));
      }
      return (Pr(o), { p: r, f: s });
    }
    wNAFUnsafe(e, n, o, r = this.ZERO) {
      let s = mo(e, this.bits);
      for (let i = 0; i < s.windows && o !== In; i++) {
        let { nextN: c, offset: a, isZero: l, isNeg: u } = Nr(o, i, s);
        if (((o = c), !l)) {
          let d = n[a];
          r = r.add(u ? d.negate() : d);
        }
      }
      return (Pr(o), r);
    }
    getPrecomputes(e, n, o) {
      let r = yo.get(n);
      return (
        r ||
          ((r = this.precomputeWindow(n, e)),
          e !== 1 && (typeof o == "function" && (r = o(r)), yo.set(n, r))),
        r
      );
    }
    cached(e, n, o) {
      let r = xo(e);
      return this.wNAF(r, this.getPrecomputes(r, e, o), n);
    }
    unsafe(e, n, o, r) {
      let s = xo(e);
      return s === 1
        ? this._unsafeLadder(e, n, r)
        : this.wNAFUnsafe(s, this.getPrecomputes(s, e, o), n, r);
    }
    createCache(e, n) {
      (Kr(n, this.bits), qr.set(e, n), yo.delete(e));
    }
    hasCache(e) {
      return xo(e) !== 1;
    }
  };
  function Cn(t, e, n, o) {
    (fi(n, t), di(o, e));
    let r = n.length,
      s = o.length;
    if (r !== s)
      throw new Error("arrays of points and scalars must have equal length");
    let i = t.ZERO,
      c = Sr(BigInt(r)),
      a = 1;
    c > 12 ? (a = c - 3) : c > 4 ? (a = c - 2) : c > 0 && (a = 2);
    let l = Je(a),
      u = new Array(Number(l) + 1).fill(i),
      d = Math.floor((e.BITS - 1) / a) * a,
      f = i;
    for (let m = d; m >= 0; m -= a) {
      u.fill(i);
      for (let B = 0; B < s; B++) {
        let p = o[B],
          h = Number((p >> BigInt(m)) & l);
        u[h] = u[h].add(n[B]);
      }
      let x = i;
      for (let B = u.length - 1, p = i; B > 0; B--)
        ((p = p.add(u[B])), (x = x.add(p)));
      if (((f = f.add(x)), m !== 0)) for (let B = 0; B < a; B++) f = f.double();
    }
    return f;
  }
  function Rr(t, e, n) {
    if (e) {
      if (e.ORDER !== t)
        throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
      return (Mr(e), e);
    } else return Wt(t, { isLE: n });
  }
  function Gr(t, e, n = {}, o) {
    if ((o === void 0 && (o = t === "edwards"), !e || typeof e != "object"))
      throw new Error(`expected valid ${t} CURVE object`);
    for (let a of ["p", "n", "h"]) {
      let l = e[a];
      if (!(typeof l == "bigint" && l > In))
        throw new Error(`CURVE.${a} must be positive bigint`);
    }
    let r = Rr(e.p, n.Fp, o),
      s = Rr(e.n, n.Fn, o),
      c = ["Gx", "Gy", "a", t === "weierstrass" ? "b" : "d"];
    for (let a of c)
      if (!r.isValid(e[a]))
        throw new Error(`CURVE.${a} must be valid field element of CURVE.Fp`);
    return (
      (e = Object.freeze(Object.assign({}, e))),
      { CURVE: e, Fp: r, Fn: s }
    );
  }
  var ae = BigInt(0),
    rt = BigInt(1),
    bo = BigInt(2),
    li = BigInt(8);
  function ui(t, e, n, o) {
    let r = t.sqr(n),
      s = t.sqr(o),
      i = t.add(t.mul(e.a, r), s),
      c = t.add(t.ONE, t.mul(e.d, t.mul(r, s)));
    return t.eql(i, c);
  }
  function hi(t, e = {}) {
    let n = Gr("edwards", t, e, e.FpFnLE),
      { Fp: o, Fn: r } = n,
      s = n.CURVE,
      { h: i } = s;
    ke(e, {}, { uvRatio: "function" });
    let c = bo << (BigInt(r.BYTES * 8) - rt),
      a = (p) => o.create(p),
      l =
        e.uvRatio ||
        ((p, h) => {
          try {
            return { isValid: !0, value: o.sqrt(o.div(p, h)) };
          } catch {
            return { isValid: !1, value: ae };
          }
        });
    if (!ui(o, s, s.Gx, s.Gy))
      throw new Error("bad curve params: generator point");
    function u(p, h, g = !1) {
      let y = g ? rt : ae;
      return (Me("coordinate " + p, h, y, c), h);
    }
    function d(p) {
      if (!(p instanceof x)) throw new Error("ExtendedPoint expected");
    }
    let f = ho((p, h) => {
        let { X: g, Y: y, Z: k } = p,
          E = p.is0();
        h == null && (h = E ? li : o.inv(k));
        let H = a(g * h),
          O = a(y * h),
          U = o.mul(k, h);
        if (E) return { x: ae, y: rt };
        if (U !== rt) throw new Error("invZ was invalid");
        return { x: H, y: O };
      }),
      m = ho((p) => {
        let { a: h, d: g } = s;
        if (p.is0()) throw new Error("bad point: ZERO");
        let { X: y, Y: k, Z: E, T: H } = p,
          O = a(y * y),
          U = a(k * k),
          b = a(E * E),
          A = a(b * b),
          _ = a(O * h),
          P = a(b * a(_ + U)),
          I = a(A + a(g * a(O * U)));
        if (P !== I) throw new Error("bad point: equation left != right (1)");
        let M = a(y * k),
          K = a(E * H);
        if (M !== K) throw new Error("bad point: equation left != right (2)");
        return !0;
      });
    class x {
      constructor(h, g, y, k) {
        ((this.X = u("x", h)),
          (this.Y = u("y", g)),
          (this.Z = u("z", y, !0)),
          (this.T = u("t", k)),
          Object.freeze(this));
      }
      static CURVE() {
        return s;
      }
      static fromAffine(h) {
        if (h instanceof x) throw new Error("extended point not allowed");
        let { x: g, y } = h || {};
        return (u("x", g), u("y", y), new x(g, y, rt, a(g * y)));
      }
      static fromBytes(h, g = !1) {
        let y = o.BYTES,
          { a: k, d: E } = s;
        ((h = lo(Qe(h, y, "point"))), kn(g, "zip215"));
        let H = lo(h),
          O = h[y - 1];
        H[y - 1] = O & -129;
        let U = Dt(H),
          b = g ? c : o.ORDER;
        Me("point.y", U, ae, b);
        let A = a(U * U),
          _ = a(A - rt),
          P = a(E * A - k),
          { isValid: I, value: M } = l(_, P);
        if (!I) throw new Error("bad point: invalid y coordinate");
        let K = (M & rt) === rt,
          Z = (O & 128) !== 0;
        if (!g && M === ae && Z) throw new Error("bad point: x=0 and x_0=1");
        return (Z !== K && (M = a(-M)), x.fromAffine({ x: M, y: U }));
      }
      static fromHex(h, g = !1) {
        return x.fromBytes(ut("point", h), g);
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      precompute(h = 8, g = !0) {
        return (B.createCache(this, h), g || this.multiply(bo), this);
      }
      assertValidity() {
        m(this);
      }
      equals(h) {
        d(h);
        let { X: g, Y: y, Z: k } = this,
          { X: E, Y: H, Z: O } = h,
          U = a(g * O),
          b = a(E * k),
          A = a(y * O),
          _ = a(H * k);
        return U === b && A === _;
      }
      is0() {
        return this.equals(x.ZERO);
      }
      negate() {
        return new x(a(-this.X), this.Y, this.Z, a(-this.T));
      }
      double() {
        let { a: h } = s,
          { X: g, Y: y, Z: k } = this,
          E = a(g * g),
          H = a(y * y),
          O = a(bo * a(k * k)),
          U = a(h * E),
          b = g + y,
          A = a(a(b * b) - E - H),
          _ = U + H,
          P = _ - O,
          I = U - H,
          M = a(A * P),
          K = a(_ * I),
          Z = a(A * I),
          z = a(P * _);
        return new x(M, K, z, Z);
      }
      add(h) {
        d(h);
        let { a: g, d: y } = s,
          { X: k, Y: E, Z: H, T: O } = this,
          { X: U, Y: b, Z: A, T: _ } = h,
          P = a(k * U),
          I = a(E * b),
          M = a(O * y * _),
          K = a(H * A),
          Z = a((k + E) * (U + b) - P - I),
          z = K - M,
          tt = K + M,
          W = a(I - g * P),
          pt = a(Z * z),
          xt = a(tt * W),
          Bt = a(Z * W),
          w = a(z * tt);
        return new x(pt, xt, w, Bt);
      }
      subtract(h) {
        return this.add(h.negate());
      }
      multiply(h) {
        if (!r.isValidNot0(h))
          throw new Error("invalid scalar: expected 1 <= sc < curve.n");
        let { p: g, f: y } = B.cached(this, h, (k) => tn(x, k));
        return tn(x, [g, y])[0];
      }
      multiplyUnsafe(h, g = x.ZERO) {
        if (!r.isValid(h))
          throw new Error("invalid scalar: expected 0 <= sc < curve.n");
        return h === ae
          ? x.ZERO
          : this.is0() || h === rt
            ? this
            : B.unsafe(this, h, (y) => tn(x, y), g);
      }
      isSmallOrder() {
        return this.multiplyUnsafe(i).is0();
      }
      isTorsionFree() {
        return B.unsafe(this, s.n).is0();
      }
      toAffine(h) {
        return f(this, h);
      }
      clearCofactor() {
        return i === rt ? this : this.multiplyUnsafe(i);
      }
      toBytes() {
        let { x: h, y: g } = this.toAffine(),
          y = o.toBytes(g);
        return ((y[y.length - 1] |= h & rt ? 128 : 0), y);
      }
      toHex() {
        return xe(this.toBytes());
      }
      toString() {
        return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
      }
      get ex() {
        return this.X;
      }
      get ey() {
        return this.Y;
      }
      get ez() {
        return this.Z;
      }
      get et() {
        return this.T;
      }
      static normalizeZ(h) {
        return tn(x, h);
      }
      static msm(h, g) {
        return Cn(x, r, h, g);
      }
      _setWindowSize(h) {
        this.precompute(h);
      }
      toRawBytes() {
        return this.toBytes();
      }
    }
    ((x.BASE = new x(s.Gx, s.Gy, rt, a(s.Gx * s.Gy))),
      (x.ZERO = new x(ae, rt, rt, ae)),
      (x.Fp = o),
      (x.Fn = r));
    let B = new Tn(x, r.BITS);
    return (x.BASE.precompute(8), x);
  }
  var Ln = class {
    constructor(e) {
      this.ep = e;
    }
    static fromBytes(e) {
      uo();
    }
    static fromHex(e) {
      uo();
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    clearCofactor() {
      return this;
    }
    assertValidity() {
      this.ep.assertValidity();
    }
    toAffine(e) {
      return this.ep.toAffine(e);
    }
    toHex() {
      return xe(this.toBytes());
    }
    toString() {
      return this.toHex();
    }
    isTorsionFree() {
      return !0;
    }
    isSmallOrder() {
      return !1;
    }
    add(e) {
      return (this.assertSame(e), this.init(this.ep.add(e.ep)));
    }
    subtract(e) {
      return (this.assertSame(e), this.init(this.ep.subtract(e.ep)));
    }
    multiply(e) {
      return this.init(this.ep.multiply(e));
    }
    multiplyUnsafe(e) {
      return this.init(this.ep.multiplyUnsafe(e));
    }
    double() {
      return this.init(this.ep.double());
    }
    negate() {
      return this.init(this.ep.negate());
    }
    precompute(e, n) {
      return this.init(this.ep.precompute(e, n));
    }
    toRawBytes() {
      return this.toBytes();
    }
  };
  function pi(t, e, n = {}) {
    if (typeof e != "function")
      throw new Error('"hash" function param is required');
    ke(
      n,
      {},
      {
        adjustScalarBytes: "function",
        randomBytes: "function",
        domain: "function",
        prehash: "function",
        mapToCurve: "function",
      },
    );
    let { prehash: o } = n,
      { BASE: r, Fp: s, Fn: i } = t,
      c = n.randomBytes || ge,
      a = n.adjustScalarBytes || ((b) => b),
      l =
        n.domain ||
        ((b, A, _) => {
          if ((kn(_, "phflag"), A.length || _))
            throw new Error("Contexts/pre-hash are not supported");
          return b;
        });
    function u(b) {
      return i.create(Dt(b));
    }
    function d(b) {
      let A = y.secretKey;
      b = ut("private key", b, A);
      let _ = ut("hashed private key", e(b), 2 * A),
        P = a(_.slice(0, A)),
        I = _.slice(A, 2 * A),
        M = u(P);
      return { head: P, prefix: I, scalar: M };
    }
    function f(b) {
      let { head: A, prefix: _, scalar: P } = d(b),
        I = r.multiply(P),
        M = I.toBytes();
      return { head: A, prefix: _, scalar: P, point: I, pointBytes: M };
    }
    function m(b) {
      return f(b).pointBytes;
    }
    function x(b = Uint8Array.of(), ...A) {
      let _ = Vt(...A);
      return u(e(l(_, ut("context", b), !!o)));
    }
    function B(b, A, _ = {}) {
      ((b = ut("message", b)), o && (b = o(b)));
      let { prefix: P, scalar: I, pointBytes: M } = f(A),
        K = x(_.context, P, b),
        Z = r.multiply(K).toBytes(),
        z = x(_.context, Z, M, b),
        tt = i.create(K + z * I);
      if (!i.isValid(tt)) throw new Error("sign failed: invalid s");
      let W = Vt(Z, i.toBytes(tt));
      return Qe(W, y.signature, "result");
    }
    let p = { zip215: !0 };
    function h(b, A, _, P = p) {
      let { context: I, zip215: M } = P,
        K = y.signature;
      ((b = ut("signature", b, K)),
        (A = ut("message", A)),
        (_ = ut("publicKey", _, y.publicKey)),
        M !== void 0 && kn(M, "zip215"),
        o && (A = o(A)));
      let Z = K / 2,
        z = b.subarray(0, Z),
        tt = Dt(b.subarray(Z, K)),
        W,
        pt,
        xt;
      try {
        ((W = t.fromBytes(_, M)),
          (pt = t.fromBytes(z, M)),
          (xt = r.multiplyUnsafe(tt)));
      } catch {
        return !1;
      }
      if (!M && W.isSmallOrder()) return !1;
      let Bt = x(I, pt.toBytes(), W.toBytes(), A);
      return pt.add(W.multiplyUnsafe(Bt)).subtract(xt).clearCofactor().is0();
    }
    let g = s.BYTES,
      y = { secretKey: g, publicKey: g, signature: 2 * g, seed: g };
    function k(b = c(y.seed)) {
      return Qe(b, y.seed, "seed");
    }
    function E(b) {
      let A = U.randomSecretKey(b);
      return { secretKey: A, publicKey: m(A) };
    }
    function H(b) {
      return ye(b) && b.length === i.BYTES;
    }
    function O(b, A) {
      try {
        return !!t.fromBytes(b, A);
      } catch {
        return !1;
      }
    }
    let U = {
      getExtendedPublicKey: f,
      randomSecretKey: k,
      isValidSecretKey: H,
      isValidPublicKey: O,
      toMontgomery(b) {
        let { y: A } = t.fromBytes(b),
          _ = y.publicKey,
          P = _ === 32;
        if (!P && _ !== 57) throw new Error("only defined for 25519 and 448");
        let I = P ? s.div(rt + A, rt - A) : s.div(A - rt, A + rt);
        return s.toBytes(I);
      },
      toMontgomerySecret(b) {
        let A = y.secretKey;
        Qe(b, A);
        let _ = e(b.subarray(0, A));
        return a(_).subarray(0, A);
      },
      randomPrivateKey: k,
      precompute(b = 8, A = t.BASE) {
        return A.precompute(b, !1);
      },
    };
    return Object.freeze({
      keygen: E,
      getPublicKey: m,
      sign: B,
      verify: h,
      utils: U,
      Point: t,
      lengths: y,
    });
  }
  function mi(t) {
    let e = {
        a: t.a,
        d: t.d,
        p: t.Fp.ORDER,
        n: t.n,
        h: t.h,
        Gx: t.Gx,
        Gy: t.Gy,
      },
      n = t.Fp,
      o = Wt(e.n, t.nBitLength, !0),
      r = { Fp: n, Fn: o, uvRatio: t.uvRatio },
      s = {
        randomBytes: t.randomBytes,
        adjustScalarBytes: t.adjustScalarBytes,
        domain: t.domain,
        prehash: t.prehash,
        mapToCurve: t.mapToCurve,
      };
    return { CURVE: e, curveOpts: r, hash: t.hash, eddsaOpts: s };
  }
  function yi(t, e) {
    let n = e.Point;
    return Object.assign({}, e, {
      ExtendedPoint: n,
      CURVE: t,
      nBitLength: n.Fn.BITS,
      nByteLength: n.Fn.BYTES,
    });
  }
  function Fr(t) {
    let { CURVE: e, curveOpts: n, hash: o, eddsaOpts: r } = mi(t),
      s = hi(e, n),
      i = pi(s, o, r);
    return yi(t, i);
  }
  var en = BigInt(0),
    Oe = BigInt(1),
    Hn = BigInt(2);
  function xi(t) {
    return (
      ke(t, { adjustScalarBytes: "function", powPminus2: "function" }),
      Object.freeze({ ...t })
    );
  }
  function jr(t) {
    let e = xi(t),
      {
        P: n,
        type: o,
        adjustScalarBytes: r,
        powPminus2: s,
        randomBytes: i,
      } = e,
      c = o === "x25519";
    if (!c && o !== "x448") throw new Error("invalid type");
    let a = i || ge,
      l = c ? 255 : 448,
      u = c ? 32 : 56,
      d = BigInt(c ? 9 : 5),
      f = BigInt(c ? 121665 : 39081),
      m = c ? Hn ** BigInt(254) : Hn ** BigInt(447),
      x = c
        ? BigInt(8) * Hn ** BigInt(251) - Oe
        : BigInt(4) * Hn ** BigInt(445) - Oe,
      B = m + x + Oe,
      p = (I) => j(I, n),
      h = g(d);
    function g(I) {
      return vn(p(I), u);
    }
    function y(I) {
      let M = ut("u coordinate", I, u);
      return (c && (M[31] &= 127), p(Dt(M)));
    }
    function k(I) {
      return Dt(r(ut("scalar", I, u)));
    }
    function E(I, M) {
      let K = U(y(M), k(I));
      if (K === en) throw new Error("invalid private or public key received");
      return g(K);
    }
    function H(I) {
      return E(I, h);
    }
    function O(I, M, K) {
      let Z = p(I * (M - K));
      return ((M = p(M - Z)), (K = p(K + Z)), { x_2: M, x_3: K });
    }
    function U(I, M) {
      (Me("u", I, en, n), Me("scalar", M, m, B));
      let K = M,
        Z = I,
        z = Oe,
        tt = en,
        W = I,
        pt = Oe,
        xt = en;
      for (let w = BigInt(l - 1); w >= en; w--) {
        let C = (K >> w) & Oe;
        ((xt ^= C),
          ({ x_2: z, x_3: W } = O(xt, z, W)),
          ({ x_2: tt, x_3: pt } = O(xt, tt, pt)),
          (xt = C));
        let S = z + tt,
          L = p(S * S),
          D = z - tt,
          R = p(D * D),
          Q = L - R,
          at = W + pt,
          et = W - pt,
          nt = p(et * S),
          St = p(at * D),
          Tt = nt + St,
          kt = nt - St;
        ((W = p(Tt * Tt)),
          (pt = p(Z * p(kt * kt))),
          (z = p(L * R)),
          (tt = p(Q * (L + p(f * Q)))));
      }
      (({ x_2: z, x_3: W } = O(xt, z, W)),
        ({ x_2: tt, x_3: pt } = O(xt, tt, pt)));
      let Bt = s(tt);
      return p(z * Bt);
    }
    let b = { secretKey: u, publicKey: u, seed: u },
      A = (I = a(u)) => ($(I, b.seed), I);
    function _(I) {
      let M = A(I);
      return { secretKey: M, publicKey: H(M) };
    }
    return {
      keygen: _,
      getSharedSecret: (I, M) => E(I, M),
      getPublicKey: (I) => H(I),
      scalarMult: E,
      scalarMultBase: H,
      utils: { randomSecretKey: A, randomPrivateKey: A },
      GuBytes: h.slice(),
      lengths: b,
    };
  }
  var gi = BigInt(0),
    Jt = BigInt(1),
    Vr = BigInt(2),
    bi = BigInt(3),
    wi = BigInt(5),
    Bi = BigInt(8),
    De = BigInt(
      "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    ),
    nn = {
      p: De,
      n: BigInt(
        "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
      ),
      h: Bi,
      a: BigInt(
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
      ),
      d: BigInt(
        "0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
      ),
      Gx: BigInt(
        "0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
      ),
      Gy: BigInt(
        "0x6666666666666666666666666666666666666666666666666666666666666658",
      ),
    };
  function Xr(t) {
    let e = BigInt(10),
      n = BigInt(20),
      o = BigInt(40),
      r = BigInt(80),
      s = De,
      c = (((t * t) % s) * t) % s,
      a = (It(c, Vr, s) * c) % s,
      l = (It(a, Jt, s) * t) % s,
      u = (It(l, wi, s) * l) % s,
      d = (It(u, e, s) * u) % s,
      f = (It(d, n, s) * d) % s,
      m = (It(f, o, s) * f) % s,
      x = (It(m, r, s) * m) % s,
      B = (It(x, r, s) * m) % s,
      p = (It(B, e, s) * u) % s;
    return { pow_p_5_8: (It(p, Vr, s) * t) % s, b2: c };
  }
  function Yr(t) {
    return ((t[0] &= 248), (t[31] &= 127), (t[31] |= 64), t);
  }
  var wo = BigInt(
    "19681161376707505956807079304988542015446066515923890162744021073123829784752",
  );
  function Ao(t, e) {
    let n = De,
      o = j(e * e * e, n),
      r = j(o * o * e, n),
      s = Xr(t * r).pow_p_5_8,
      i = j(t * o * s, n),
      c = j(e * i * i, n),
      a = i,
      l = j(i * wo, n),
      u = c === t,
      d = c === j(-t, n),
      f = c === j(-t * wo, n);
    return (
      u && (i = a),
      (d || f) && (i = l),
      zt(i, n) && (i = j(-i, n)),
      { isValid: u || d, value: i }
    );
  }
  var Qt = Wt(nn.p, { isLE: !0 }),
    Ei = Wt(nn.n, { isLE: !0 }),
    Ai = { ...nn, Fp: Qt, hash: gn, adjustScalarBytes: Yr, uvRatio: Ao },
    _e = Fr(Ai);
  var on = (() => {
    let t = Qt.ORDER;
    return jr({
      P: t,
      type: "x25519",
      powPminus2: (e) => {
        let { pow_p_5_8: n, b2: o } = Xr(e);
        return j(It(n, bi, t) * o, t);
      },
      adjustScalarBytes: Yr,
    });
  })();
  var Bo = wo,
    Si = BigInt(
      "25063068953384623474111414158702152701244531502492656460079210482610430750235",
    ),
    ki = BigInt(
      "54469307008909316920995813868745141605393597292927456921205312896311721017578",
    ),
    vi = BigInt(
      "1159843021668779879193775521855586647937357759715417654439879720876111806838",
    ),
    _i = BigInt(
      "40440834346308536858101042469323190826248399146238708352240133220865137265952",
    ),
    Zr = (t) => Ao(Jt, t),
    Ii = BigInt(
      "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    Eo = (t) => _e.Point.Fp.create(Dt(t) & Ii);
  function $r(t) {
    let { d: e } = nn,
      n = De,
      o = (h) => Qt.create(h),
      r = o(Bo * t * t),
      s = o((r + Jt) * vi),
      i = BigInt(-1),
      c = o((i - e * r) * o(r + e)),
      { isValid: a, value: l } = Ao(s, c),
      u = o(l * t);
    (zt(u, n) || (u = o(-u)), a || (l = u), a || (i = r));
    let d = o(i * (r - Jt) * _i - c),
      f = l * l,
      m = o((l + l) * c),
      x = o(d * Si),
      B = o(Jt - f),
      p = o(Jt + f);
    return new _e.Point(o(m * p), o(B * x), o(x * p), o(m * B));
  }
  function Ti(t) {
    $(t, 64);
    let e = Eo(t.subarray(0, 32)),
      n = $r(e),
      o = Eo(t.subarray(32, 64)),
      r = $r(o);
    return new te(n.add(r));
  }
  var te = class t extends Ln {
    constructor(e) {
      super(e);
    }
    static fromAffine(e) {
      return new t(_e.Point.fromAffine(e));
    }
    assertSame(e) {
      if (!(e instanceof t)) throw new Error("RistrettoPoint expected");
    }
    init(e) {
      return new t(e);
    }
    static hashToCurve(e) {
      return Ti(ut("ristrettoHash", e, 64));
    }
    static fromBytes(e) {
      $(e, 32);
      let { a: n, d: o } = nn,
        r = De,
        s = (k) => Qt.create(k),
        i = Eo(e);
      if (!Ar(Qt.toBytes(i), e) || zt(i, r))
        throw new Error("invalid ristretto255 encoding 1");
      let c = s(i * i),
        a = s(Jt + n * c),
        l = s(Jt - n * c),
        u = s(a * a),
        d = s(l * l),
        f = s(n * o * u - d),
        { isValid: m, value: x } = Zr(s(f * d)),
        B = s(x * l),
        p = s(x * B * f),
        h = s((i + i) * B);
      zt(h, r) && (h = s(-h));
      let g = s(a * p),
        y = s(h * g);
      if (!m || zt(y, r) || g === gi)
        throw new Error("invalid ristretto255 encoding 2");
      return new t(new _e.Point(h, g, Jt, y));
    }
    static fromHex(e) {
      return t.fromBytes(ut("ristrettoHex", e, 32));
    }
    static msm(e, n) {
      return Cn(t, _e.Point.Fn, e, n);
    }
    toBytes() {
      let { X: e, Y: n, Z: o, T: r } = this.ep,
        s = De,
        i = (p) => Qt.create(p),
        c = i(i(o + n) * i(o - n)),
        a = i(e * n),
        l = i(a * a),
        { value: u } = Zr(i(c * l)),
        d = i(u * c),
        f = i(u * a),
        m = i(d * f * r),
        x;
      if (zt(r * m, s)) {
        let p = i(n * Bo),
          h = i(e * Bo);
        ((e = p), (n = h), (x = i(d * ki)));
      } else x = f;
      zt(e * m, s) && (n = i(-n));
      let B = i((o - n) * x);
      return (zt(B, s) && (B = i(-B)), Qt.toBytes(B));
    }
    equals(e) {
      this.assertSame(e);
      let { X: n, Y: o } = this.ep,
        { X: r, Y: s } = e.ep,
        i = (l) => Qt.create(l),
        c = i(n * s) === i(o * r),
        a = i(o * s) === i(n * r);
      return c || a;
    }
    is0() {
      return this.equals(t.ZERO);
    }
  };
  te.BASE = new te(_e.Point.BASE);
  te.ZERO = new te(_e.Point.ZERO);
  te.Fp = Qt;
  te.Fn = Ei;
  var Un = class extends oe {
      constructor(e, n) {
        (super(), (this.finished = !1), (this.destroyed = !1), Ge(e));
        let o = Ht(n);
        if (((this.iHash = e.create()), typeof this.iHash.update != "function"))
          throw new Error(
            "Expected instance of class which extends utils.Hash",
          );
        ((this.blockLen = this.iHash.blockLen),
          (this.outputLen = this.iHash.outputLen));
        let r = this.blockLen,
          s = new Uint8Array(r);
        s.set(o.length > r ? e.create().update(o).digest() : o);
        for (let i = 0; i < s.length; i++) s[i] ^= 54;
        (this.iHash.update(s), (this.oHash = e.create()));
        for (let i = 0; i < s.length; i++) s[i] ^= 106;
        (this.oHash.update(s), gt(s));
      }
      update(e) {
        return (jt(this), this.iHash.update(e), this);
      }
      digestInto(e) {
        (jt(this),
          $(e, this.outputLen),
          (this.finished = !0),
          this.iHash.digestInto(e),
          this.oHash.update(e),
          this.oHash.digestInto(e),
          this.destroy());
      }
      digest() {
        let e = new Uint8Array(this.oHash.outputLen);
        return (this.digestInto(e), e);
      }
      _cloneInto(e) {
        e || (e = Object.create(Object.getPrototypeOf(this), {}));
        let {
          oHash: n,
          iHash: o,
          finished: r,
          destroyed: s,
          blockLen: i,
          outputLen: c,
        } = this;
        return (
          (e = e),
          (e.finished = r),
          (e.destroyed = s),
          (e.blockLen = i),
          (e.outputLen = c),
          (e.oHash = n._cloneInto(e.oHash)),
          (e.iHash = o._cloneInto(e.iHash)),
          e
        );
      }
      clone() {
        return this._cloneInto();
      }
      destroy() {
        ((this.destroyed = !0), this.oHash.destroy(), this.iHash.destroy());
      }
    },
    Mn = (t, e, n) => new Un(t, e).update(n).digest();
  Mn.create = (t, e) => new Un(t, e);
  function Ci(t, e, n) {
    return (
      Ge(t),
      n === void 0 && (n = new Uint8Array(t.outputLen)),
      Mn(t, Ht(n), Ht(e))
    );
  }
  var So = Uint8Array.from([0]),
    zr = Uint8Array.of();
  function Li(t, e, n, o = 32) {
    (Ge(t), Rt(o));
    let r = t.outputLen;
    if (o > 255 * r) throw new Error("Length should be <= 255*HashLen");
    let s = Math.ceil(o / r);
    n === void 0 && (n = zr);
    let i = new Uint8Array(s * r),
      c = Mn.create(t, e),
      a = c._cloneInto(),
      l = new Uint8Array(c.outputLen);
    for (let u = 0; u < s; u++)
      ((So[0] = u + 1),
        a
          .update(u === 0 ? zr : l)
          .update(n)
          .update(So)
          .digestInto(l),
        i.set(l, r * u),
        c._cloneInto(a));
    return (c.destroy(), a.destroy(), gt(l, So), i.slice(0, o));
  }
  var Wr = (t, e, n, o, r) => Li(t, Ci(t, e, n), o, r);
  var Dn = "HUMID-PQ1",
    Hi =
      "ML-KEM-1024 + X25519 hybrid KEM / HKDF-SHA3-256 / AES-256-GCM / ML-DSA-87 / SHA3-512",
    vo = new Uint8Array([72, 85, 77, 73, 68, 1]),
    Ie = new TextEncoder(),
    Io = new TextDecoder(),
    On = globalThis.crypto.subtle,
    wt = (t) => globalThis.crypto.getRandomValues(new Uint8Array(t)),
    Te = (...t) => {
      let e = new Uint8Array(t.reduce((o, r) => o + r.length, 0)),
        n = 0;
      for (let o of t) (e.set(o, n), (n += o.length));
      return e;
    },
    bt = (t) => Array.from(t, (e) => e.toString(16).padStart(2, "0")).join(""),
    Y = (t) => {
      let e = "";
      for (let n = 0; n < t.length; n += 32768)
        e += String.fromCharCode(...t.subarray(n, n + 32768));
      return btoa(e);
    },
    V = (t) => Uint8Array.from(atob(t), (e) => e.charCodeAt(0)),
    qt = (...t) => {
      for (let e of t) e && e.fill && e.fill(0);
    },
    ko = (t) => {
      let e = new Uint8Array(4);
      return (new DataView(e.buffer).setUint32(0, t), e);
    },
    _o = (t, e) => new DataView(t.buffer, t.byteOffset + e, 4).getUint32(0),
    Ne = (t, e, n, o = 32) => Wr(Ut, t, e, Ie.encode(n), o);
  async function Qr(t, e, n, o) {
    let r = await On.importKey("raw", t, "AES-GCM", !1, ["encrypt"]);
    return new Uint8Array(
      await On.encrypt({ name: "AES-GCM", iv: e, additionalData: o }, r, n),
    );
  }
  async function Jr(t, e, n, o) {
    let r = await On.importKey("raw", t, "AES-GCM", !1, ["decrypt"]);
    return new Uint8Array(
      await On.decrypt({ name: "AES-GCM", iv: e, additionalData: o }, r, n),
    );
  }
  function To(t) {
    let e = Ne(t, void 0, "HUMID-PQ1 ml-kem-1024", 64),
      n = Ne(t, void 0, "HUMID-PQ1 ml-dsa-87", 32),
      o = Ne(t, void 0, "HUMID-PQ1 x25519", 32),
      r = En.keygen(e),
      s = Sn.keygen(n),
      i = {
        kemPk: r.publicKey,
        kemSk: r.secretKey,
        dsaPk: s.publicKey,
        dsaSk: s.secretKey,
        xPk: on.getPublicKey(o),
        xSk: o,
      };
    return (qt(e, n), i);
  }
  var Co = (t) => t && qt(t.kemSk, t.dsaSk, t.xSk),
    ts = (t) => ({ kemPk: t.kemPk, dsaPk: t.dsaPk, xPk: t.xPk });
  function es(t, e) {
    return Ut(
      Te(Ie.encode("HUMID-ID-COMMIT-v1"), vt(t.kemPk), vt(t.dsaPk), t.xPk, e),
    );
  }
  async function ns(t, e, n) {
    let o = wt(32),
      r = wt(12),
      s = Ne(t, o, "HUMID-PQ1 seed-wrap"),
      i = await Qr(s, r, e, n);
    return (qt(s), { salt: Y(o), nonce: Y(r), ct: Y(i) });
  }
  async function os(t, e, n) {
    let o = Ne(t, V(e.salt), "HUMID-PQ1 seed-wrap");
    try {
      return await Jr(o, V(e.nonce), V(e.ct), n);
    } finally {
      qt(o);
    }
  }
  function rs(t, e, n, o, r) {
    let s = Ut(Te(n, o, Ut(r.kemPk), r.xPk));
    return Ne(Te(t, e), s, "HUMID-PQ1 payload-key");
  }
  var ss = (t, e, n) => Te(Ie.encode(Dn), t, e, n),
    is = (t) => Te(Ie.encode("HUMID-MANIFEST-v1"), t);
  async function cs({ bytes: t, name: e, type: n }, o, r, s) {
    let i = vt(t),
      c = Ie.encode(
        JSON.stringify({
          name: e,
          type: n || "application/octet-stream",
          size: t.length,
          sha3_512: bt(i),
        }),
      ),
      a = Te(ko(c.length), c, t),
      { cipherText: l, sharedSecret: u } = En.encapsulate(r.kemPk),
      d = wt(32),
      f = on.getPublicKey(d),
      m = on.getSharedSecret(d, r.xPk),
      x = rs(u, m, l, f, r),
      B = wt(12),
      p = await Qr(x, B, a, ss(l, f, B));
    qt(u, m, d, x, a);
    let h = {
        format: "humid-envelope",
        v: 1,
        suite: Dn,
        suiteDesc: Hi,
        created: new Date().toISOString(),
        kem: { mlkem1024Ct: Y(l), x25519Eph: Y(f) },
        nonce: Y(B),
        ciphertext: { bytes: p.length, sha3_512: bt(vt(p)) },
        recipient: { kemPkFp: bt(Ut(r.kemPk)) },
        signer: { mldsa87Pk: Y(o.dsaPk), identityCommit: s.identityCommit },
        interrupt: s.interrupt,
      },
      g = Ie.encode(JSON.stringify(h)),
      y = Sn.sign(o.dsaSk, is(g));
    return {
      envelope: Te(vo, ko(g.length), g, ko(y.length), y, p),
      manifest: h,
      plainHash: bt(i),
    };
  }
  function Nn(t) {
    if (t.length < 14 || vo.some((c, a) => t[a] !== c))
      throw new Error("Not a HumID envelope.");
    let e = vo.length,
      n = _o(t, e);
    e += 4;
    let o = t.subarray(e, e + n);
    e += n;
    let r = _o(t, e);
    e += 4;
    let s = t.subarray(e, e + r);
    e += r;
    let i = t.subarray(e);
    return { manifest: JSON.parse(Io.decode(o)), mBytes: o, sig: s, ct: i };
  }
  function Lo(t) {
    let { manifest: e, mBytes: n, sig: o, ct: r } = Nn(t),
      s = Sn.verify(V(e.signer.mldsa87Pk), is(n), o),
      i = bt(vt(r)) === e.ciphertext.sha3_512;
    return { ok: s && i, sigOk: s, ctOk: i, manifest: e };
  }
  async function as(t, e) {
    let n = Lo(t);
    if (!n.ok)
      throw new Error(
        n.sigOk
          ? "Ciphertext does not match its signed hash."
          : "ML-DSA-87 signature is invalid.",
      );
    let { manifest: o, ct: r } = Nn(t),
      s = V(o.kem.mlkem1024Ct),
      i = V(o.kem.x25519Eph),
      c = V(o.nonce),
      a = En.decapsulate(s, e.kemSk),
      l = on.getSharedSecret(e.xSk, i),
      u = rs(a, l, s, i, e),
      d;
    try {
      d = await Jr(u, c, r, ss(s, i, c));
    } catch {
      throw new Error(
        "Decryption failed. This envelope was not sealed to this identity.",
      );
    } finally {
      qt(a, l, u);
    }
    let f = _o(d, 0),
      m = JSON.parse(Io.decode(d.subarray(4, 4 + f))),
      x = d.slice(4 + f);
    if (bt(vt(x)) !== m.sha3_512) throw new Error("Payload hash mismatch.");
    return { meta: m, bytes: x, manifest: o };
  }
  var fe = { sha3_256: Ut, sha3_512: vt, te: Ie, td: Io };
  globalThis.__orig = { To, ts, es, ns, os, cs, Lo, as, fe, Y, V, bt };
})();
