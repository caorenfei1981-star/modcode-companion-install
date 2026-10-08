(function (root) {
  'use strict';
  const encoder = new TextEncoder();
  const decode64 = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const encode64 = bytes => btoa(Array.from(bytes, b => String.fromCharCode(b)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const concat = (...arrays) => { const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0)); let p = 0; for (const a of arrays) { out.set(a, p); p += a.length; } return out; };
  // HTTP on a private LAN has no SubtleCrypto. SHA-256 still verifies the APK
  // bytes against the pinned desktop package before a browser saves the file.
  function sha256(input) {
    const bytes = input instanceof Uint8Array ? input : encoder.encode(input);
    const constants = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const padded = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64);
    padded.set(bytes); padded[bytes.length] = 128;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(bytes.length / 0x20000000));
    view.setUint32(padded.length - 4, bytes.length * 8);
    const w = new Uint32Array(64), rot = (x, n) => (x >>> n) | (x << (32 - n));
    for (let pos = 0; pos < padded.length; pos += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(pos + i * 4);
      for (let i = 16; i < 64; i++) { const a = w[i - 15], b = w[i - 2]; w[i] = w[i - 16] + (rot(a,7)^rot(a,18)^(a>>>3)) + w[i - 7] + (rot(b,17)^rot(b,19)^(b>>>10)); }
      let [a,b,c,d,e,f,g,j] = h;
      for (let i = 0; i < 64; i++) {
        const t1 = (j + (rot(e,6)^rot(e,11)^rot(e,25)) + ((e&f)^(~e&g)) + constants[i] + w[i]) | 0;
        const t2 = ((rot(a,2)^rot(a,13)^rot(a,22)) + ((a&b)^(a&c)^(b&c))) | 0;
        j=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
      }
      [a,b,c,d,e,f,g,j].forEach((v, i) => { h[i] = (h[i] + v) | 0; });
    }
    const out = new Uint8Array(32), outView = new DataView(out.buffer);
    h.forEach((v,i) => outView.setUint32(i*4,v));
    return out;
  }
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  function rawSignature(der) {
    if (der.length === 64) return der;
    if (der[0] !== 48 || der[1] !== der.length - 2 || der[2] !== 2) throw new Error('电脑身份签名无效');
    const out = new Uint8Array(64); let p = 2;
    for (let i = 0; i < 2; i++) {
      if (der[p++] !== 2) throw new Error('电脑身份签名无效');
      const n = der[p++]; let part = der.slice(p, p + n); p += n;
      if (part.length === 33 && part[0] === 0) part = part.slice(1);
      if (!part.length || part.length > 32) throw new Error('电脑身份签名无效');
      out.set(part, (i + 1) * 32 - part.length);
    }
    if (p !== der.length) throw new Error('电脑身份签名无效');
    return out;
  }
  const api = { encoder, decode64, encode64, concat, sha256, hex, rawSignature };
  root.InstallCrypto = api;
  if (typeof module !== 'undefined') module.exports = api;
})(globalThis);
