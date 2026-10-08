(function (root) {
  'use strict';
  const C = root.InstallCrypto;
  const brokers = ['wss://broker-cn.emqx.io:8084/mqtt', 'wss://broker.emqx.io:8084/mqtt', 'wss://test.mosquitto.org:8081/mqtt'];
  const context = 'modcode-public-signal-v1';
  const mqttString = text => { const b = C.encoder.encode(text); return C.concat(new Uint8Array([b.length >> 8, b.length & 255]), b); };
  const packet = (header, body = new Uint8Array()) => { let n = body.length; const length = []; do { let d = n % 128; n = Math.floor(n / 128); length.push(d | (n ? 128 : 0)); } while (n); return C.concat(new Uint8Array([header, ...length]), body); };

  class InstallerPeer {
    constructor(config) {
      this.config = config; this.secret = C.decode64(config.k);
      this.room = 'install_' + C.hex(C.sha256(this.secret)).slice(0, 32);
      this.desktop = 'desktop_' + this.room;
      this.client = 'web_' + C.hex(crypto.getRandomValues(new Uint8Array(12)));
      this.sessionId = C.hex(crypto.getRandomValues(new Uint8Array(12)));
      this.topic = 'modcode/v1/' + C.encode64(C.sha256(C.concat(C.encoder.encode(context), this.secret)));
      this.sockets = []; this.seen = new Set(); this.requests = new Map(); this.pendingCandidates = [];
      this.closed = false; this.chain = Promise.resolve();
    }

    async connect() {
      if (!crypto.subtle || !root.RTCPeerConnection) throw new Error('请用手机系统浏览器打开安装入口');
      this.aes = await crypto.subtle.importKey('raw', this.secret, 'AES-GCM', false, ['encrypt', 'decrypt']);
      this.publicKey = await crypto.subtle.importKey('raw', C.decode64(this.config.p), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const ready = new Promise((resolve, reject) => { this.resolveConnect = resolve; this.rejectConnect = reject; });
      this.timeout = setTimeout(() => this.fail(new Error('暂时连不上电脑，请保持电脑开启后重试')), 60_000);
      const targets = this.config.s ? [this.config.s] : (this.config.b || brokers);
      for (const target of targets) this.openSignal(target);
      this.announce = setInterval(() => { void this.publish({ type: 'peer-online', role: 'mobile', sessionId: this.sessionId }); }, 3000);
      return ready;
    }

    openSignal(target) {
      const custom = Boolean(this.config.s); const url = new URL(target);
      if (!['ws:', 'wss:'].includes(url.protocol) || url.username || url.password) return;
      if (custom) { url.searchParams.set('role', 'mobile'); url.searchParams.set('room', this.room); url.searchParams.set('client', this.client); }
      const ws = new WebSocket(url, custom ? undefined : 'mqtt'); ws.binaryType = 'arraybuffer';
      const state = { ws, custom, ready: custom, rest: new Uint8Array() }; this.sockets.push(state);
      ws.onopen = () => {
        if (custom) { void this.publish({ type: 'peer-online', role: 'mobile', sessionId: this.sessionId }); return; }
        const id = 'mdw' + C.hex(C.sha256(this.client + target)).slice(0, 20);
        ws.send(packet(0x10, C.concat(mqttString('MQTT'), new Uint8Array([4,2,0,30]), mqttString(id))));
      };
      ws.onmessage = event => {
        if (custom) { try { this.enqueue(JSON.parse(event.data)); } catch {} return; }
        try { this.mqttData(state, new Uint8Array(event.data)); } catch { ws.close(); }
      };
      ws.onerror = () => {};
      ws.onclose = () => { state.ready = false; clearInterval(state.ping); };
    }

    mqttData(state, bytes) {
      const all = C.concat(state.rest, bytes); let offset = 0;
      while (offset < all.length) {
        const header = all[offset]; let cursor = offset + 1, n = 0, mult = 1, count = 0, digit;
        do { if (cursor >= all.length) { state.rest = all.slice(offset); return; } digit = all[cursor++]; n += (digit & 127) * mult; mult *= 128; if (++count > 4) throw new Error('MQTT'); } while (digit & 128);
        if (n > 512 * 1024) throw new Error('MQTT');
        if (cursor + n > all.length) { state.rest = all.slice(offset); return; }
        const body = all.slice(cursor, cursor + n); offset = cursor + n;
        const type = header >> 4;
        if (type === 2 && body.length === 2 && body[1] === 0) state.ws.send(packet(0x82, C.concat(new Uint8Array([0,1]), mqttString(this.topic), new Uint8Array([0]))));
        else if (type === 9 && !state.ready) {
          state.ready = true; state.ping = setInterval(() => { if (state.ws.readyState === WebSocket.OPEN) state.ws.send(new Uint8Array([0xc0,0])); }, 20_000);
          void this.publish({ type: 'peer-online', role: 'mobile', sessionId: this.sessionId });
        } else if (type === 3 && body.length > 2) {
          const length = (body[0] << 8) | body[1];
          if (new TextDecoder().decode(body.slice(2, length + 2)) !== this.topic) continue;
          this.chain = this.chain.then(async () => {
            const envelope = JSON.parse(new TextDecoder().decode(body.slice(length + 2)));
            if (envelope.v !== 1) return;
            const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: C.decode64(envelope.n), additionalData: C.encoder.encode(context + '\n' + this.topic) }, this.aes, C.concat(C.decode64(envelope.c), C.decode64(envelope.t)));
            await this.signal(JSON.parse(new TextDecoder().decode(clear)));
          }).catch(() => {});
        }
      }
      state.rest = new Uint8Array();
    }

    enqueue(message) { this.chain = this.chain.then(() => this.signal(message)).catch(error => this.fail(error)); }

    async publish(value) {
      if (this.closed) return;
      const message = { ...value, id: C.hex(crypto.getRandomValues(new Uint8Array(12))), from: this.client, sentAt: new Date().toISOString(), to: this.desktop };
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: C.encoder.encode(context + '\n' + this.topic) }, this.aes, C.encoder.encode(JSON.stringify(message))));
      const envelope = C.encoder.encode(JSON.stringify({ v:1,n:C.encode64(nonce),c:C.encode64(sealed.slice(0,-16)),t:C.encode64(sealed.slice(-16)) }));
      for (const state of this.sockets) if (state.ready && state.ws.readyState === WebSocket.OPEN) state.ws.send(state.custom ? JSON.stringify(message) : packet(0x30, C.concat(mqttString(this.topic), envelope)));
    }

    async signal(message) {
      if (this.closed || message.from !== this.desktop || (message.to && message.to !== this.client)) return;
      // The custom coordinator relays only offer/answer/candidate fields;
      // encrypted public MQTT envelopes also carry timestamp and message ID.
      if (!this.config.s && (Math.abs(Date.now() - Date.parse(message.sentAt)) > 10 * 60_000 || !Number.isFinite(Date.parse(message.sentAt)))) return;
      if (message.id) { if (this.seen.has(message.id)) return; this.seen.add(message.id); if (this.seen.size > 512) this.seen.delete(this.seen.values().next().value); }
      if (message.type === 'offer') {
        const match = String(message.sdp).match(/^a=fingerprint:sha-256\s+([0-9A-F:]+)\s*$/im);
        const fingerprint = match?.[1].replace(/:/g, '').toLowerCase();
        if (!fingerprint || fingerprint.length !== 64 || !(await crypto.subtle.verify({ name:'ECDSA',hash:'SHA-256' }, this.publicKey, C.rawSignature(C.decode64(message.signature)), C.encoder.encode('modcode-p2p-desktop-v1\n' + this.room + '\n' + fingerprint)))) throw new Error('电脑身份校验失败，请重新扫码');
        if (this.pc && this.offerSdp === message.sdp) return;
        this.pc?.close(); this.offerSdp = message.sdp;
        const pc = this.pc = new RTCPeerConnection({ iceServers:[{ urls:'stun:stun.cloudflare.com:3478' },{ urls:'stun:stun.l.google.com:19302' }] });
        pc.onicecandidate = event => { if (event.candidate) void this.publish({ type:'candidate',candidate:event.candidate.candidate,mid:event.candidate.sdpMid }); };
        pc.ondatachannel = event => {
          this.channel = event.channel;
          this.channel.onopen = () => { clearTimeout(this.timeout); clearInterval(this.announce); this.resolveConnect?.(this); };
          this.channel.onmessage = e => { try { const value = JSON.parse(e.data); if (value.kind !== 'response') return; const pending = this.requests.get(value.id); if (!pending) return; this.requests.delete(value.id); clearTimeout(pending.timer); if (value.status !== 200) pending.reject(new Error(value.body?.error || '下载失败')); else pending.resolve(value.body); } catch {} };
          this.channel.onclose = () => this.fail(new Error('下载连接已断开，请重试'));
        };
        await pc.setRemoteDescription({ type:'offer',sdp:message.sdp });
        for (const candidate of this.pendingCandidates.splice(0)) await pc.addIceCandidate(candidate);
        await pc.setLocalDescription(await pc.createAnswer());
        await this.publish({ type:'answer',sdp:pc.localDescription.sdp });
      } else if (message.type === 'candidate') {
        const candidate = { candidate:message.candidate,sdpMid:String(message.mid || '0') };
        if (this.pc?.remoteDescription) await this.pc.addIceCandidate(candidate); else if (this.pendingCandidates.length < 128) this.pendingCandidates.push(candidate);
      }
    }

    request(method, path, body = {}) {
      return new Promise((resolve, reject) => {
        if (this.channel?.readyState !== 'open') return reject(new Error('下载连接已断开'));
        const id = C.hex(crypto.getRandomValues(new Uint8Array(12)));
        const timer = setTimeout(() => { this.requests.delete(id); reject(new Error('下载响应超时，请重试')); }, 20_000);
        this.requests.set(id, { resolve,reject,timer });
        this.channel.send(JSON.stringify({ kind:'request',id,method,path,body,token:this.config.k }));
      });
    }
    fail(error) { this.rejectConnect?.(error); for (const pending of this.requests.values()) { clearTimeout(pending.timer); pending.reject(error); } this.requests.clear(); }
    close() { this.closed = true; clearTimeout(this.timeout); clearInterval(this.announce); this.fail(new Error('下载已结束')); for (const state of this.sockets) { clearInterval(state.ping); state.ws.close(); } this.pc?.close(); }
  }
  root.InstallerPeer = InstallerPeer;
})(globalThis);
