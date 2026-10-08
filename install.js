(function () {
  'use strict';
  const C = InstallCrypto;
  const title = document.getElementById('title'), status = document.getElementById('status');
  const download = document.getElementById('download'), open = document.getElementById('open');
  const retry = document.getElementById('retry'), progress = document.getElementById('progress');
  let config, info, peer, blobUrl, parts = [], offset = 0, downloading = false, currentHash = '';
  let expiresTimer;
  function fail(error) {
    downloading = false; download.disabled = false; progress.hidden = true;
    title.textContent = '暂时无法安装'; status.textContent = error.message || '请在电脑端重新生成安装二维码。';
    retry.hidden = false;
  }
  async function request(method, route, body) {
    if (config.mode !== 'lan') return peer.request(method, route, body);
    const endpoint = route === '/v1/install/info' ? 'info' : 'apk';
    const response = await fetch(endpoint, { headers:{ 'X-Install-Token':config.k }, cache:'no-store',signal:AbortSignal.timeout(20_000) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || '电脑下载服务暂时不可用'); return result;
  }
  function setOpenLink() {
    const uri = new URL(info.pairingUri);
    if (uri.protocol !== 'modcode:' || uri.hostname !== 'pair' || !uri.searchParams.get('data')) throw new Error('配对信息无效');
    // The package comes from the actual APK metadata, including the maintained
    // trial package. A normal installer Open button cannot forward this URI.
    if (!/^com\.modcode\.companion(?:\.chattrial)?$/.test(info.applicationId)) throw new Error('安装包身份无效');
    open.href = `intent://pair${uri.search}#Intent;scheme=modcode;package=${info.applicationId};end`;
  }
  function copyPairing() {
    // execCommand is retained as a gesture-only fallback for private-LAN HTTP.
    // Clipboard handoff is best effort; the explicit Open link always remains.
    const text = document.createElement('textarea'); text.value = info.pairingUri; text.style.position = 'fixed'; text.style.opacity = '0';
    document.body.append(text); text.focus(); text.select(); let copied = false;
    try { copied = document.execCommand('copy'); } catch {} text.remove();
    if (!copied && navigator.clipboard?.writeText && window.isSecureContext) {
      void navigator.clipboard.writeText(info.pairingUri).catch(() => {});
    }
    return copied;
  }
  function saveFile() {
    const copied = copyPairing();
    const link = document.createElement('a'); link.href = blobUrl;
    link.download = `modcode-companion-${String(info.version || 'latest').replace(/[^\w.-]/g,'_')}.apk`;
    document.body.append(link); link.click(); link.remove();
    title.textContent = '安装包已准备好';
    status.textContent = copied ? '打开下载的安装包，确认安装后点“打开”，手机伴侣会接续本次配对。' : '打开下载的安装包并确认安装。安装完成后，点击下面的“打开并配对”。';
    open.hidden = false; download.textContent = '重新保存安装包'; download.hidden = false;
  }
  async function prepare() {
    retry.hidden = true; download.hidden = true; open.hidden = true;
    title.textContent = '正在准备安装'; status.textContent = '正在连接你的电脑，请保持电脑开启。';
    try {
      if (!config || config.v !== 1 || !/^[\w-]{43}$/.test(config.k || '') || !Number.isSafeInteger(config.e) || config.e * 1000 <= Date.now()) throw new Error('安装二维码已失效，请在电脑端重新生成。');
      document.getElementById('hint').textContent = config.mode === 'lan'
        ? '手机与电脑需连接同一 Wi-Fi。安装完成后点“打开”；首次安装可能需要允许浏览器安装应用。'
        : '手机可用 5G 或其他 Wi-Fi，请保持电脑开启联网。安装完成后点“打开”；首次安装可能需要允许浏览器安装应用。';
      if (config.mode !== 'lan') { peer?.close(); peer = new InstallerPeer(config); await peer.connect(); }
      info = await request('GET','/v1/install/info');
      if (!Number.isSafeInteger(info.bytes) || info.bytes <= 0 || info.bytes > 200 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(info.sha256) || Date.parse(info.expiresAt) <= Date.now()) throw new Error('安装包信息无效或二维码已过期');
      if (currentHash !== info.sha256) { parts=[];offset=0; if (blobUrl) URL.revokeObjectURL(blobUrl); blobUrl=''; currentHash=info.sha256; }
      setOpenLink(); document.getElementById('meta').textContent = `${info.version || '手机版'} · ${(info.bytes / 1024 / 1024).toFixed(1)} MB`;
      title.textContent = '安装手机伴侣'; status.textContent = '安装包由你的电脑提供，下载安装后即可连接。';
      download.textContent = blobUrl ? '下载并安装' : '准备安装包'; download.hidden = false;
      clearTimeout(expiresTimer); expiresTimer = setTimeout(() => { peer?.close(); fail(new Error('安装二维码已失效，请在电脑端重新生成。')); download.hidden=true;open.hidden=true; }, Math.max(1, Math.min(config.e * 1000, Date.parse(info.expiresAt)) - Date.now()));
      // Begin preparing immediately after scan. Saving remains a user gesture
      // so download, clipboard and installer restrictions have a clear fallback.
      if (!blobUrl) await fetchApk();
    } catch (error) { fail(error); }
  }
  async function fetchApk() {
    if (downloading) return; downloading=true; download.disabled=true; progress.hidden=false;
    title.textContent = '正在准备安装包';
    try {
      if (config.mode === 'lan') {
        const controller = new AbortController(); let timer;
        const renew = () => { clearTimeout(timer); timer=setTimeout(() => controller.abort(),30_000); }; renew();
        try {
          const response = await fetch('apk', { headers:{ 'X-Install-Token':config.k,...(offset ? { Range:`bytes=${offset}-` } : {}) },signal:controller.signal,cache:'no-store' });
          if (!response.ok) throw new Error((await response.json()).error || '下载失败');
          if (offset && response.status !== 206) { parts=[];offset=0; }
          const reader=response.body.getReader();
          while (true) { const { done,value }=await reader.read(); if (done) break; renew(); offset+=value.length; if (offset>info.bytes) { controller.abort(); throw new Error('安装包大小不匹配'); } parts.push(value); progress.value=offset*100/info.bytes;status.textContent=`准备安装 · ${Math.floor(progress.value)}%`; }
        } finally { clearTimeout(timer); }
      } else {
        while (offset < info.bytes) {
          const chunk = await request('POST','/v1/install/chunk',{ offset }); const bytes=C.decode64(chunk.data);
          if (chunk.offset !== offset || !bytes.length || bytes.length > 48*1024 || chunk.nextOffset !== offset+bytes.length || chunk.nextOffset > info.bytes) throw new Error('安装包分块校验失败');
          parts.push(bytes);offset=chunk.nextOffset;progress.value=offset*100/info.bytes;status.textContent=`准备安装 · ${Math.floor(progress.value)}%`;
        }
      }
      if (offset !== info.bytes) throw new Error('下载未完成，请重试');
      status.textContent = '正在校验安装包…';
      const blob=new Blob(parts,{ type:'application/vnd.android.package-archive' });
      const bytes=new Uint8Array(await blob.arrayBuffer());
      if (C.hex(C.sha256(bytes)) !== info.sha256) { parts=[];offset=0;throw new Error('安装包校验失败，请重试'); }
      blobUrl=URL.createObjectURL(blob);parts=[];downloading=false;download.disabled=false;progress.hidden=true;
      title.textContent='安装包已准备好';status.textContent='点击下方按钮保存安装包，然后按系统提示安装。';download.textContent='下载并安装';download.hidden=false;
    } catch (error) { fail(error); }
  }
  download.addEventListener('click', () => { if (blobUrl) saveFile(); else void fetchApk(); });
  open.addEventListener('click', () => { copyPairing(); });
  retry.addEventListener('click', () => { void prepare(); });
  window.addEventListener('pagehide', () => { peer?.close(); });
  try { config=JSON.parse(new TextDecoder().decode(C.decode64(location.hash.slice(1)))); } catch { fail(new Error('请扫描电脑端的安装二维码。')); return; }
  void prepare();
})();
