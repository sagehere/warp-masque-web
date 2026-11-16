import {
  bytesToHex,randomBytes,cfTimestamp,generateMasqueKeys,generateRegistrationPublicKey,
  buildUsqueFromApi,normalizeUsqueConfig,makeXrayOutbound,makeXrayFull,
  makeSingboxLxOutbound,prettyJson,validateCrypto,validatePublicKey
} from './lib.mjs';

const $ = id => document.getElementById(id);
let device = null;
let pendingRegistration = null;
let registering = false;
let lastError = '';

function message(text, error = false) {
  const el = $('statusMessage');
  el.textContent = text;
  el.classList.toggle('err', error);
  el.hidden = false;
}
function steps(text) { $('registrationSteps').hidden = false; $('registrationSteps').textContent = text; }
function switchTab(which) {
  const isReg = which === 'register';
  $('tabRegister').classList.toggle('active',isReg);
  $('tabImport').classList.toggle('active',!isReg);
  $('tabRegister').setAttribute('aria-selected',String(isReg));
  $('tabImport').setAttribute('aria-selected',String(!isReg));
  $('registerPane').hidden = !isReg;
  $('importPane').hidden = isReg;
}
async function loadDevice(raw, source) {
  await validateCrypto(raw);
  const conf = normalizeUsqueConfig(raw);
  device = conf;
  pendingRegistration = null;
  $('resultSection').hidden = false;
  $('deviceId').textContent = '设备 ID：' + (conf.id ? conf.id.slice(0,8) + '…' + conf.id.slice(-4) : '从本地配置导入');
  $('ip4').textContent = conf.ipv4;
  $('ip6').textContent = conf.ipv6 || '未分配';
  $('revealSecrets').checked = false;
  $('publicKeyOverride').value = '';
  $('portInput').value = '443';
  $('sniInput').value = 'consumer-masque.cloudflareclient.com';
  $('transport').value = 'h2';
  $('family').value='v4';
  $('endpointInput').value = conf.endpoint_h2_v4 || '162.159.198.2';
  $('outputFormat').value = 'xray-full';
  renderPreview();
  message(`${source}成功。设备私钥仅在当前页面内存中；请立即下载 usque 原生备份。`);
  $('resultSection').scrollIntoView({behavior:'smooth',block:'start'});
}
async function apiRequest(path, body, accessCode) {
  let res;
  try {
    res = await fetch(path, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-WARP-Action':'personal-enrollment','X-Registration-Token':accessCode},
      credentials:'same-origin',cache:'no-store',
      body:JSON.stringify(body)
    });
  } catch { throw new Error('无法连接注册后端。请检查 注册服务的部署与 /api/health 状态。'); }
  let data;
  try { data = await res.json(); } catch { throw new Error(`服务端不是 JSON 响应（HTTP ${res.status}），请检查 注册服务是否正常运行。`); }
  if (!res.ok) throw new Error(data.error || `请求失败，HTTP ${res.status}`);
  return data;
}
async function registerDevice() {
  if (registering) return;
  if (!$('tosCheck').checked) return message('注册前请先阅读并接受 Cloudflare 服务条款。',true);
  const code = $('accessCode').value.trim();
  if (!code) return message('请填写 服务端的注册访问口令。',true);
  if(!crypto?.subtle)return message('注册需要 HTTPS 或 localhost 安全环境',true);
  const name = $('deviceName').value.trim() || 'Web-MASQUE';
  registering = true; $('registerBtn').disabled = true;
  $('statusMessage').hidden = true;
  let history = [];
  const log = s => { history.push(s); steps(history.join('\n')); };
  try {
    if (!pendingRegistration) {
      log('01 / 03  正在浏览器本地生成 P-256 密钥…');
      const keys = await generateMasqueKeys();
      log('02 / 03  创建 Cloudflare WARP 个人设备账户…');
      const account = await apiRequest('/api/register', {
        key: await generateRegistrationPublicKey(), serial_number: bytesToHex(randomBytes(8)), tos: cfTimestamp()
      },code);
      if (!account?.id || !account?.token) throw new Error('上游注册响应缺少 id/token，请检查上游版本');
      pendingRegistration = {keys,account};
    } else {
      log('检测到上次注册已创建账户，尝试继续设备密钥登记（不重复新建账户）。');
    }
    log('03 / 03  将设备公钥登记为 MASQUE；私钥不上传…');
    const enrolled = await apiRequest('/api/enroll', {
      id:pendingRegistration.account.id,
      token:pendingRegistration.account.token,
      public_key:pendingRegistration.keys.publicKey,
      name
    },code);
    const newConfig = buildUsqueFromApi(pendingRegistration.account,enrolled,pendingRegistration.keys);
    log('✓ 已注册并完成 MASQUE enroll。');
    $('accessCode').value = '';
    await loadDevice(newConfig,'WARP MASQUE 注册');
  } catch (e) {
    log('✗ ' + String(e?.message || e));
    message(String(e?.message || e) + (pendingRegistration ? '。可再次点击注册以继续公钥登记，不会重复创建账号。' : ''),true);
  } finally {
    registering = false;
    $('registerBtn').disabled = false;
  }
}
async function importFile(file) {
  try {
    if (!file) return;
    if (file.size > 1048576) throw new Error('配置文件不能超过 1 MB');
    const raw = JSON.parse(await file.text());
    await loadDevice(raw,'导入');
    $('importText').value = '';
  } catch(e) { message('导入失败：' + e.message,true); }
}
async function importPasted() {
  try { if($('importText').value.length>1048576)throw Error('配置不能超过 1 MB'); await loadDevice(JSON.parse($('importText').value),'导入'); $('importText').value=''; }
  catch(e) { message('导入失败：' + e.message,true); }
}
function filename() {
  const f = $('outputFormat').value;
  const t = $('transport').value;
  if (f === 'usque') return 'usque-config.json';
  if (f === 'xray-full') return `warp-xray-${t}-full.json`;
  if (f === 'singbox-lx') return `warp-singbox-lx-${t}-outbound.json`;
  return `warp-xray-${t}-outbound.json`;
}
function currentOptions() {
  return {
    mode:$('transport').value,
    family:$('family').value,localPort:Number($('localPort').value),route:$('route').value,dns:$('dns').value,
    endpoint:$('endpointInput').value.trim(),
    port:Number($('portInput').value),
    sni:$('sniInput').value.trim(),
    publicKey:$('publicKeyOverride').value.trim()
  };
}
function getExport() {
  if (!device) throw new Error('请先注册或导入设备');
  const fmt = $('outputFormat').value;
  if (fmt === 'usque') return device;
  const opts = currentOptions();
  if (fmt === 'xray-outbound') return makeXrayOutbound(device,opts);
  if (fmt === 'xray-full') return makeXrayFull(device,opts);
  if (fmt === 'singbox-lx') return makeSingboxLxOutbound(device,opts);
  throw new Error('未知格式');
}
function masked(value) {
  const obj = structuredClone(value);
  function walk(x) {
    if (!x || typeof x !== 'object') return;
    for (const k of Object.keys(x)) {
      if (['private_key','privateKey','access_token','license'].includes(k)) x[k] = '•••• 已隐藏，下载文件包含原始值 ••••';
      else walk(x[k]);
    }
  }
  walk(obj); return obj;
}
function renderPreview() {
  if (!device) return;
  const fmt = $('outputFormat').value;
  $('previewTitle').textContent = filename();
  $('transport').disabled = fmt === 'usque';
  $('endpointInput').disabled = fmt === 'usque';
  $('portInput').disabled = fmt === 'usque';
  $('sniInput').disabled = fmt === 'usque';
  $('publicKeyOverride').disabled = fmt === 'usque';
  const notes = {
    'xray-outbound':'单个 Xray MASQUE 出站对象。新版 v2rayN 请选择“添加自定义出站服务器”，无需导入完整 config。',
    'xray-full':'完整配置：v2rayN → 添加自定义配置服务器 → 导入此 JSON，内核选 Xray。SOCKS 使用所填端口，HTTP 使用下一端口；请将客户端 SOCKS 端口与此保持一致。此配置的路由由文件管理。',
    'usque':'保留设备注册凭据，适合备份及 usque CLI 在 Windows、Linux、macOS、Android 等环境复用。',
    'singbox-lx':'仅适用于显式支持 WARP MASQUE 的 sing-box-lx 分支，不是原版 sing-box。这里导出单个出站，请合入带 DNS 的完整配置。'
  };
  $('formatNote').textContent = notes[fmt];
  try {
    const json = getExport();
    $('preview').textContent = prettyJson($('revealSecrets').checked ? json : masked(json));
    $('downloadBtn').disabled = false; $('copyBtn').disabled = false;
    lastError = '';
  } catch (e) {
    lastError = String(e.message);
    $('preview').textContent = '// 配置参数有误：' + lastError;
    $('downloadBtn').disabled = true; $('copyBtn').disabled = true;
  }
}
function saveFile(name, object) {
  const blob = new Blob([prettyJson(object)],{type:'application/json;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1500);
}
async function handleDownload() {
  try { if($('publicKeyOverride').value.trim())await validatePublicKey($('publicKeyOverride').value); saveFile(filename(),getExport()); message('已创建下载文件。此文件含设备密钥，请妥善保存。'); }
  catch (e) { message('下载失败：'+e.message,true); }
}
async function handleCopy() {
  try {
    if (!$('revealSecrets').checked && !confirm('复制的完整配置包含 WARP 私钥，可能进入系统剪贴板历史。确定复制？')) return;
    if($('publicKeyOverride').value.trim())await validatePublicKey($('publicKeyOverride').value);
    await navigator.clipboard.writeText(prettyJson(getExport()));
    message('已复制完整配置到剪贴板，请注意防止私钥泄露。');
  } catch (e) { message('复制失败。请使用下载按钮，或在 HTTPS 环境中重试。',true); }
}
function clearSensitive() {
  if(registering)return message('注册进行中，请等待完成后再清除',true);
  if (!device && !pendingRegistration) return;
  if (!confirm('清除当前页面中的设备凭据？如果尚未备份，私钥将无法恢复。')) return;
  device = null; pendingRegistration = null; lastError = '';
  $('resultSection').hidden = true;
  $('preview').textContent = '';
  $('registrationSteps').textContent = ''; $('registrationSteps').hidden = true;
  $('importText').value = ''; $('importFile').value = ''; $('accessCode').value = '';
  message('当前页面中的设备凭据已清除；已下载到设备的文件不会被删除。');
  window.scrollTo({top:0,behavior:'smooth'});
}
async function checkBackend() {
  const el = $('apiStatus');
  try {
    const res = await fetch('/api/health',{cache:'no-store'});
    if (!res.ok) throw Error();
    const data = await res.json();
    if (!data.ok) throw Error();
    el.textContent = data.registrationEnabled ? '注册服务已就绪' : '后端缺少访问口令';
    el.className = 'online ' + (data.registrationEnabled ? 'good' : 'error');
  } catch {
    el.textContent = '离线转换模式'; el.className = 'online error';
  }
}
$('tabRegister').addEventListener('click',()=>switchTab('register'));
$('tabImport').addEventListener('click',()=>switchTab('import'));
$('registerBtn').addEventListener('click',registerDevice);
$('importBtn').addEventListener('click',importPasted);
$('importFile').addEventListener('change',e=>importFile(e.target.files?.[0]));
$('outputFormat').addEventListener('change',renderPreview);
function updateEndpoint(){
  if (!device) return;
  $('publicKeyOverride').value = '';
  const key='endpoint_'+($('transport').value==='h2'?'h2_':'')+$('family').value;
  $('endpointInput').value=device[key]||'';
  renderPreview();
}
$('transport').addEventListener('change',updateEndpoint);
$('family').addEventListener('change',updateEndpoint);
['localPort','route','dns','endpointInput','portInput','sniInput','publicKeyOverride','revealSecrets'].forEach(id=>$(id).addEventListener('input',renderPreview));
$('downloadBtn').addEventListener('click',handleDownload);
$('copyBtn').addEventListener('click',handleCopy);
$('downloadUsqueBtn').addEventListener('click',()=>{ if(device) { saveFile('usque-config.json',device); message('已创建 usque 原生配置备份。'); } });
$('clearBtn').addEventListener('click',clearSensitive);
checkBackend();
