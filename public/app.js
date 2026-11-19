import {
  bytesToHex,randomBytes,cfTimestamp,generateMasqueKeys,generateRegistrationPublicKey,
  buildUsqueFromApi,normalizeUsqueConfig,makeXrayOutbound,makeXrayFull,
  makeSingboxLxOutbound,extractWarpLicenses,prettyJson,validateCrypto,validatePublicKey
} from './lib.mjs';

const $ = id => document.getElementById(id);
let device = null;
let deviceHasPlus = false;
let importing = false;
let pendingRegistration = null;
let registering = false;
let authorizing = false;
let lastError = '';

function message(text, error = false) {
  const el = $('statusMessage');
  el.textContent = text;
  el.classList.toggle('err', error);
  el.hidden = false;
}
function steps(text) { $('registrationSteps').hidden = false; $('registrationSteps').textContent = text; }
function switchTab(which) {
  if (registering || importing) return;
  const isReg = which === 'register';
  $('tabRegister').classList.toggle('active',isReg);
  $('tabImport').classList.toggle('active',!isReg);
  $('tabRegister').setAttribute('aria-selected',String(isReg));
  $('tabImport').setAttribute('aria-selected',String(!isReg));
  $('registerPane').hidden = !isReg;
  $('importPane').hidden = isReg;
}
async function loadDevice(raw, source, plus = false) {
  await validateCrypto(raw);
  const conf = normalizeUsqueConfig(raw);
  device = conf;
  deviceHasPlus = plus;
  $('resultSection').hidden = false;
  $('exportSettings').open = false;
  $('deviceStatus').textContent = plus ? 'WARP+ 账户权益已确认' : '设备配置已载入';
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
  message(`${source}成功，可以下载 v2rayN 配置。`);
  $('resultSection').scrollIntoView({behavior:'smooth',block:'start'});
}
async function apiRequest(path, body, accessCode = "") {
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
  if (!res.ok) {
    const error = new Error(data.error || `请求失败，HTTP ${res.status}`);
    error.status = res.status;
    throw error;
  }
  return data;
}
function updateLicenseChoices() {
  const licenses = extractWarpLicenses($('licenseInput').value);
  const select = $('licenseChoice');
  const previous = select.value;
  select.replaceChildren(new Option('请选择密钥', ''));
  for (const [i, key] of licenses.entries()) {
    select.add(new Option(`第 ${i + 1} 条 · ${key.slice(0, 4)}…${key.slice(-4)}`, key));
  }
  if (licenses.includes(previous)) select.value = previous;
  $('licenseChoiceField').hidden = licenses.length < 2;
  return licenses;
}

function showRegistrationAccess(authorized, enabled = true) {
  $('loginForm').hidden = !enabled || authorized;
  $('licenseFlow').hidden = !enabled || !authorized;
}

async function authorize(event) {
  event.preventDefault();
  if (authorizing) return;
  authorizing = true;
  $('loginBtn').disabled = true;
  try {
    await apiRequest('/api/session', {}, $('accessCode').value);
    $('accessCode').value = '';
    const health = await checkBackend();
    if (!health?.authorized) throw Error('会话未建立，请通过 HTTPS 域名或 localhost 访问。');
    $('statusMessage').hidden = true;
    $('licenseInput').focus();
  } catch (error) {
    message(error.message, true);
  } finally {
    authorizing = false;
    $('loginBtn').disabled = false;
  }
}

function updateRegistrationControls() {
  const attempt = pendingRegistration;
  const keyLocked = Boolean(attempt?.bindingAttempt);
  const ready = deviceHasPlus;
  $('licenseInput').disabled = registering || keyLocked || ready;
  $('licenseChoice').disabled = $('licenseInput').disabled;
  $('registerBtn').disabled = registering || ready;
  $('freeRegisterBtn').disabled = registering || Boolean(attempt?.mode === 'plus') || ready;
  $('registerBtn').textContent = ready ? '配置已生成'
    : attempt?.enrolled ? '确认 WARP+ 权益'
    : attempt?.bindingConfirmed ? '继续登记'
    : attempt?.mode === 'plus' ? '继续生成' : '生成配置';
}

async function registerDevice(mode) {
  if (registering || importing || (mode === 'plus' && deviceHasPlus)) return;
  if (!globalThis.crypto?.subtle) return message('注册需要 HTTPS 或 localhost 安全环境。', true);
  if (pendingRegistration && pendingRegistration.mode !== mode) {
    return message('请先完成当前页面的设备注册。', true);
  }
  if (mode === 'free' && !$('tosCheck').checked) return message('请先确认免费 WARP 注册条款。', true);
  const licenses = updateLicenseChoices();
  const license = pendingRegistration?.bindingAttempt || (licenses.length === 1 ? licenses[0] : $('licenseChoice').value);
  if (mode === 'plus' && !license) {
    return message(licenses.length ? '请选择要使用的许可证。' : '请粘贴一条有效格式的 WARP+ 密钥。', true);
  }
  const name = mode === 'plus' ? 'Web-MASQUE' : $('deviceName').value.trim() || 'Web-MASQUE';
  registering = true;
  updateRegistrationControls();
  $('statusMessage').hidden = true;
  try {
    if (!pendingRegistration) {
      steps('正在生成设备密钥并注册 WARP 设备…');
      const keys = await generateMasqueKeys();
      const account = await apiRequest('/api/register', {
        key: await generateRegistrationPublicKey(), serial_number: bytesToHex(randomBytes(8)), tos: cfTimestamp()
      });
      if (!account?.id || !account?.token) throw Error('Cloudflare 注册响应缺少设备 ID 或令牌。');
      pendingRegistration = {keys, account, mode};
    }
    const attempt = pendingRegistration;
    const credentials = {id: attempt.account.id, token: attempt.account.token};
    const licenseRequest = {...credentials, license};
    if (mode === 'plus' && !attempt.bindingConfirmed) {
      if (attempt.bindingAttempt) {
        steps('正在查询上次许可证绑定的结果…');
        const status = await apiRequest('/api/license/status', licenseRequest);
        attempt.bindingConfirmed = status.matched;
      }
      if (!attempt.bindingConfirmed) {
        steps('正在将 WARP+ 许可证绑定到当前设备…');
        attempt.bindingAttempt = license;
        try {
          await apiRequest('/api/license', licenseRequest);
          attempt.bindingConfirmed = true;
        } catch (error) {
          if ([409, 422].includes(error.status)) attempt.bindingAttempt = '';
          throw error;
        }
      }
    }
    if (!attempt.enrolled) {
      steps('正在登记 MASQUE 设备公钥…');
      const enrolled = await apiRequest('/api/enroll', {...credentials, public_key: attempt.keys.publicKey, name});
      if (enrolled.id && enrolled.id !== credentials.id) throw Error('Cloudflare 返回了不同的设备 ID。');
      const config = buildUsqueFromApi(attempt.account, enrolled, attempt.keys);
      if (mode === 'plus') config.license = license;
      await validateCrypto(config);
      attempt.enrolled = config;
    }
    if (mode === 'plus') {
      steps('正在确认当前设备的 WARP+ 权益…');
      const status = await apiRequest('/api/license/status', licenseRequest);
      if (!status.matched) throw Error('Cloudflare 尚未确认此设备绑定了所选许可证，请稍后继续。');
      if (!status.plus) throw Error('Cloudflare 已绑定此许可证，当前账户未显示 WARP+ 权益。请检查订阅状态后再继续。');
    }
    await loadDevice(attempt.enrolled, mode === 'plus' ? 'WARP+ MASQUE 配置生成' : 'WARP MASQUE 注册', mode === 'plus');
    pendingRegistration = null;
    $('licenseInput').value = '';
    updateLicenseChoices();
    steps('配置已生成，可下载。');
  } catch (error) {
    if (error.status === 401) showRegistrationAccess(false);
    steps('生成暂停');
    message(error.message + (pendingRegistration ? ' 再次点击可沿用当前设备继续。' : ''), true);
  } finally {
    registering = false;
    updateRegistrationControls();
  }
}
async function importFile(file) {
  if (!file || registering || importing) return;
  importing = true;
  try {
    if (file.size > 1048576) throw new Error('配置文件不能超过 1 MB');
    const raw = JSON.parse(await file.text());
    await loadDevice(raw,'导入');
    $('importText').value = '';
  } catch(e) { message('导入失败：' + e.message,true); }
  finally { importing = false; updateRegistrationControls(); }
}
async function importPasted() {
  if (registering || importing) return;
  importing = true;
  try { if($('importText').value.length>1048576)throw Error('配置不能超过 1 MB'); await loadDevice(JSON.parse($('importText').value),'导入'); $('importText').value=''; }
  catch(e) { message('导入失败：' + e.message,true); }
  finally { importing = false; updateRegistrationControls(); }
}
function filename() {
  const f = $('outputFormat').value;
  const t = $('transport').value;
  if (f === 'usque') return 'usque-config.json';
  if (f === 'xray-full') return `warp-masque-xray-${t}.json`;
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
  if (registering || importing) return message('请等待当前操作完成后再清除。', true);
  if (!device && !pendingRegistration) return;
  if (!confirm('清除当前页面中的设备凭据？如果尚未备份，私钥将无法恢复。')) return;
  device = null; deviceHasPlus = false; pendingRegistration = null; lastError = '';
  $('resultSection').hidden = true;
  $('preview').textContent = '';
  $('registrationSteps').textContent = ''; $('registrationSteps').hidden = true;
  $('importText').value = ''; $('importFile').value = ''; $('accessCode').value = '';
  $('licenseInput').value = '';
  updateLicenseChoices();
  updateRegistrationControls();
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
    showRegistrationAccess(data.authorized, data.registrationEnabled);
    return data;
  } catch {
    el.textContent = '离线转换模式'; el.className = 'online error';
  }
}
$('tabRegister').addEventListener('click',()=>switchTab('register'));
$('tabImport').addEventListener('click',()=>switchTab('import'));
$('loginForm').addEventListener('submit', authorize);
$('licenseInput').addEventListener('input', updateLicenseChoices);
$('registerBtn').addEventListener('click', () => registerDevice('plus'));
$('freeRegisterBtn').addEventListener('click', () => registerDevice('free'));
$('quickDownloadBtn').addEventListener('click', () => {
  if (!device) return;
  try {
    saveFile('warp-masque-xray.json', makeXrayFull(device, {
      mode: 'h2', family: 'v4', endpoint: device.endpoint_h2_v4, localPort: 10808
    }));
  } catch (error) {
    message('下载失败：' + error.message, true);
  }
});
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
