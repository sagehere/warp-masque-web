import {
  bytesToHex, randomBytes, cfTimestamp, generateMasqueKeys, generateRegistrationPublicKey,
  buildUsqueFromApi, normalizeUsqueConfig, extractWarpLicenses, prettyJson,
  parsePrivateKeyInput, parseWireGuardKey, deriveMasqueKeysFromWireGuard,
  convertMasqueOutbound, importMasqueKeys, publicKeyFingerprint
} from './lib.mjs';

const $ = id => document.getElementById(id);
let device = null;
let deviceHasPlus = false;
let importing = false;
let pendingRegistration = null;
let registering = false;
let authorizing = false;
let activeTab = 'register';
let importedKeys = null;
let registrationEnabled = false;
let authorized = false;

function message(text, error = false) {
  const el = $('statusMessage');
  el.textContent = text;
  el.classList.toggle('err', error);
  el.hidden = false;
}
function steps(text) {
  $('progressPane').hidden = false;
  $('registrationSteps').textContent = text;
}

function switchTab(which) {
  if (registering || importing) return;
  activeTab = which;
  for (const [name, label] of [['register', 'Register'], ['private', 'Private'], ['import', 'Import']]) {
    const active = name === which;
    $('tab' + label).classList.toggle('active', active);
    $('tab' + label).setAttribute('aria-selected', String(active));
    $(name + 'Pane').hidden = !active;
  }
  renderAccess();
}

function displayDevice(conf, source, plus = false, connection = null) {
  device = conf;
  deviceHasPlus = plus;
  $('resultSection').hidden = false;
  $('deviceStatus').textContent = plus ? 'WARP+ 账户权益已确认' : '设备配置已载入';
  $('deviceId').textContent = '设备 ID：' + (conf.id ? conf.id.slice(0,8) + '…' + conf.id.slice(-4) : '从本地配置导入');
  $('ip4').textContent = conf.ipv4;
  $('ip6').textContent = conf.ipv6 || '未分配';
  const http2 = connection?.http2 ?? !(conf.endpoint_v4 || conf.endpoint_v6);
  const outerV6 = connection?.outerV6 ?? (http2 ? !conf.endpoint_h2_v4 : !conf.endpoint_v4);
  $('connectCommand').textContent = 'usque -c config.json socks --bind 127.0.0.1' +
    (http2 ? ' --http2' : '') + (outerV6 ? ' --ipv6' : '') +
    (connection?.port && connection.port !== 443 ? ' --connect-port ' + connection.port : '');
  message(`${source}成功，可以下载 usque 配置。`);
  $('resultSection').scrollIntoView({behavior: 'smooth', block: 'start'});
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

function renderAccess() {
  const secure = window.isSecureContext;
  const registerTab = activeTab === 'register';
  const showLogin = secure && registrationEnabled && !authorized &&
    (registerTab || (activeTab === 'private' && importedKeys));
  $('accessPane').hidden = secure && !showLogin;
  $('httpsNotice').hidden = secure;
  $('loginForm').hidden = !showLogin;
  $('registerUnavailable').hidden = !secure || !registerTab || registrationEnabled;
  $('licenseFlow').hidden = !secure || !authorized;
  $('privateEnrollment').hidden = !secure || !authorized || !importedKeys;
  $('privateActions').hidden = !importedKeys;
}

async function authorize(event) {
  event.preventDefault();
  if (authorizing || !window.isSecureContext) return;
  authorizing = true;
  $('loginBtn').disabled = true;
  try {
    await apiRequest('/api/session', {}, $('accessCode').value);
    $('accessCode').value = '';
    const health = await checkBackend();
    if (!health?.authorized) throw Error('会话未建立，请通过 HTTPS 或 localhost 访问。');
    $('statusMessage').hidden = true;
    $(activeTab === 'private' ? 'privateRegisterBtn' : 'licenseInput').focus();
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
  const privatePending = attempt?.mode === 'private';
  const ready = deviceHasPlus && !attempt;
  $('licenseInput').disabled = registering || keyLocked || ready;
  $('licenseChoice').disabled = $('licenseInput').disabled;
  $('registerBtn').disabled = registering || ready;
  $('freeRegisterBtn').disabled = registering || ready;
  $('privateKeyInput').disabled = registering || importing || privatePending;
  $('privateAnalyzeBtn').disabled = $('privateKeyInput').disabled;
  $('privateBackupBtn').disabled = registering || importing || privatePending;
  $('privateLicense').disabled = registering || keyLocked;
  $('privateRegisterBtn').disabled = registering || importing;
  $('clearPendingBtn').hidden = !attempt;
  $('clearPendingBtn').disabled = registering || importing;
  const retryText = attempt?.enrolled ? '确认 WARP+ 权益'
    : attempt?.bindingConfirmed ? '继续登记' : '继续生成';
  $('registerBtn').textContent = ready ? '配置已生成' : attempt?.mode === 'plus' ? retryText : '生成配置';
  $('privateRegisterBtn').textContent = privatePending ? retryText : '登记设备并生成 usque 配置';
}

async function registerDevice(mode) {
  if (registering || importing || !authorized || (mode === 'plus' && deviceHasPlus && !pendingRegistration)) return;
  if (!globalThis.crypto?.subtle) return message('注册需要 HTTPS 或 localhost 安全环境。', true);
  if (pendingRegistration && pendingRegistration.mode !== mode) {
    return message('请先完成或放弃当前登记，再使用其他注册方式。', true);
  }
  if (mode === 'free' && !$('tosCheck').checked) return message('请先确认免费 WARP 注册条款。', true);
  if (mode === 'private' && !importedKeys) return message('请先校验私钥。', true);
  let license = pendingRegistration?.bindingAttempt || '';
  if (!license && mode === 'plus') {
    const licenses = updateLicenseChoices();
    license = licenses.length === 1 ? licenses[0] : $('licenseChoice').value;
    if (!license) return message(licenses.length ? '请选择要使用的许可证。' : '请粘贴一条有效格式的 WARP+ 密钥。', true);
  }
  if (!license && mode === 'private') {
    license = $('privateLicense').value.trim();
    if (license && !/^[A-Za-z0-9]{8}(?:-[A-Za-z0-9]{8}){2}$/.test(license)) {
      return message('WARP+ 许可证格式无效。', true);
    }
  }
  const name = mode === 'free' ? $('deviceName').value.trim() || 'Web-MASQUE' : 'Web-MASQUE';
  registering = true;
  updateRegistrationControls();
  $('statusMessage').hidden = true;
  try {
    if (!pendingRegistration) {
      steps('正在注册 WARP 设备…');
      const keys = mode === 'private' ? importedKeys : await generateMasqueKeys();
      const account = await apiRequest('/api/register', {
        key: await generateRegistrationPublicKey(), serial_number: bytesToHex(randomBytes(8)), tos: cfTimestamp()
      });
      if (!account?.id || !account?.token) throw Error('Cloudflare 注册响应缺少设备 ID 或令牌。');
      pendingRegistration = {keys, account, mode};
    }
    const attempt = pendingRegistration;
    const credentials = {id: attempt.account.id, token: attempt.account.token};
    const licenseRequest = {...credentials, license};
    if (license && !attempt.bindingConfirmed) {
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
      attempt.enrolled = await buildUsqueFromApi(attempt.account, enrolled, attempt.keys);
    }
    if (license) {
      steps('正在确认当前设备的 WARP+ 权益…');
      const status = await apiRequest('/api/license/status', licenseRequest);
      if (!status.matched) throw Error('Cloudflare 尚未确认此设备绑定了所选许可证，请稍后继续。');
      if (!status.plus) throw Error('Cloudflare 已绑定此许可证，当前账户未显示 WARP+ 权益。请检查订阅状态后再继续。');
      attempt.enrolled.license = license;
    }
    displayDevice(attempt.enrolled, 'usque 配置生成', Boolean(license));
    pendingRegistration = null;
    if (mode === 'private') clearPrivateInput();
    $('licenseInput').value = '';
    updateLicenseChoices();
    steps('配置已生成，可下载。');
  } catch (error) {
    if (error.status === 401) {
      authorized = false;
      renderAccess();
    }
    steps('生成暂停');
    const rejectedKey = mode === 'private' && error.status === 422 && error.message.includes('公钥');
    message(error.message + (rejectedKey ? ' 如这把密钥已登记，可用原 usque 备份或完整的 MASQUE 出站 JSON 生成配置。'
      : pendingRegistration ? ' 再次点击可沿用当前设备继续。' : ''), true);
  } finally {
    registering = false;
    updateRegistrationControls();
  }
}
function parseConfig(text) {
  if (text.length > 1048576) throw Error('配置不能超过 1 MB');
  try { return JSON.parse(text); }
  catch { throw Error('配置 JSON 格式无效'); }
}

async function localImport(action) {
  if (registering || importing) return;
  if (!globalThis.crypto?.subtle) return message('密钥校验需要 HTTPS 或 localhost。', true);
  importing = true;
  updateRegistrationControls();
  try { await action(); }
  catch (error) { message(error.message, true); }
  finally { importing = false; updateRegistrationControls(); }
}

function importFile(file) {
  if (!file) return;
  return localImport(async () => {
    if (file.size > 1048576) throw Error('配置文件不能超过 1 MB');
    displayDevice(await normalizeUsqueConfig(parseConfig(await file.text())), '导入');
    $('importText').value = '';
    $('importFile').value = '';
  });
}

function importPasted() {
  return localImport(async () => {
    displayDevice(await normalizeUsqueConfig(parseConfig($('importText').value)), '导入');
    $('importText').value = '';
  });
}

function analyzePrivateKey() {
  return localImport(async () => {
    const input = parsePrivateKeyInput($('privateKeyInput').value);
    const wireGuardKey = input.backup || input.outbound ? null : parseWireGuardKey(input.privateKey);
    const keys = wireGuardKey ? await deriveMasqueKeysFromWireGuard(wireGuardKey) : await importMasqueKeys(input.privateKey);
    $('wireGuardNotice').hidden = !wireGuardKey;
    $('privateFingerprint').textContent = await publicKeyFingerprint(keys.publicKey);
    importedKeys = keys;
    renderAccess();
    if (input.backup) {
      displayDevice(await normalizeUsqueConfig(input.backup, keys.publicKey), '原设备配置生成');
      clearPrivateInput();
      return;
    }
    if (input.outbound) {
      const converted = await convertMasqueOutbound(input.outbound);
      displayDevice(converted.config, '原设备配置生成', false, converted);
      clearPrivateInput();
      return;
    }
    message(wireGuardKey ? 'WireGuard 私钥已在本地派生 MASQUE 密钥。'
      : '私钥已通过本地校验。请选择复用备份或登记新设备。');
  });
}

function importMatchingBackup() {
  if (!importedKeys) return;
  return localImport(async () => {
    const conf = await normalizeUsqueConfig(parseConfig($('privateBackupText').value), importedKeys.publicKey);
    displayDevice(conf, '原设备配置生成');
    clearPrivateInput();
  });
}

function clearPrivateInput() {
  importedKeys = null;
  $('privateKeyInput').value = '';
  $('privateBackupText').value = '';
  $('privateLicense').value = '';
  $('privateFingerprint').textContent = '';
  renderAccess();
}

function downloadConfig() {
  if (!device) return;
  const blob = new Blob([prettyJson(device)], {type:'application/json;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'config.json';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function clearPending() {
  if (!pendingRegistration || registering || importing) return;
  if (!confirm('放弃当前登记？Cloudflare 可能已保留已创建的设备。')) return;
  if (pendingRegistration.mode === 'private') clearPrivateInput();
  pendingRegistration = null;
  $('progressPane').hidden = true;
  updateRegistrationControls();
  message('已放弃当前登记。');
}

function clearSensitive() {
  if (registering || importing) return message('请等待当前操作完成后再清除。', true);
  if (!device && !pendingRegistration) return;
  if (!confirm('清除当前页面中的设备凭据？如果尚未备份，私钥将无法恢复。')) return;
  device = null; deviceHasPlus = false; pendingRegistration = null;
  $('resultSection').hidden = true;
  $('progressPane').hidden = true;
  clearPrivateInput();
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
    registrationEnabled = data.registrationEnabled;
    authorized = data.authorized;
    const secure = window.isSecureContext;
    el.textContent = !secure ? '生成配置需要 HTTPS' : registrationEnabled ? '注册服务已就绪' : '本地导入模式';
    el.className = 'online ' + (secure && registrationEnabled ? 'good' : 'error');
    renderAccess();
    return data;
  } catch {
    registrationEnabled = authorized = false;
    el.textContent = '服务连接失败'; el.className = 'online error';
    renderAccess();
  }
}
$('tabRegister').addEventListener('click', () => switchTab('register'));
$('tabPrivate').addEventListener('click', () => switchTab('private'));
$('tabImport').addEventListener('click', () => switchTab('import'));
$('loginForm').addEventListener('submit', authorize);
$('licenseInput').addEventListener('input', updateLicenseChoices);
$('registerBtn').addEventListener('click', () => registerDevice('plus'));
$('freeRegisterBtn').addEventListener('click', () => registerDevice('free'));
$('privateRegisterBtn').addEventListener('click', () => registerDevice('private'));
$('privateAnalyzeBtn').addEventListener('click', analyzePrivateKey);
$('privateBackupBtn').addEventListener('click', importMatchingBackup);
$('privateKeyInput').addEventListener('input', () => {
  importedKeys = null;
  $('privateFingerprint').textContent = '';
  renderAccess();
});
$('importBtn').addEventListener('click', importPasted);
$('importFile').addEventListener('change', event => importFile(event.target.files?.[0]));
$('downloadBtn').addEventListener('click', downloadConfig);
$('clearPendingBtn').addEventListener('click', clearPending);
$('clearBtn').addEventListener('click', clearSensitive);
checkBackend();
