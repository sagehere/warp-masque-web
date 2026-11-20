// Small, dependency-free helpers. All device secrets stay in browser memory.
const H2_DEFAULT = '162.159.198.2';
export function derLength(n) {
  if (!Number.isInteger(n) || n < 0) throw new Error('DER 长度错误');
  if (n < 128) return Uint8Array.of(n);
  const b = [];
  while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); }
  return Uint8Array.of(0x80 | b.length, ...b);
}
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, v) => n + v.length, 0));
  let k = 0; for (const v of parts) { out.set(v, k); k += v.length; } return out;
}
export const der = (tag, payload) => concat(Uint8Array.of(tag), derLength(payload.length), payload);
export function b64ToBytes(raw) {
  const s = String(raw).replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('Base64 格式错误');
  const p = s.padEnd(Math.ceil(s.length / 4) * 4, '=');
  const str = atob(p);
  return Uint8Array.from(str, c => c.charCodeAt(0));
}
export function bytesToB64(arr) {
  let s = '';
  for (let i = 0; i < arr.length; i += 8192) s += String.fromCharCode(...arr.subarray(i, i + 8192));
  return btoa(s);
}
export function bytesToHex(arr) { return Array.from(arr, v => v.toString(16).padStart(2, '0')).join(''); }
export function randomBytes(size) { const x = new Uint8Array(size); crypto.getRandomValues(x); return x; }
export function sec1P256(jwk) {
  const d = b64ToBytes(jwk.d), x = b64ToBytes(jwk.x), y = b64ToBytes(jwk.y);
  if (d.length !== 32 || x.length !== 32 || y.length !== 32) throw new Error('P-256 密钥长度不正确');
  const oid = Uint8Array.of(0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07);
  return der(0x30, concat(
    Uint8Array.of(0x02,0x01,0x01),
    der(0x04,d),
    der(0xa0,oid),
    der(0xa1,der(0x03,concat(Uint8Array.of(0),Uint8Array.of(0x04),x,y)))
  ));
}
export async function generateMasqueKeys() {
  if (!crypto?.subtle) throw new Error('需要 HTTPS 安全环境才能生成密钥');
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  return { privateKey: bytesToB64(sec1P256(jwk)), publicKey: bytesToB64(spki) };
}
export async function generateRegistrationPublicKey() {
  // The temporary WireGuard registration key is replaced immediately during MASQUE enrolment.
  // Modern browsers provide X25519; older ones can use a random 32-byte placeholder.
  try {
    const pair = await crypto.subtle.generateKey({name:'X25519'}, true, ['deriveBits']);
    return bytesToB64(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)));
  } catch { throw Error('当前浏览器不支持 X25519 注册密钥，请升级浏览器，或导入已有 usque 配置'); }
}
export function cfTimestamp(date = new Date()) {
  // Cloudflare accepts RFC3339 with milliseconds and timezone; ISO UTC is unambiguous.
  return date.toISOString();
}
export function stripEndpoint(value) {
  const s = String(value || '').trim();
  if (/^\[[^\]]+\](?::\d+)?$/.test(s)) return s.slice(1,s.indexOf(']'));
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(s)) return s.slice(0,s.lastIndexOf(':'));
  return s;
}
function ipv4(s) { return typeof s==='string' && s.split('.').length===4 && s.split('.').every(x=>/^(0|[1-9]\d{0,2})$/.test(x)&&+x<=255); }
function ipv6(s) {
  if(typeof s!=='string'||!s.includes(':')||s.includes('%')||s.includes('/')||s.includes('[')) return false;
  try { return new URL('http://['+s+']/').hostname.startsWith('['); } catch { return false; }
}
export function isIP(s) { return ipv4(s)||ipv6(s); }
function address(value, bits, check) {
  const parts=String(value||'').trim().split('/');
  if(parts.length>2||!check(parts[0])||(parts.length===2&&parts[1]!==String(bits))) throw new Error('WARP 分配的 IP 地址或前缀无效');
  return parts[0];
}
function pemBytes(value) { return b64ToBytes(String(value||'').replace(/-----[A-Z ]+-----/g,'').replace(/\s+/g,'')); }
function tlv(bytes) {
  let i=0;
  function read(){
    if(i+2>bytes.length) throw Error('DER 截断');
    const tag=bytes[i++];let n=bytes[i++];
    if(n&128){const count=n&127;if(!count||count>3||i+count>bytes.length)throw Error('DER 长度无效');n=0;for(let j=0;j<count;j++)n=n*256+bytes[i++];}
    if(i+n>bytes.length)throw Error('DER 内容截断');const value=bytes.slice(i,i+n);i+=n;return {tag,value};
  }
  const out=[];while(i<bytes.length)out.push(read());return out;
}
const CURVE='06082a8648ce3d030107', ALGORITHM='06072a8648ce3d0201';
function privateDer(value) {
  const bytes = pemBytes(value);
  if (bytes.length === 32) throw Error('检测到 32 字节密钥。请提供 MASQUE 的 P-256 私钥，WireGuard 密钥无法用于登记。');
  const root = tlv(bytes);
  if (root.length !== 1 || root[0].tag !== 48) throw Error('P-256 私钥 DER 无效');
  let parts = tlv(root[0].value);
  const pkcs8 = parts[1]?.tag === 48;
  if (pkcs8) {
    const alg = bytesToHex(parts[1].value);
    if (alg !== ALGORITHM + CURVE || parts[2]?.tag !== 4) throw Error('私钥必须使用 P-256 曲线');
    const inner = tlv(parts[2].value);
    if (inner.length !== 1 || inner[0].tag !== 48) throw Error('PKCS#8 私钥无效');
    parts = tlv(inner[0].value);
  }
  if (parts[0]?.tag !== 2 || bytesToHex(parts[0].value) !== '01' ||
      parts[1]?.tag !== 4 || parts[1].value.length !== 32 || !parts[1].value.some(x => x)) {
    throw Error('请输入 P-256 SEC1 或 PKCS#8 私钥');
  }
  const curve = parts.find(x => x.tag === 160);
  if ((!pkcs8 && !curve) || (curve && bytesToHex(curve.value) !== CURVE)) throw Error('私钥必须使用 P-256 曲线');
  return {bytes, pkcs8};
}

export function parsePrivateKeyInput(text) {
  const value = text.trim();
  if (!value) throw Error('请输入 MASQUE 私钥');
  if (!value.startsWith('{')) return {privateKey: value};
  let config;
  try { config = JSON.parse(value); }
  catch { throw Error('配置 JSON 格式无效'); }
  const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [config];
  const masque = outbounds.filter(outbound => typeof outbound?.streamSettings?.masqueSettings?.warp?.privateKey === 'string');
  const candidates = [config.private_key, config.privateKey, ...masque.map(outbound => outbound.streamSettings.masqueSettings.warp.privateKey)];
  const keys = [...new Set(candidates.filter(key => typeof key === 'string' && key.trim()).map(key => key.trim()))];
  if (!keys.length) throw Error('JSON 中没有找到 MASQUE 私钥');
  if (keys.length > 1) throw Error('JSON 中有多把私钥，请单独粘贴要使用的一把');
  return {privateKey: keys[0], outbound: masque.length === 1 ? masque[0] : undefined, backup: config.endpoint_pub_key ? config : undefined};
}

export async function convertMasqueOutbound(outbound) {
  const {warp} = outbound.streamSettings.masqueSettings;
  const {tlsSettings} = outbound.streamSettings;
  const alpn = Array.isArray(tlsSettings?.alpn) ? tlsSettings.alpn.filter(x => x === 'h2' || x === 'h3') : [];
  const transport = [...new Set(alpn)];
  const endpoint = stripEndpoint(outbound.settings?.address);
  const port = Number(outbound.settings?.port ?? 443);
  if (transport.length !== 1 || !isIP(endpoint) || !warp.publicKey || !Array.isArray(warp.address) ||
      !Number.isInteger(port) || port < 1 || port > 65535) {
    throw Error('MASQUE 出站缺少明确的 H2/H3、IP 端点、端口、设备地址或服务端公钥');
  }
  const http2 = transport[0] === 'h2';
  const outerV6 = ipv6(endpoint);
  const endpointField = 'endpoint_' + (http2 ? 'h2_' : '') + (outerV6 ? 'v6' : 'v4');
  const config = await normalizeUsqueConfig({
    private_key: warp.privateKey,
    [endpointField]: endpoint,
    endpoint_pub_key: warp.publicKey,
    ipv4: warp.address.find(addr => ipv4(String(addr).split('/')[0])),
    ipv6: warp.address.find(addr => ipv6(String(addr).split('/')[0]))
  });
  return {config, http2, outerV6, port};
}

export async function importMasqueKeys(value) {
  const {bytes, pkcs8} = privateDer(value);
  const algorithm = der(48, concat(b64ToBytes('BgcqhkjOPQIB'), b64ToBytes('BggqhkjOPQMBBw==')));
  const encoded = pkcs8 ? bytes : der(48, concat(Uint8Array.of(2, 1, 0), algorithm, der(4, bytes)));
  try {
    const params = {name: 'ECDSA', namedCurve: 'P-256'};
    const key = await crypto.subtle.importKey('pkcs8', encoded, params, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    const verifyKey = await crypto.subtle.importKey('jwk', {
      kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y
    }, params, true, ['verify']);
    const challenge = new TextEncoder().encode('warp-config-key-check');
    const signParams = {name: 'ECDSA', hash: 'SHA-256'};
    const signature = await crypto.subtle.sign(signParams, key, challenge);
    if (!await crypto.subtle.verify(signParams, verifyKey, signature, challenge)) throw Error();
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', verifyKey));
    return {privateKey: bytesToB64(sec1P256(jwk)), publicKey: bytesToB64(spki)};
  } catch {
    throw Error('无法通过 P-256 私钥校验');
  }
}

export async function publicKeyFingerprint(publicKey) {
  const hash = await crypto.subtle.digest('SHA-256', b64ToBytes(publicKey));
  return bytesToHex(new Uint8Array(hash));
}

function pubFromPem(value) {
  const bytes=pemBytes(value), root=tlv(bytes);
  if(root.length!==1||root[0].tag!==48)throw Error('服务端公钥 DER 无效');
  const parts=tlv(root[0].value);
  if(parts.length!==2||parts[0].tag!==48||bytesToHex(parts[0].value)!==ALGORITHM+CURVE||parts[1].tag!==3||parts[1].value.length!==66||parts[1].value[0]!==0||parts[1].value[1]!==4)throw Error('服务端公钥必须是 P-256 SPKI');
  return bytesToB64(bytes);
}
export async function normalizeUsqueConfig(cfg, expectedPublicKey) {
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) throw Error('配置应是 JSON 对象');
  const deviceKey = await importMasqueKeys(cfg.private_key);
  if (expectedPublicKey && deviceKey.publicKey !== expectedPublicKey) {
    throw Error('所输入的私钥与原设备备份不匹配');
  }
  let pin;
  try {
    pin = pubFromPem(cfg.endpoint_pub_key);
    await crypto.subtle.importKey('spki', b64ToBytes(pin), {name: 'ECDSA', namedCurve: 'P-256'}, false, ['verify']);
  } catch {
    throw Error('服务端公钥必须是有效的 P-256 SPKI 公钥');
  }
  const endpoints = {};
  for (const key of ['endpoint_v4', 'endpoint_v6', 'endpoint_h2_v4', 'endpoint_h2_v6']) {
    endpoints[key] = stripEndpoint(cfg[key]);
    const check = key.endsWith('_v4') ? ipv4 : ipv6;
    if (endpoints[key] && !check(endpoints[key])) throw Error(key + ' 的 IP 地址无效');
  }
  if (!Object.values(endpoints).some(Boolean)) throw Error('缺少 WARP MASQUE Endpoint');
  if (!endpoints.endpoint_h2_v4 && !endpoints.endpoint_h2_v6) endpoints.endpoint_h2_v4 = H2_DEFAULT;
  return {
    private_key: deviceKey.privateKey,
    ...endpoints,
    endpoint_pub_key: '-----BEGIN PUBLIC KEY-----\n' + pin.match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----\n',
    id: String(cfg.id || ''),
    access_token: String(cfg.access_token || ''),
    ...(cfg.license ? {license: String(cfg.license)} : {}),
    ipv4: address(cfg.ipv4, 32, ipv4),
    ipv6: cfg.ipv6 ? address(cfg.ipv6, 128, ipv6) : ''
  };
}

export async function buildUsqueFromApi(registerResponse, enrolled, keys) {
  if (enrolled?.warp_enabled === false) throw Error('设备尚未启用 WARP，请完成登记后重试');
  const peer = enrolled?.config?.peers?.[0];
  const addresses = enrolled?.config?.interface?.addresses;
  if (!peer?.endpoint?.v4 && !peer?.endpoint?.v6) throw Error('Cloudflare 未返回 MASQUE 端点，请继续登记');
  return normalizeUsqueConfig({
    private_key: keys.privateKey,
    endpoint_v4: peer.endpoint.v4,
    endpoint_v6: peer.endpoint.v6,
    endpoint_pub_key: peer.public_key,
    id: enrolled.id || registerResponse.id,
    access_token: registerResponse.token,
    license: enrolled.account?.license || registerResponse.account?.license,
    ipv4: addresses?.v4,
    ipv6: addresses?.v6
  }, keys.publicKey);
}
export const prettyJson = obj => JSON.stringify(obj, null, 2) + '\n';

export function extractWarpLicenses(text) {
  const pattern = /(?<![A-Za-z0-9-])[A-Za-z0-9]{8}(?:-[A-Za-z0-9]{8}){2}(?![A-Za-z0-9-])/g;
  return [...new Set(text.match(pattern) || [])];
}
