// Small, dependency-free helpers. All device secrets stay in browser memory.
const H2_DEFAULT = '162.159.198.2';
// Public pin for the standard personal-WARP H2 edge. Independently verify if Cloudflare rotates it.
// Source: Xray-core issue #7115, the 162.159.198.2 certificate SPKI.
const H2_DEFAULT_PUBLIC_KEY = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==';
const SNI_DEFAULT = 'consumer-masque.cloudflareclient.com';

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
export function privateDer(value) {
  const bytes=pemBytes(value), root=tlv(bytes);
  if(root.length!==1||root[0].tag!==48)throw Error('P-256 私钥 DER 无效');
  let parts=tlv(root[0].value);let pkcs8=parts[1]?.tag===48;
  if(pkcs8) {
    const alg=bytesToHex(parts[1].value);
    if(alg!==ALGORITHM+CURVE||parts[2]?.tag!==4)throw Error('私钥必须使用 P-256 曲线');
    const inner=tlv(parts[2].value);if(inner.length!==1||inner[0].tag!==48)throw Error('PKCS#8 私钥无效');parts=tlv(inner[0].value);
  }
  if(parts[0]?.tag!==2||bytesToHex(parts[0].value)!=='01'||parts[1]?.tag!==4||parts[1].value.length!==32||!parts[1].value.some(x=>x))throw Error('private_key 不是 P-256 SEC1/PKCS#8 私钥（不能使用 WireGuard 私钥）');
  const curve=parts.find(x=>x.tag===160);
  if((!pkcs8&&!curve)||(curve&&bytesToHex(curve.value)!==CURVE))throw Error('私钥必须使用 P-256 曲线');
  return {bytes,pkcs8,sec1:pkcs8?tlv(root[0].value)[2].value:bytes};
}
function pubFromPem(value) {
  const bytes=pemBytes(value), root=tlv(bytes);
  if(root.length!==1||root[0].tag!==48)throw Error('服务端公钥 DER 无效');
  const parts=tlv(root[0].value);
  if(parts.length!==2||parts[0].tag!==48||bytesToHex(parts[0].value)!==ALGORITHM+CURVE||parts[1].tag!==3||parts[1].value.length!==66||parts[1].value[0]!==0||parts[1].value[1]!==4)throw Error('服务端公钥必须是 P-256 SPKI');
  return bytesToB64(bytes);
}
export {pubFromPem};
export function validateUsqueConfig(cfg) {
  if(!cfg||typeof cfg!=='object'||Array.isArray(cfg))throw Error('配置应是 JSON 对象');
  try {privateDer(cfg.private_key);}catch(e){throw Error('private_key: '+e.message);}
  try {pubFromPem(cfg.endpoint_pub_key);}catch(e){throw Error('服务端公钥: '+e.message);}
  address(cfg.ipv4,32,ipv4);if(cfg.ipv6)address(cfg.ipv6,128,ipv6);
  for(const key of ['endpoint_v4','endpoint_v6','endpoint_h2_v4','endpoint_h2_v6'])if(cfg[key]&&!isIP(stripEndpoint(cfg[key])))throw Error(key+' 不是合法 IP');
  if(!cfg.endpoint_v4&&!cfg.endpoint_v6&&!cfg.endpoint_h2_v4&&!cfg.endpoint_h2_v6)throw Error('缺少 WARP MASQUE Endpoint');
  return true;
}
export async function validateCrypto(cfg) {
  validateUsqueConfig(cfg);
  const p=privateDer(cfg.private_key);
  const algorithm=der(48,concat(b64ToBytes('BgcqhkjOPQIB'),b64ToBytes('BggqhkjOPQMBBw==')));
  const pkcs=p.pkcs8?p.bytes:der(48,concat(Uint8Array.of(2,1,0),algorithm,der(4,p.bytes)));
  try {
    const key=await crypto.subtle.importKey('pkcs8',pkcs,{name:'ECDSA',namedCurve:'P-256'},true,['sign']);
    const jwk=await crypto.subtle.exportKey('jwk',key);
    const publicKey=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y},{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    const challenge=new TextEncoder().encode('warp-config-key-check');
    const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,challenge);
    if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,sig,challenge))throw Error();
    await validatePublicKey(cfg.endpoint_pub_key);
  } catch {throw Error('密钥校验失败：P-256 私钥、公钥或曲线点无效');}
}
export async function validatePublicKey(value){await crypto.subtle.importKey('spki',b64ToBytes(pubFromPem(value)),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);}
export function normalizeUsqueConfig(cfg) {
  validateUsqueConfig(cfg);
  return {
    private_key:bytesToB64(privateDer(cfg.private_key).sec1),
    endpoint_v4:stripEndpoint(cfg.endpoint_v4),endpoint_v6:stripEndpoint(cfg.endpoint_v6),
    endpoint_h2_v4:stripEndpoint(cfg.endpoint_h2_v4)||H2_DEFAULT,endpoint_h2_v6:stripEndpoint(cfg.endpoint_h2_v6),
    endpoint_pub_key:cfg.endpoint_pub_key,id:String(cfg.id||''),access_token:String(cfg.access_token||''),
    ...(cfg.license?{license:String(cfg.license)}:{}),ipv4:address(cfg.ipv4,32,ipv4),ipv6:cfg.ipv6?address(cfg.ipv6,128,ipv6):''
  };
}
export function buildUsqueFromApi(registerResponse, enrolled, keys) {
  if(enrolled?.warp_enabled===false) throw Error('设备尚未启用 WARP，请完成登记后重试');
  const peer = enrolled?.config?.peers?.[0];
  const address = enrolled?.config?.interface?.addresses;
  const cfg = {
    private_key: keys.privateKey,
    endpoint_v4: stripEndpoint(peer?.endpoint?.v4),
    endpoint_v6: stripEndpoint(peer?.endpoint?.v6),
    endpoint_h2_v4: H2_DEFAULT,
    endpoint_h2_v6: '',
    endpoint_pub_key: peer?.public_key || '',
    id: enrolled?.id || registerResponse?.id || '',
    access_token: registerResponse?.token || '',
    license: enrolled?.account?.license || registerResponse?.account?.license || '',
    ipv4: address?.v4 || '',
    ipv6: address?.v6 || ''
  };
  return normalizeUsqueConfig(cfg);
}
function validateServer(host) {
  if (!isIP(host)) throw new Error('端点地址无效');
  return host;
}
export function makeXrayOutbound(config, options = {}) {
  const cfg = normalizeUsqueConfig(config);
  const mode = options.mode === 'h3' ? 'h3' : 'h2';
  const target = options.family==='v6' ? (mode==='h2'?cfg.endpoint_h2_v6:cfg.endpoint_v6) : (mode==='h2'?cfg.endpoint_h2_v4:cfg.endpoint_v4);
  if(!target&&!options.endpoint)throw Error('此传输未提供 IPv6 端点，请填写已核验的官方端点');
  const host = validateServer(String(options.endpoint || target || '').trim());
  const port = Number(options.port ?? 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口必须为 1~65535');
  // H2 edge .2 is known to use its own pinned certificate key; H3 pin comes from enrolment.
  const selectedPin = options.publicKey || (mode === 'h2' && (host === H2_DEFAULT || host === '2606:4700:103::2') ? H2_DEFAULT_PUBLIC_KEY : cfg.endpoint_pub_key);
  const publicKey = pubFromPem(selectedPin);
  const addresses = [`${cfg.ipv4}/32`];
  if (cfg.ipv6) addresses.push(`${cfg.ipv6}/128`);
  const dns=String(options.dns||'1.1.1.1,1.0.0.1').split(/[,，\s]+/).filter(Boolean);
  if(!dns.length||dns.some(x=>!isIP(x)))throw Error('隧道 DNS 必须填写合法 IP 地址');
  const sni = String(options.sni || SNI_DEFAULT).trim();
  if (!/^[A-Za-z0-9.-]{1,253}$/.test(sni)) throw new Error('SNI 格式无效');
  return {
    protocol: 'masque',
    settings: { address: host, port, remoteDNS:dns },
    streamSettings: {
      method: 'masque',
      masqueSettings: { warp: { privateKey: cfg.private_key, publicKey, address: addresses } },
      security: 'tls',
      tlsSettings: { serverName: sni, alpn: [mode] }
    },
    tag: 'proxy'
  };
}
export function makeXrayFull(config, options = {}) {
  const outbound = makeXrayOutbound(config, options);
  const port=Number(options.localPort??10808);
  if(!Number.isInteger(port)||port<1024||port>65534)throw Error('本地 SOCKS 端口必须为 1024~65534，HTTP 使用相邻端口');
  const rules=options.route==='lan-direct'?[{type:'field',ip:['geoip:private'],outboundTag:'direct'}]:[];
  // Literal private ranges avoid requiring external geoip.dat.
  if(rules.length)rules[0].ip=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','::1/128','fc00::/7','fe80::/10'];
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      { tag: 'socks-in', listen: '127.0.0.1', port, protocol: 'socks', settings: { auth: 'noauth', udp: true } },
      { tag: 'http-in', listen: '127.0.0.1', port:port+1, protocol: 'http', settings: {} }
    ],
    outbounds: [outbound, { protocol: 'freedom', tag: 'direct' }],
    routing: { domainStrategy: 'AsIs', rules }
  };
}
export function makeSingboxLxOutbound(config, options = {}) {
  const cfg = normalizeUsqueConfig(config);
  const mode = options.mode === 'h3' ? 'h3' : 'h2';
  const xray = makeXrayOutbound(cfg, options);
  return {
    type: 'masque', tag: 'warp-masque', profile: 'cloudflare',
    server: xray.settings.address, server_port: xray.settings.port,
    vhttp: mode,
    private_key: cfg.private_key,
    public_key: xray.streamSettings.masqueSettings.warp.publicKey,
    ip: `${cfg.ipv4}/32`,
    ...(cfg.ipv6 ? { ipv6: `${cfg.ipv6}/128` } : {}),
    mtu: 1280,
    tls: { enabled: true, server_name: xray.streamSettings.tlsSettings.serverName }
  };
}
export const prettyJson = obj => JSON.stringify(obj, null, 2) + '\n';

export function extractWarpLicenses(text) {
  const pattern = /(?<![A-Za-z0-9-])[A-Za-z0-9]{8}(?:-[A-Za-z0-9]{8}){2}(?![A-Za-z0-9-])/g;
  return [...new Set(text.match(pattern) || [])];
}
