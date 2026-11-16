import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey} from 'node:crypto';
import {
  generateMasqueKeys, normalizeUsqueConfig, validateUsqueConfig,
  makeXrayOutbound,makeXrayFull,makeSingboxLxOutbound,
  buildUsqueFromApi,stripEndpoint,pubFromPem
} from '../public/lib.mjs';

const PEM = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n-----END PUBLIC KEY-----\n';
const a = async () => {
  const k = await generateMasqueKeys();
  return {
    private_key:k.privateKey,
    endpoint_pub_key:PEM,
    endpoint_v4:'162.159.198.1',endpoint_v6:'2606:4700:103::1',
    endpoint_h2_v4:'162.159.198.2',endpoint_h2_v6:'',
    id:'0000-1111',access_token:'dummy-for-test',ipv4:'172.16.0.2',ipv6:'2606:4700:110::1234'
  };
};

test('生成 WebCrypto P-256 SEC1 Base64 私钥，Node 可解析',async()=>{
  const keys = await generateMasqueKeys();
  const keyObj = createPrivateKey({key:Buffer.from(keys.privateKey,'base64'),format:'der',type:'sec1'});
  assert.equal(keyObj.asymmetricKeyType,'ec');
  assert.equal(keyObj.asymmetricKeyDetails.namedCurve,'prime256v1');
  assert.ok(keys.publicKey.startsWith('MFkw'));
});
test('usque 格式验证、PEM 解析、Endpoint',async()=>{
  const conf = await a();
  assert.equal(validateUsqueConfig(conf),true);
  assert.ok(pubFromPem(PEM).startsWith('MFkw'));
  assert.equal(stripEndpoint('162.159.198.1:0'),'162.159.198.1');
  assert.equal(stripEndpoint('[2606:4700:103::1]:0'),'2606:4700:103::1');
  const normalized = normalizeUsqueConfig(conf);
  assert.equal(normalized.endpoint_h2_v4,'162.159.198.2');
  assert.equal(normalized.access_token,'dummy-for-test');
});
test('拒绝 Curve25519 WireGuard 私钥与缺失公钥',async()=>{
  const conf = await a();
  conf.private_key=Buffer.alloc(32,1).toString('base64');
  assert.throws(()=>validateUsqueConfig(conf),/private_key/);
  const c = await a(); c.endpoint_pub_key='not valid';
  assert.throws(()=>validateUsqueConfig(c),/公钥/);
});
test('Xray H2/H3 自定义出站选择正确 Endpoint / ALPN',async()=>{
  const conf = await a();
  const h2 = makeXrayOutbound(conf,{mode:'h2'});
  const h3 = makeXrayOutbound(conf,{mode:'h3'});
  assert.equal(h2.protocol,'masque');
  assert.equal(h2.settings.address,'162.159.198.2');
  assert.equal(h3.settings.address,'162.159.198.1');
  assert.deepEqual(h2.streamSettings.tlsSettings.alpn,['h2']);
  assert.deepEqual(h3.streamSettings.tlsSettings.alpn,['h3']);
  assert.deepEqual(h2.streamSettings.masqueSettings.warp.address,['172.16.0.2/32','2606:4700:110::1234/128']);
  assert.equal(h2.streamSettings.masqueSettings.warp.publicKey,pubFromPem(PEM));
  assert.equal(h2.streamSettings.masqueSettings.warp.privateKey,conf.private_key);
});
test('全量 Xray 配置只在 localhost 监听',async()=>{
  const full=makeXrayFull(await a());
  assert.equal(full.inbounds.length,2);
  assert.ok(full.inbounds.every(i=>i.listen==='127.0.0.1'));
  assert.equal(full.outbounds[0].protocol,'masque');
  assert.equal(full.inbounds[1].port,10809);
});
test('sing-box-lx 出站标注明确类型与专属字段',async()=>{
  const s=makeSingboxLxOutbound(await a(),{mode:'h2'});
  assert.equal(s.type,'masque');assert.equal(s.profile,'cloudflare');assert.equal(s.vhttp,'h2');
  assert.equal(s.tls.server_name,'consumer-masque.cloudflareclient.com');
});
test('注册 JSON 按 usque 格式整理',async()=>{
  const k=await generateMasqueKeys();
  const conf=buildUsqueFromApi({id:'device-1',token:'token-123456'},
    {config:{peers:[{endpoint:{v4:'162.159.198.1:0',v6:'[2606:4700:103::1]:0'},public_key:PEM}],interface:{addresses:{v4:'172.16.0.2',v6:'2606:4700:110::1234'}}}},k);
  assert.equal(conf.id,'device-1');assert.equal(conf.endpoint_v4,'162.159.198.1');
  assert.equal(conf.access_token,'token-123456');
});
