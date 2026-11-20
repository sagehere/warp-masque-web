import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey} from 'node:crypto';
import {
  generateMasqueKeys, normalizeUsqueConfig, buildUsqueFromApi, stripEndpoint
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
  assert.equal(stripEndpoint('162.159.198.1:0'),'162.159.198.1');
  assert.equal(stripEndpoint('[2606:4700:103::1]:0'),'2606:4700:103::1');
  const normalized = await normalizeUsqueConfig(conf);
  assert.equal(normalized.endpoint_pub_key, PEM);
  assert.equal(normalized.endpoint_h2_v4,'162.159.198.2');
  assert.equal(normalized.access_token,'dummy-for-test');
});
test('拒绝 Curve25519 WireGuard 私钥与缺失公钥',async()=>{
  const conf = await a();
  conf.private_key=Buffer.alloc(32,1).toString('base64');
  await assert.rejects(normalizeUsqueConfig(conf),/WireGuard/);
  const c = await a(); c.endpoint_pub_key='not valid';
  await assert.rejects(normalizeUsqueConfig(c),/公钥/);
});
test('注册 JSON 按 usque 格式整理',async()=>{
  const k=await generateMasqueKeys();
  const conf=await buildUsqueFromApi({id:'device-1',token:'token-123456'},
    {config:{peers:[{endpoint:{v4:'162.159.198.1:0',v6:'[2606:4700:103::1]:0'},public_key:PEM}],interface:{addresses:{v4:'172.16.0.2',v6:'2606:4700:110::1234'}}}},k);
  assert.equal(conf.id,'device-1');assert.equal(conf.endpoint_v4,'162.159.198.1');
  assert.equal(conf.access_token,'token-123456');
});
