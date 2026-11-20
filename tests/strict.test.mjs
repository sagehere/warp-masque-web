import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey, createPublicKey, generateKeyPairSync} from 'node:crypto';
import {
  generateMasqueKeys, importMasqueKeys, normalizeUsqueConfig, isIP, buildUsqueFromApi,
  parsePrivateKeyInput, convertMasqueOutbound, publicKeyFingerprint,
  parseWireGuardKey, deriveMasqueKeysFromWireGuard
} from '../public/lib.mjs';

const pin = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==';

function fixture(private_key) {
  return {private_key, endpoint_v4: '162.159.198.1', endpoint_v6: '2606:4700:103::1',
    endpoint_pub_key: pin, ipv4: '172.16.0.2/32', ipv6: '2606:4700:110::1/128',
    id: 'original-device', access_token: 'device-token'};
}

test('SEC1 和 PKCS#8 PEM/Base64 保留原公钥并输出原生 SEC1', async () => {
  const original = await generateMasqueKeys();
  const key = createPrivateKey({key: Buffer.from(original.privateKey, 'base64'), format: 'der', type: 'sec1'});
  for (const type of ['sec1', 'pkcs8']) {
    for (const format of ['pem', 'der']) {
      const input = key.export({format, type}).toString(format === 'der' ? 'base64' : 'utf8');
      const imported = await importMasqueKeys(input);
      assert.equal(imported.publicKey, original.publicKey);
      const config = await normalizeUsqueConfig(fixture(input), imported.publicKey);
      const sec1 = createPrivateKey({key: Buffer.from(config.private_key, 'base64'), format: 'der', type: 'sec1'});
      assert.equal(createPublicKey(sec1).export({format: 'der', type: 'spki'}).toString('base64'), original.publicKey);
      assert.equal(config.ipv4, '172.16.0.2');
      assert.equal(config.ipv6, '2606:4700:110::1');
      assert.equal(config.id, 'original-device');
      assert.equal(config.access_token, 'device-token');
      assert.equal(createPublicKey(config.endpoint_pub_key).export({format: 'der', type: 'spki'}).toString('base64'), pin);
    }
  }
});

test('拒绝私钥不匹配、错误曲线、错误地址族和未启用的登记响应', async () => {
  const key = await generateMasqueKeys();
  const another = await generateMasqueKeys();
  assert.match(await publicKeyFingerprint(key.publicKey), /^[0-9a-f]{64}$/);
  await assert.rejects(normalizeUsqueConfig(fixture(key.privateKey), another.publicKey), /不匹配/);
  const otherCurve = generateKeyPairSync('ec', {namedCurve: 'secp384r1'}).privateKey;
  await assert.rejects(importMasqueKeys(otherCurve.export({type: 'pkcs8', format: 'pem'})), /P-256/);
  assert.equal(isIP('1:2:3'), false);
  await assert.rejects(normalizeUsqueConfig({...fixture(key.privateKey), endpoint_v4: '2606:4700:103::2'}), /endpoint_v4/);
  await assert.rejects(buildUsqueFromApi({}, {warp_enabled: false}, {}), /尚未启用/);
});

test('从 MASQUE JSON 本地迁移非默认 H2 端口和 IPv6 端点', async () => {
  const key = await generateMasqueKeys();
  const outbound = {
    protocol: 'masque',
    settings: {address: '2606:4700:103::2', port: 8443},
    streamSettings: {
      tlsSettings: {alpn: ['h2']},
      masqueSettings: {warp: {privateKey: key.privateKey, publicKey: pin, address: ['172.16.0.2/32']}}
    }
  };
  const parsed = parsePrivateKeyInput(JSON.stringify({outbounds: [{protocol: 'socks'}, outbound]}));
  assert.equal(parsed.privateKey, key.privateKey);
  const result = await convertMasqueOutbound(parsed.outbound);
  assert.equal(result.config.endpoint_h2_v6, '2606:4700:103::2');
  assert.equal(result.config.endpoint_h2_v4, '');
  assert.equal(result.config.id, '');
  assert.equal(result.config.access_token, '');
  assert.equal(result.port, 8443);
  assert.equal(result.http2, true);
  assert.equal(result.outerV6, true);
  assert.deepEqual(parsePrivateKeyInput(key.privateKey), {privateKey: key.privateKey});
  assert.throws(() => parsePrivateKeyInput('{"outbounds":[]}'), /没有找到/);
});

test('从带流量说明的文本识别密钥，保留大小写和输入顺序', async () => {
  const {extractWarpLicenses} = await import('../public/lib.mjs');
  const first = 'Abcdef12-Abcdef34-Abcdef56';
  const second = '9abcdefG-8abcdefH-7abcdefI';
  assert.deepEqual(extractWarpLicenses(`密钥：\n${first}\n(1 GB)\n密钥：\n${second}\n${first}`), [first, second]);
  assert.deepEqual(extractWarpLicenses(`0${first}\n${second}-1234\n${first.slice(1)}`), []);
});


test('WireGuard 私钥与配置行派生同一 P-256 身份并且原私钥不进入 usque 文件', async () => {
  const raw = Buffer.from(Array.from({length: 32}, (_, index) => index + 1));
  const base64 = raw.toString('base64');
  const parsed = parsePrivateKeyInput(`[Interface]\r\nPrivateKey = ${base64} # 示例\r\nAddress = 10.0.0.2/32`);
  assert.equal(parsed.privateKey, base64);
  const normalized = parseWireGuardKey(base64);
  const result = await deriveMasqueKeysFromWireGuard(normalized);
  assert.equal(await publicKeyFingerprint(result.publicKey), '04582191a95ef60efe7f4a9be4abd9e569963de53f384776dd4ff04295d48602');
  assert.deepEqual(normalized, Uint8Array.from(raw));
  raw[0] ^= 7;
  raw[31] ^= 128;
  const equivalent = await deriveMasqueKeysFromWireGuard(parseWireGuardKey(raw.toString('base64')));
  assert.deepEqual(equivalent, result);
  const config = await normalizeUsqueConfig(fixture(result.privateKey), result.publicKey);
  assert.ok(!JSON.stringify(config).includes(base64));
  await assert.rejects(importMasqueKeys(base64), /WireGuard/);
  assert.throws(() => parseWireGuardKey(Buffer.alloc(32).toString('base64')), /全为零/);
  assert.throws(() => parsePrivateKeyInput('PrivateKey = invalid'), /32 字节/);
  assert.throws(() => parsePrivateKeyInput(`PrivateKey = ${base64}\nPrivateKey = ${base64}`), /多把/);
});
