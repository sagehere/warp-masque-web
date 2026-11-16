// Uses fresh, unregistered test keys. Checks parsing only; does not claim connectivity.
import {generateMasqueKeys,makeXrayFull} from '../public/lib.mjs';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const dir=await mkdtemp(join(tmpdir(),'warp-xray-check-'));
try{const c={private_key:(await generateMasqueKeys()).privateKey,endpoint_v4:'162.159.198.1',endpoint_v6:'2606:4700:103::1',endpoint_pub_key:'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==',ipv4:'172.16.0.2',ipv6:'2606:4700:110::1'};
for(const mode of ['h2','h3']){const path=join(dir,mode+'.json');await writeFile(path,JSON.stringify(makeXrayFull(c,{mode,route:'lan-direct'})),{mode:0o600});const result=spawnSync(process.env.XRAY_BIN||'xray',['run','-test','-config',path],{encoding:'utf8'});if(result.status!==0)throw Error(result.stderr||result.error||result.stdout);console.log(mode+': Xray 配置加载通过');}}
finally{await rm(dir,{recursive:true,force:true});}
