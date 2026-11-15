import { sim } from '../sim/runner.js';
await sim.start();
for (const sc of ['full','round2','round3','offline'] as const) {
  await sim.run(sc);
}
const s = sim.snapshot();
for (const st of s.steps) console.log(st.status, st.ms, st.title, st.error ? 'ERR: '+String(st.error).slice(0,300) : JSON.stringify(st.result)?.slice(0,250));
console.log('findings', s.findings.length, 'active', s.findings.filter((f:any)=>f.active).length, 'jira', s.jira.map((i:any)=>i.key+':'+i.fields.labels[1]+':'+i.fields.status.name).join(' '));
console.log('emails', s.emails.length, s.emails[0]?.tls, s.emails[0]?.authUser, 'proxy', s.proxyLog.length, s.proxyLog.slice(0,3), 'conf', s.confluence.map((p:any)=>p.version.number));
await sim.stop();
