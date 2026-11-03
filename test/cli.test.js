import { test, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Database } from 'bun:sqlite';

const cli = join(import.meta.dir, '../bin/pii-guard.js');
const secret = 'syntheticPassword1234';
const token = 'sk-or-v1-' + 'abcdef12'.repeat(8);
function run(cwd, ...args) {
  const r = spawnSync('bun', [cli, ...args], { cwd, encoding: 'utf8' });
  expect(r.status).toBe(0);
  expect(r.stdout + r.stderr).not.toContain(secret);
  expect(r.stdout + r.stderr).not.toContain(token);
  return r.stdout;
}
test('export, replay and report protect values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-'));
  const bw = join(dir, 'bw.json'), known = join(dir, 'known.json');
  writeFileSync(bw, JSON.stringify([
    { type: 1, name: 'Login', login: { password: secret, totp: 'totpSecret1234', username: 'user@example.test' }, fields: [{type:1,value:'hiddenValue1234'}, {type:0,value:'textValue12345'}], notes: 'noteValue123456' },
    { type: 2, name: 'Note', notes: 'noteOther123456' },
    { type: 3, name: 'Card', card: {number:'1234567812345678',code:'123'} },
    { type: 4, name: 'Identity', identity: {ssn:'123456',passportNumber:'A1234567',licenseNumber:'1234567',phone:'123456',email:'person@example.test',address1:'123 Main Road'} },
    { type: 5, name: 'SSH', sshKey: {privateKey:'privateKey123456'} },
    { type: 1, name: 'Duplicate', login: {password: secret} }
  ]));
  run(dir, 'known','export','--bw-json',bw,'--out',known);
  const a = JSON.parse(readFileSync(known));
  expect(a.items.find(x => x.value === secret).name).toBe('login.password');
  expect(a.items.filter(x => x.value === secret)).toHaveLength(1);
  expect(a.items.some(x => x.value === '123')).toBe(false);
  expect(a.items.some(x => x.name === 'ssh.privateKey')).toBe(true);
  expect(a.items.some(x => x.name === 'identity.ssn')).toBe(true);
  expect(statSync(known).mode & 0o777).toBe(0o600);
  run(dir, 'known','export','--bw-json',bw,'--out',known);
  expect(JSON.parse(readFileSync(known)).salt).toBe(a.salt);
  const claude = join(dir,'.claude/projects/project/subagents'), codex = join(dir,'.codex/sessions'), t3 = join(dir,'.t3/userdata');
  for (const p of [claude,codex,t3]) mkdirSync(p,{recursive:true});
  writeFileSync(join(claude,'one.jsonl'), JSON.stringify({role:'user',content:`hello ${secret} and ${token}`})+'\ninvalid\n');
  writeFileSync(join(codex,'two.jsonl'), JSON.stringify({role:'assistant',content:secret})+'\n');
  const db = new Database(join(t3,'statev2.sqlite'));
  db.run('CREATE TABLE orchestration_v2_projection_turn_items (payload_json TEXT, updated_at TEXT)');
  db.run('INSERT INTO orchestration_v2_projection_turn_items VALUES (?, ?)', [JSON.stringify({role:'user',content:secret}), new Date().toISOString()]); db.close();
  run(dir,'replay','--home',dir,'--known',known,'--context');
  const md = readFileSync(join(dir,'reports',readdirSync(join(dir,'reports'))[0]),'utf8');
  expect(md).toContain('login.password'); expect(md).toContain('parse errors: 1');
  expect(md).not.toContain(secret); expect(md).not.toContain(token);
  const events = join(dir,'events.jsonl');
  writeFileSync(events, JSON.stringify({ts:new Date().toISOString(),endpoint:'/v1/messages',ua:'cli',scanMs:3,counts:{'login.password':2},new:[{name:'login.password',source:'user/text',hash:'abc'}]})+'\n');
  const output = run(dir,'report','--events',events);
  expect(output).toContain('Requests with findings: 1 / 1');
  expect(output).toContain('login.password: 2');
});
