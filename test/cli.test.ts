import { test, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, readdirSync, utimesSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Database } from 'bun:sqlite';
import { verhoeff } from '../src/rules.ts';
import { createDetector } from '../src/detector.ts';

const cli = join(import.meta.dir, '../bin/pii-guard.ts');
const secret = 'syntheticPassword1234';
const token = 'sk-or-v1-' + 'abcdef12'.repeat(8);
const shortPassword = 'x';
const bikePlate = 'KA03MN1234';
const formattedId = 'AB-1234/23';
function run(cwd: string, ...args: string[]) {
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
    { type: 1, name: 'Login', login: { password: secret, totp: 'totpSecret1234', username: 'user@example.test' }, fields: [{type:1,value:'hiddenValue1234'}, {type:0,value:'textValue12345'}, {type:0,name:'Bike plate',value:bikePlate}, {type:0,name:'Formatted ID',value:formattedId}], notes: 'noteValue123456' },
    { type: 2, name: 'Note', notes: 'noteOther123456' },
    { type: 3, name: 'Card', card: {number:'1234567812345678',code:'123'} },
    { type: 4, name: 'Identity', identity: {ssn:'123456',passportNumber:'A1234567',licenseNumber:'1234567',phone:'123456',email:'person@example.test',address1:'123 Main Road'} },
    { type: 5, name: 'SSH', sshKey: {privateKey:'privateKey123456'} },
    { type: 1, name: 'Duplicate', login: {password: secret} },
    { type: 1, name: 'Short', login: {password: shortPassword} }
  ]));
  run(dir, 'known','export','--bw-json',bw,'--out',known);
  const a = JSON.parse(readFileSync(known, 'utf8'));
  expect(a.items.find((x: any) => x.value === secret).name).toBe('login.password');
  expect(a.items.filter((x: any) => x.value === secret)).toHaveLength(1);
  expect(a.items.some((x: any) => x.value === '123')).toBe(false);
  expect(a.items.some((x: any) => x.name === 'ssh.privateKey')).toBe(true);
  expect(a.items.some((x: any) => x.name === 'identity.ssn')).toBe(true);
  expect(a.items.some((x: any) => x.value === shortPassword && x.category === 'secret')).toBe(true);
  expect(a.items.some((x: any) => x.value === bikePlate && x.category === 'id')).toBe(true);
  expect(a.items.some((x: any) => x.value === formattedId && x.category === 'id')).toBe(true);
  expect(statSync(known).mode & 0o777).toBe(0o600);
  run(dir, 'known','export','--bw-json',bw,'--out',known);
  expect(JSON.parse(readFileSync(known, 'utf8')).salt).toBe(a.salt);
  const claude = join(dir,'.claude/projects/project/subagents'), codex = join(dir,'.codex/sessions'), t3 = join(dir,'.t3/userdata');
  for (const p of [claude,codex,t3]) mkdirSync(p,{recursive:true});
  writeFileSync(join(claude,'one.jsonl'), JSON.stringify({role:'user',content:`hello ${secret} and ${token}`})+'\ninvalid\n');
  writeFileSync(join(codex,'two.jsonl'), JSON.stringify({role:'assistant',content:secret})+'\n');
  const db = new Database(join(t3,'statev2.sqlite'));
  db.run('CREATE TABLE orchestration_v2_projection_turn_items (payload_json TEXT, updated_at TEXT)');
  db.run('INSERT INTO orchestration_v2_projection_turn_items VALUES (?, ?)', [JSON.stringify({role:'user',content:secret}), new Date().toISOString()]); db.close();
  const replay = spawnSync('bun', [cli,'replay','--home',dir,'--known',known,'--context'], { cwd: dir, encoding: 'utf8' });
  expect(replay.status).toBe(2);
  expect(replay.stdout).toMatch(/Report: .*reports\/replay-\d{8}-\d{6}-[a-f0-9]{12}\.md/);
  expect(replay.stdout + replay.stderr).not.toContain(secret);
  expect(replay.stdout + replay.stderr).not.toContain(token);
  const md = readFileSync(join(dir,'reports',readdirSync(join(dir,'reports'))[0]),'utf8');
  expect(md).toContain('login.password'); expect(md).toContain('parse errors: 1');
  expect(md).not.toContain(secret); expect(md).not.toContain(token);
  const events = join(dir,'events.jsonl');
  writeFileSync(events, JSON.stringify({ts:new Date().toISOString(),endpoint:'/v1/messages',ua:'cli',scanMs:3,counts:{'login.password':2},new:[{name:'login.password',source:'user/text',hash:'abc'}]})+'\n');
  const output = run(dir,'report','--home',dir,'--events',events);
  expect(output).toContain('Requests with findings: 1 / 1');
  expect(output).toContain('login.password: 2');
});

test('replay filters rows by timestamp and reports skipped and undated rows', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-since-'));
  const claude = join(dir,'.claude/projects/p'), codex = join(dir,'.codex/sessions');
  mkdirSync(claude,{recursive:true}); mkdirSync(codex,{recursive:true});
  const claudeFile = join(claude,'old-file.jsonl');
  writeFileSync(claudeFile, [
    JSON.stringify({timestamp:'2026-06-01T00:00:00Z',content:token}),
    JSON.stringify({ts:'2026-05-31T23:59:59Z',content:token}),
    JSON.stringify({createdAt:'bad-date',content:token}),
    JSON.stringify({content:token}),
    'invalid json'
  ].join('\n')+'\n');
  const old = new Date('2020-01-01T00:00:00Z'); utimesSync(claudeFile, old, old);
  writeFileSync(join(codex,'old-file.jsonl'), [
    JSON.stringify({ts:'2026-06-02T00:00:00Z',content:token}),
    JSON.stringify({createdAt:'2026-06-01T00:00:00Z',content:token})
  ].join('\n')+'\n');
  const stdin = [
    JSON.stringify({timestamp:'2026-05-31T23:59:59Z',content:token}),
    JSON.stringify({createdAt:'2026-06-01T00:00:00Z',content:token}),
    JSON.stringify({content:token})
  ].join('\n')+'\n';
  const r = spawnSync('bun', [cli,'replay','--home',dir,'--source','claude,codex','--since','2026-06-01','--stdin','--label','remote'], { cwd: dir, encoding: 'utf8', input: stdin });
  expect(r.status).toBe(2);
  expect(r.stdout).toContain('Replay: 3 sources, 4 rows');
  const reportName = r.stdout.match(/Report: .*reports\/(replay-[^\s]+\.md)/)?.[1];
  expect(reportName).toBeDefined();
  const md = readFileSync(join(dir,'reports',reportName!), 'utf8');
  expect(md).toContain('Files: 1; rows: 1; skipped by --since: 1; undated: 3;');
  expect(md).toContain('Files: 1; rows: 2; skipped by --since: 0; undated: 0;');
  expect(md).toContain('Files: 1; rows: 1; skipped by --since: 1; undated: 1;');
  expect(md).toContain('parse errors: 1');
  expect(statSync(join(dir,'reports',reportName!)).mode & 0o777).toBe(0o600);
});

test('report loads known values before printing event metadata labels', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-label-'));
  const knownDir = join(dir,'.config/pii-guard'), events = join(dir,'events.jsonl');
  mkdirSync(knownDir,{recursive:true});
  const known = join(knownDir,'known.json');
  const privateValue = `${'P'.repeat(190)}|LongSecret123`;
  writeFileSync(known, JSON.stringify({version:1,salt:'a'.repeat(64),items:[{name:'account.secret',value:privateValue,category:'secret'}]}));
  writeFileSync(events, JSON.stringify({ts:new Date().toISOString(),ua:`${privateValue}\n|browser`})+'\n');
  const output = run(dir,'report','--home',dir,'--events',events);
  expect(output).not.toContain(privateValue);
  expect(output).not.toContain('P'.repeat(10));
  expect(output).toContain('User agents: [V]__browser: 1');
});

test('explicit missing and malformed known lists fail without printing values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-known-'));
  const events = join(dir,'events.jsonl'), known = join(dir,'known.json');
  writeFileSync(events, '');
  const missing = spawnSync('bun', [cli,'report','--home',dir,'--known',known,'--events',events], { cwd: dir, encoding: 'utf8' });
  expect(missing.status).not.toBe(0);
  expect(missing.stdout + missing.stderr).not.toContain(known);
  const privateValue = 'MalformedKnownSecret123';
  writeFileSync(known, JSON.stringify({version:1,salt:'b'.repeat(64),items:[{name:'',value:privateValue,category:'secret'}]}));
  const malformed = spawnSync('bun', [cli,'report','--home',dir,'--known',known,'--events',events], { cwd: dir, encoding: 'utf8' });
  expect(malformed.status).not.toBe(0);
  expect(malformed.stdout + malformed.stderr).not.toContain(privateValue);
  expect(malformed.stdout + malformed.stderr).toContain('Command failed; check input files and options');
});

test('replay report names stay unique and context masks Unicode text', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-context-'));
  const sessions = join(dir,'.claude/projects/p'); mkdirSync(sessions,{recursive:true});
  writeFileSync(join(sessions,'a.jsonl'), JSON.stringify({role:'user',content:`नमस्ते秘密 ${token} 世界`})+'\n');
  const first = run(dir,'replay','--home',dir,'--source','claude','--context');
  const second = run(dir,'replay','--home',dir,'--source','claude','--context');
  expect(first).toMatch(/replay-\d{8}-\d{6}-[a-f0-9]{12}\.md/);
  expect(second).toMatch(/replay-\d{8}-\d{6}-[a-f0-9]{12}\.md/);
  const names = readdirSync(join(dir,'reports'));
  expect(names).toHaveLength(2);
  const md = readFileSync(join(dir,'reports',names[0]),'utf8') + readFileSync(join(dir,'reports',names[1]),'utf8');
  expect(md).not.toContain('नमस्ते'); expect(md).not.toContain('秘密'); expect(md).not.toContain('世界');
  expect(md).toMatch(/x{3,}/);
  expect(names[0]).not.toBe(names[1]);
});
test('stdin replay scans only stdin', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-'));
  mkdirSync(join(dir,'.claude/projects/p'),{recursive:true});
  writeFileSync(join(dir,'.claude/projects/p/a.jsonl'), JSON.stringify({role:'user',content:token})+'\n');
  const r = spawnSync('bun', [cli,'replay','--stdin','--label','remote','--home',dir], { cwd: dir, encoding: 'utf8', input: JSON.stringify({role:'user',content:token})+'\n' });
  expect(r.status).toBe(0);
  expect(r.stdout).toContain('Replay: 1 sources');
  expect(r.stdout + r.stderr).not.toContain(token);
});

test('metadata masks embedded literal IDs and stats rows are not request events', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-'));
  const known = join(dir, 'known.json'), events = join(dir, 'events.jsonl');
  writeFileSync(known, JSON.stringify({version:1,salt:'a'.repeat(64),items:[{name:'plate',value:'KA01AB1234',category:'id'}]}));
  writeFileSync(events, [
    {ts:new Date().toISOString(),endpoint:'/v1/prefixKA01AB1234suffix',counts:{plate:1}},
    {ts:new Date().toISOString(),type:'stats',requests:100,withFindings:1},
  ].map(x=>JSON.stringify(x)).join('\n'));
  const output = run(dir,'report','--known',known,'--events',events);
  expect(output).not.toContain('KA01AB1234');
  expect(output).toContain('Requests with findings: 1 / 1 recorded events');
  expect(output).toContain('Completed stats windows: 1 / 100 requests');
});

test('one unscannable row leaves a partial report and preserves valid neighbors', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-'));
  let deep: any = 'value'; for(let i=0;i<102;i++) deep={nested:deep};
  const input=[{text:token},deep,{text:token}].map(x=>JSON.stringify(x)).join('\n');
  const r=spawnSync('bun',[cli,'replay','--home',dir,'--stdin','--label','synthetic'],{cwd:dir,encoding:'utf8',input});
  expect(r.status).toBe(2);
  expect(r.stdout+r.stderr).not.toContain(token);
  const report=readFileSync(join(dir,'reports',readdirSync(join(dir,'reports'))[0]),'utf8');
  expect(report).toContain('rows: 2');
  expect(report).toContain('scan errors: 1');
});

test('note exports include labeled Aadhaar, PAN, and bike registration', () => {
  const dir=mkdtempSync(join(tmpdir(),'pii-cli-'));
  const aadhaar=Array.from({length:10},(_,i)=>`23456789012${i}`).find(verhoeff)!;
  const input=join(dir,'notes.txt'),out=join(dir,'known.json');
  writeFileSync(input,`Aadhaar: ${aadhaar}\nPAN: ABCPE1234F\nRegistration: KA01AB1234\n`);
  const output=run(dir,'known','export','--from-text',input,'--out',out);
  const known=JSON.parse(readFileSync(out,'utf8'));
  for(const value of [aadhaar,'ABCPE1234F','KA01AB1234']) {
    expect(known.items.some((x:any)=>x.value===value&&x.category==='id')).toBe(true);
    expect(output).not.toContain(value);
  }
  const vault=join(dir,'vault.json');
  writeFileSync(vault,JSON.stringify([{type:2,name:'Aadhaar',notes:aadhaar},{type:2,name:'PAN',notes:'ABCPE1234F'}]));
  run(dir,'known','export','--bw-json',vault,'--out',out);
  expect(JSON.parse(readFileSync(out,'utf8')).items.map((x:any)=>x.value).sort()).toEqual([aadhaar,'ABCPE1234F'].sort());
});

test('replay honors an explicit output path without overwriting it', () => {
  const dir=mkdtempSync(join(tmpdir(),'pii-cli-')),out=join(dir,'private','result.md');
  const args=[cli,'replay','--home',dir,'--stdin','--label','synthetic','--out',out];
  expect(spawnSync('bun',args,{cwd:dir,encoding:'utf8',input:'{"text":"safe"}\n'}).status).toBe(0);
  const before=readFileSync(out,'utf8');
  expect(statSync(out).mode&0o777).toBe(0o600);
  expect(spawnSync('bun',args,{cwd:dir,encoding:'utf8',input:'{"text":"different"}\n'}).status).toBe(1);
  expect(readFileSync(out,'utf8')).toBe(before);
});

test('known-value totals count distinct values even when vault labels collide', () => {
  const dir=mkdtempSync(join(tmpdir(),'pii-cli-')),known=join(dir,'known.json');
  const values=['synthetic-first-secret','synthetic-second-secret'];
  writeFileSync(known,JSON.stringify({version:1,salt:'a'.repeat(64),items:values.map(value=>({name:'same.password',value,category:'secret'}))}));
  const r=spawnSync('bun',[cli,'replay','--home',dir,'--known',known,'--stdin','--label','synthetic'],{cwd:dir,encoding:'utf8',input:JSON.stringify({text:values.join(' ')})});
  expect(r.status).toBe(0);
  expect(r.stdout).toContain('2/2 known values');
  for(const value of values) expect(r.stdout+r.stderr).not.toContain(value);
});

test('known check exercises every configured value without printing it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-check-')), known = join(dir, 'known.json');
  const items = [secret, '4111 1111 1111 1111', '4111111111111111'].map(value => ({ name: 'private', value, category: 'secret' }));
  writeFileSync(known, JSON.stringify({ version: 1, salt: 'a'.repeat(64), items }));
  const output = run(dir, 'known', 'check', '--known', known);
  expect(output).toContain('12/12 passed; 3 distinct configured values; 0 failures');
  for (const item of items) expect(output).not.toContain(item.value);
  writeFileSync(known, JSON.stringify({ version: 1, salt: 'a'.repeat(64), items: [] }));
  expect(spawnSync('bun', [cli, 'known', 'check', '--known', known], { encoding: 'utf8' }).status).toBe(2);
});

test('ID context precedes token heuristics in fields and notes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-ids-')), vault = join(dir, 'vault.json'), known = join(dir, 'known.json');
  const value = 'KA0120201234567';
  for (const item of [
    { type: 1, name: 'Login', fields: [{ type: 0, name: 'Driving license', value }] },
    { type: 2, name: 'Driving license', notes: value },
  ]) {
    writeFileSync(vault, JSON.stringify([item]));
    run(dir, 'known', 'export', '--bw-json', vault, '--out', known);
    const k = JSON.parse(readFileSync(known, 'utf8'));
    expect(k.items.find((x: any) => x.value === value).category).toBe('id');
    expect(createDetector({ known: k.items, rules: [] }).scan('KA01 2020 1234567')).toHaveLength(1);
  }
});

test('OCR replay reports incomplete file and opaque coverage with exit 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-coverage-')), out = join(dir, 'report.md');
  const input = JSON.stringify({ input: [{ type: 'file', file: { file_id: 'file-synthetic' } }, { type: 'redacted_thinking', data: 'U1lOVEhFVElD' }] });
  const r = spawnSync('bun', [cli, 'replay', '--home', dir, '--stdin', '--label', 'synthetic', '--ocr', '--out', out], { encoding: 'utf8', input });
  expect(r.status).toBe(2);
  const report = readFileSync(out, 'utf8');
  expect(report).toContain('unscanned file/audio blocks: 1');
  expect(report).toContain('opaque signed/encrypted fields: 1');
});

test('OCR mode CLI validation and doctor availability', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pii-cli-doctor-'));
  try {
    writeFileSync(join(dir, 'tesseract'), '#!/bin/sh\nif [ "$1" = "--list-langs" ]; then printf "List of available languages (1):\\neng\\n"; else echo tesseract; fi\n', { mode: 0o700 });
    const env = { ...process.env, PII_GUARD_OCR_BIN_DIR: dir };
    expect(spawnSync('bun', [cli, 'replay-images', '--folder', dir, '--ocr-mode', 'bogus'], { env }).status).toBe(1);
    expect(spawnSync('bun', [cli, 'doctor', '--ocr-mode', 'enhanced'], { env }).status).toBe(2);
    expect(spawnSync('bun', [cli, 'doctor', '--ocr-mode', 'basic'], { env }).status).toBe(0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
