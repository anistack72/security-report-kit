import test from 'node:test';
import assert from 'node:assert/strict';
import { normalize, buildReport } from './index.mjs';
const leak = { RuleID: 'example-token', File: 'config.txt', StartLine: 4, Secret: 'SYNTHETIC_SECRET_123', Match: 'key=SYNTHETIC_SECRET_123', Email: 'private@example.test', Author: 'Private Person' };
test('Gitleaks secret values, matches and personal metadata are omitted', () => {
  const json = JSON.stringify(buildReport(normalize([leak])));
  for (const secret of [leak.Secret, leak.Match, leak.Email, leak.Author]) assert.ok(!json.includes(secret));
  assert.ok(json.includes('example-token'));
});
test('known secret values are redacted even inside filenames and rule IDs', () => {
  assert.ok(!JSON.stringify(normalize([{ ...leak, File: leak.Secret, RuleID: 'prefix-' + leak.Secret }])).includes(leak.Secret));
});
test('Trivy vulnerability findings include useful package and fix information', () => {
  const findings = normalize({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-EXAMPLE', PkgName: 'demo', InstalledVersion: '1', FixedVersion: '2', Severity: 'CRITICAL' }] }] });
  assert.equal(findings[0].severity, 'critical'); assert.equal(findings[0].component, 'demo@1'); assert.match(findings[0].message, /version: 2/);
});
test('Semgrep messages, source snippets and metavariables never enter output', () => {
  const findings = normalize({ results: [{ check_id: 'test.rule', path: 'src/app.ts', start: { line: 7 }, extra: { severity: 'ERROR', message: leak.Secret, lines: leak.Secret, metavars: { x: leak.Secret } } }] });
  assert.equal(findings[0].severity, 'high'); assert.ok(!JSON.stringify(findings).includes(leak.Secret));
});
test('deduplicates deterministic findings and compares a normalized baseline', () => {
  const findings = normalize([leak, leak]); assert.equal(findings.length, 1);
  const old = buildReport(findings); const next = buildReport(findings, { baseline: old });
  assert.equal(next.delta.new.length, 0); assert.equal(next.delta.unchanged.length, 1);
  assert.equal(buildReport([], { baseline: old }).delta.resolved.length, 1);
});
test('failure thresholds apply to new findings', () => {
  const f = normalize([leak]); assert.equal(buildReport(f).checks[0].status, 'fail'); assert.equal(buildReport(f, { failOn: 'critical' }).checks[0].status, 'warn');
});
test('malformed or unrecognized schemas never become a clean report', () => {
  for (const data of [{}, { results: [null] }, { Results: [{ Vulnerabilities: {} }] }, [null]]) assert.throws(() => normalize(data));
  assert.throws(() => normalize({}, 'gitleaks')); assert.throws(() => buildReport([], { baseline: {} })); assert.throws(() => buildReport([], { failOn: 'none' }));
});
test('empty native reports are valid and terminal controls are removed', () => {
  assert.deepEqual(normalize([]), []);
  assert.ok(!normalize([{ ...leak, File: 'x\u001b[31m' }])[0].location.file.includes('\u001b'));
});
test('severity escalation cannot be hidden by an older baseline',()=>{
  const f=normalize([leak]), baseline=buildReport(f.map(x=>({...x,severity:'low'})));
  const next=buildReport(f,{baseline});assert.equal(next.delta.escalated.length,1);assert.equal(next.checks[0].status,'fail');
});
test('incomplete Semgrep runs cannot create a clean baseline',()=>{
  assert.throws(()=>normalize({results:[],errors:[{type:'ParseError'}]}),/analysis errors/);
});
