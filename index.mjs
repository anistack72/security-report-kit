import { createHash } from 'node:crypto';
import { clean } from './support.mjs';

export const LEVELS = ['info', 'low', 'medium', 'high', 'critical'];
function severity(value, fallback = 'medium') {
  const level = String(value ?? '').toLowerCase();
  return LEVELS.includes(level) ? level : ({ warning: 'medium', warn: 'medium', error: 'high', unknown: 'info' }[level] ?? fallback);
}
function location(file, line) {
  const normalized = clean(file).replace(/\\/g, '/');
  return { file: normalized, line: Number.isSafeInteger(line) && line > 0 ? line : null };
}
function fingerprint(source, rule, loc, component = '') {
  return createHash('sha256').update(JSON.stringify([source, rule, loc.file, loc.line, component])).digest('hex').slice(0, 24);
}
function finding(source, rule, level, loc, message, component = '') {
  const ruleId = clean(rule).slice(0, 300);
  if (!ruleId) throw new Error(`${source} finding is missing its rule identifier`);
  return { fingerprint: fingerprint(source, ruleId, loc, component), source, ruleId, severity: severity(level), location: loc, message: clean(message), ...(component ? { component: clean(component) } : {}) };
}

export function normalize(input, format = 'auto') {
  if (format === 'auto') {
    if (Array.isArray(input) && input.every(f => f && typeof f.RuleID === 'string')) format = 'gitleaks';
    else if (input && !Array.isArray(input) && Array.isArray(input.Results)) format = 'trivy';
    else if (input && !Array.isArray(input) && Array.isArray(input.results)) format = 'semgrep';
    else throw new Error('Unrecognized report schema; specify gitleaks, trivy or semgrep');
  }
  const output = [];
  if (format === 'gitleaks') {
    if (!Array.isArray(input)) throw new Error('Gitleaks report must be an array');
    // Never retain Secret, Match, Commit, Author or Email in the normalized output.
    const secrets = input.flatMap(f => [f?.Secret, f?.Match]).filter(v => typeof v === 'string' && v.length).sort((a,b) => b.length - a.length);
    const redact = value => { let text = String(value ?? ''); for (const secret of secrets) text = text.split(secret).join('[REDACTED]'); return text; };
    for (const f of input) {
      if (!f || typeof f.RuleID !== 'string') throw new Error('Malformed Gitleaks finding');
      const rule = redact(f.RuleID);
      output.push(finding('gitleaks', rule, 'high', location(redact(f.File), f.StartLine), `Potential secret detected by ${rule}. Revoke exposed credentials before removing them from history.`));
    }
  } else if (format === 'trivy') {
    if (!input || !Array.isArray(input.Results)) throw new Error('Trivy report requires Results');
    for (const target of input.Results) {
      if (!target || typeof target !== 'object') throw new Error('Malformed Trivy target');
      if (target.Vulnerabilities !== undefined && !Array.isArray(target.Vulnerabilities)) throw new Error('Malformed Trivy vulnerabilities');
      for (const v of target.Vulnerabilities ?? []) {
        if (!v || typeof v.VulnerabilityID !== 'string' || typeof v.PkgName !== 'string') throw new Error('Malformed Trivy vulnerability');
        const component = `${clean(v.PkgName)}@${clean(v.InstalledVersion)}`;
        output.push(finding('trivy', v.VulnerabilityID, v.Severity, location(target.Target, null), v.FixedVersion ? `Update ${component}; reported fixed version: ${clean(v.FixedVersion)}. Confirm compatibility and advisory details.` : `Review ${component}; no fixed version was reported.`, component));
      }
    }
  } else if (format === 'semgrep') {
    if (!input || !Array.isArray(input.results)) throw new Error('Semgrep report requires results');
    if (Array.isArray(input.errors) && input.errors.length) throw new Error('Semgrep reported analysis errors; resolve incomplete coverage before creating a baseline');
    for (const f of input.results) {
      if (!f || typeof f.check_id !== 'string') throw new Error('Malformed Semgrep finding');
      // Do not copy extra.lines, metavars or arbitrary messages containing source code.
      output.push(finding('semgrep', f.check_id, f.extra?.severity, location(f.path, f.start?.line), 'Review the rule and the referenced code location. Source snippets and metavariables are omitted.'));
    }
  } else throw new Error('format must be auto, gitleaks, trivy or semgrep');
  const unique = new Map();
  for (const f of output) {
    const prior = unique.get(f.fingerprint);
    if (!prior || LEVELS.indexOf(f.severity) > LEVELS.indexOf(prior.severity)) unique.set(f.fingerprint, f);
  }
  return [...unique.values()].sort((a,b) => LEVELS.indexOf(b.severity) - LEVELS.indexOf(a.severity) || a.fingerprint.localeCompare(b.fingerprint));
}

export function validateBaseline(input) {
  if (!input || input.schemaVersion !== 1 || !Array.isArray(input.findings)) throw new Error('Baseline must be a schemaVersion 1 Security Report Kit report');
  if (input.findings.some(f => !f || typeof f.fingerprint !== 'string' || !/^[a-f0-9]{24}$/.test(f.fingerprint) || !LEVELS.includes(f.severity))) throw new Error('Invalid baseline fingerprint or severity');
  return input.findings;
}

export function buildReport(findings, { baseline, failOn = 'high' } = {}) {
  if (!LEVELS.includes(failOn)) throw new Error('failOn must be info, low, medium, high or critical');
  const old = new Map(baseline ? validateBaseline(baseline).map(f => [f.fingerprint,f.severity]) : []);
  const current = new Set(findings.map(f => f.fingerprint));
  const escalated = findings.filter(f => old.has(f.fingerprint) && LEVELS.indexOf(f.severity) > LEVELS.indexOf(old.get(f.fingerprint)));
  const fresh = findings.filter(f => !old.has(f.fingerprint) || escalated.includes(f));
  const resolved = [...old.keys()].filter(id => !current.has(id));
  const checks = fresh.map(f => ({ id: f.ruleId, status: LEVELS.indexOf(f.severity) >= LEVELS.indexOf(failOn) ? 'fail' : 'warn', message: `${f.severity}: ${f.location.file}${f.location.line ? ':' + f.location.line : ''}. ${f.message}` }));
  if (!fresh.length) checks.push({ id: 'findings.new', status: 'pass', message: 'No new findings in the supplied report. This does not establish that the application is free of vulnerabilities.' });
  return { schemaVersion: 1, tool: 'Security Report Kit', summary: `${findings.length} unique finding(s): ${fresh.length} new or escalated, ${findings.length - fresh.length} unchanged, ${resolved.length} resolved against the supplied baseline.`, checks, findings, delta: { new: findings.filter(f=>!old.has(f.fingerprint)).map(f => f.fingerprint), escalated: escalated.map(f=>f.fingerprint), unchanged: findings.filter(f => old.has(f.fingerprint) && !escalated.includes(f)).map(f => f.fingerprint), resolved }, limitations: ['Not a scanner: results depend on the input report and its coverage.', 'Trivy adapter imports vulnerability findings only; secret and misconfiguration sections are not included.', 'Review filenames and component names before sharing a report.'] };
}
