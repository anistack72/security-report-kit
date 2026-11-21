#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { normalize, buildReport } from './index.mjs';
import { options, formatReport, exitCode, clean } from './support.mjs';
async function load(file) { if ((await stat(file)).size > 25 * 1024 * 1024) throw new Error('Input exceeds the 25 MiB report limit'); return JSON.parse(await readFile(file, 'utf8')); }
try {
  const args = options({ input: { type: 'string' }, source: { type: 'string', default: 'auto' }, baseline: { type: 'string' }, 'fail-on': { type: 'string', default: 'high' } });
  if (args.help) console.log('Security Report Kit\n\nnode cli.mjs --input report.json [--source auto|gitleaks|trivy|semgrep]\n  [--baseline previous.normalized.json] [--fail-on high]\n  [--format text|json|markdown|html]\n\nReport normalization only. Secret values and source snippets are omitted.');
  else {
    if (!args.input || args.positionals.length) throw new Error('Provide --input report.json without positional arguments');
    const report = buildReport(normalize(await load(args.input), args.source), { baseline: args.baseline ? await load(args.baseline) : undefined, failOn: args['fail-on'] });
    console.log(formatReport(report, args.format)); process.exitCode = exitCode(report);
  }
} catch (error) { console.error(`Security Report Kit: ${clean(error.message)}`); process.exitCode = 2; }
