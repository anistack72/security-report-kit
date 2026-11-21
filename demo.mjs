import { normalize, buildReport } from './index.mjs';import { formatReport } from './support.mjs';
const fixture=[{RuleID:'synthetic-demo-token',File:'example/config.txt',StartLine:7,Secret:'SYNTHETIC_NOT_A_REAL_SECRET',Match:'key=SYNTHETIC_NOT_A_REAL_SECRET'}];
const report=buildReport(normalize(fixture,'gitleaks'));report.summary='SYNTHETIC FIXTURE DEMO — no actual repository was scanned. '+report.summary;console.log(formatReport(report,process.argv[2]??'text'));
