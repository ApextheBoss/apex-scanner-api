const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

const PATTERNS = [
  { re: /(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi, sev: 'CRITICAL', cat: 'secrets', desc: 'Hardcoded secret/API key' },
  { re: /(?:sk-|pk_live_|sk_live_|ghp_|gho_|github_pat_|xoxb-|xoxp-|AKIA)[A-Za-z0-9_\-]{10,}/g, sev: 'CRITICAL', cat: 'secrets', desc: 'Known API key pattern' },
  { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, sev: 'CRITICAL', cat: 'secrets', desc: 'Private key in code' },
  { re: /eval\s*\(/g, sev: 'HIGH', cat: 'injection', desc: 'eval() usage' },
  { re: /new\s+Function\s*\(/g, sev: 'HIGH', cat: 'injection', desc: 'Dynamic Function constructor' },
  { re: /child_process|exec\s*\(|execSync|spawn\s*\(/g, sev: 'HIGH', cat: 'injection', desc: 'Shell command execution' },
  { re: /system[_\s]?prompt\s*[:=]/gi, sev: 'HIGH', cat: 'agent', desc: 'System prompt exposed' },
  { re: /(?:OPENAI|ANTHROPIC|GOOGLE|COHERE)_API_KEY/g, sev: 'CRITICAL', cat: 'agent', desc: 'LLM API key reference' },
  { re: /tool_choice\s*[:=]\s*['"](?:auto|any|required)['"]/gi, sev: 'MEDIUM', cat: 'agent', desc: 'Unrestricted tool choice' },
  { re: /\.env(?:\.local|\.prod|\.dev)?/g, sev: 'MEDIUM', cat: 'config', desc: 'Environment file reference' },
];

function scan(code, filename) {
  const findings = [];
  for (const p of PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      findings.push({
        severity: p.sev, category: p.cat, description: p.desc,
        file: filename || 'unknown',
        line: code.substring(0, m.index).split('\n').length,
        match: m[0].substring(0, 80)
      });
    }
  }
  return findings.sort((a, b) => {
    const o = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (o[a.severity] ?? 4) - (o[b.severity] ?? 4);
  });
}

app.get('/', (req, res) => res.json({
  service: 'Apex Security Scanner', version: '1.0.0',
  author: '@ApextheBossAI',
  usage: 'POST / with {"code":"...","filename":"optional"}',
  pricing: 'Free during beta'
}));

app.post('/', (req, res) => {
  const { code, filename, files } = req.body;
  if (files && Array.isArray(files)) {
    const results = files.slice(0, 20).map(f => ({ filename: f.filename, findings: scan(f.code || '', f.filename) }));
    return res.json({ results, totalFindings: results.reduce((s, r) => s + r.findings.length, 0) });
  }
  if (!code) return res.status(400).json({ error: 'Missing "code" field' });
  const findings = scan(code, filename);
  res.json({ filename: filename || 'unknown', findings, summary: {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
  }});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('Apex Security Scanner on port ' + PORT));
