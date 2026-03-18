const http = require('http');

const PATTERNS = [
  { re: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"]{8,}['"]/gi, sev: 'CRITICAL', desc: 'Hardcoded secret' },
  { re: /(?:sk-|ghp_|AKIA)[A-Za-z0-9_\-]{10,}/g, sev: 'CRITICAL', desc: 'Known API key pattern' },
  { re: /eval\s*\(/g, sev: 'HIGH', desc: 'eval() usage' },
  { re: /child_process/g, sev: 'HIGH', desc: 'Shell execution' },
  { re: /system[_\s]?prompt\s*[:=]/gi, sev: 'HIGH', desc: 'System prompt exposed' },
];

function scan(code) {
  const findings = [];
  for (const p of PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      findings.push({ severity: p.sev, description: p.desc, line: code.substring(0, m.index).split('\n').length, match: m[0].substring(0, 80) });
    }
  }
  return findings;
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }
  if (req.method === 'GET') { res.end(JSON.stringify({service:'Apex Security Scanner',version:'1.0.0'})); return; }
  if (req.method !== 'POST') { res.writeHead(405); res.end('{}'); return; }
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    try {
      const { code } = JSON.parse(body);
      if (!code) { res.writeHead(400); res.end(JSON.stringify({error:'missing code'})); return; }
      res.end(JSON.stringify({ findings: scan(code) }));
    } catch(e) { res.writeHead(400); res.end(JSON.stringify({error:'invalid json'})); }
  });
});

const PORT = process.env.PORT || process.env.VIBEKIT_PORT || 4003;
server.listen(PORT, '0.0.0.0', () => console.log('listening on ' + PORT));
