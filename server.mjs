import { createServer } from 'node:http';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('.', import.meta.url)));
const dataDir = resolve(root, 'data');
const stateFile = resolve(dataDir, 'relay.json');
const keyFile = resolve(dataDir, 'master.key');
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || '127.0.0.1';
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };

const initialState = {
  version: 1,
  workspace: { id: 'workspace-local', name: 'Northstar Studio', plan: 'Local' },
  workflows: [
    { id: 'wf-1', name: 'New lead → Slack alert', active: true, updated: '4 min ago', runs: 128, nodes: [{ id: 'n1', type: 'webhook', title: 'New lead received', detail: 'POST /lead-capture', x: 70, y: 174 }, { id: 'n2', type: 'if', title: 'Check lead score', detail: 'score is greater than 50', x: 326, y: 174 }, { id: 'n3', type: 'slack', title: 'Notify sales team', detail: '#new-leads', x: 590, y: 93 }, { id: 'n4', type: 'email', title: 'Send welcome email', detail: 'lead@company.com', x: 590, y: 267 }] },
    { id: 'wf-2', name: 'Daily product digest', active: true, updated: 'Yesterday', runs: 42, nodes: [{ id: 'n1', type: 'schedule', title: 'Every weekday at 9am', detail: 'Mon–Fri · 09:00', x: 75, y: 170 }, { id: 'n2', type: 'http', title: 'Fetch product updates', detail: 'GET /v1/updates', x: 350, y: 170 }, { id: 'n3', type: 'slack', title: 'Post digest', detail: '#product-updates', x: 625, y: 170 }] },
    { id: 'wf-3', name: 'Support ticket triage', active: false, updated: '2 days ago', runs: 16, nodes: [{ id: 'n1', type: 'webhook', title: 'Ticket created', detail: 'POST /support', x: 75, y: 170 }, { id: 'n2', type: 'if', title: 'Urgent?', detail: 'priority equals high', x: 350, y: 170 }, { id: 'n3', type: 'slack', title: 'Escalate to support', detail: '#support-urgent', x: 625, y: 170 }] },
    { id: 'wf-4', name: 'Invoice received → finance', active: true, updated: '5 days ago', runs: 8, nodes: [{ id: 'n1', type: 'webhook', title: 'Invoice received', detail: 'POST /invoice', x: 75, y: 170 }, { id: 'n2', type: 'http', title: 'Add to ledger', detail: 'POST /finance/invoices', x: 350, y: 170 }] }
  ],
  executions: [],
  credentials: [
    { id: 'cred-1', name: 'Sales team workspace', app: 'Slack', initial: 'S', color: '#f2edf9', ink: '#8067b0', used: 2, updated: 'Today' },
    { id: 'cred-2', name: 'Transactional email', app: 'SMTP', initial: '✉', color: '#eaf2fb', ink: '#5682bc', used: 1, updated: 'Sep 28' },
    { id: 'cred-3', name: 'Product API', app: 'HTTP Header Auth', initial: '↗', color: '#e9f3eb', ink: '#2b795d', used: 2, updated: 'Sep 26' }
  ]
};

let state;
await mkdir(dataDir, { recursive: true });
try { state = JSON.parse(await readFile(stateFile, 'utf8')); }
catch { state = structuredClone(initialState); await persist(); }
let masterKey;
try { masterKey = await readFile(keyFile); }
catch { masterKey = randomBytes(32); await writeFile(keyFile, masterKey, { flag: 'wx', mode: 0o600 }); }

async function persist() {
  const temp = `${stateFile}.${process.pid}.tmp`;
  await writeFile(temp, JSON.stringify(state, null, 2), { mode: 0o600 });
  await rename(temp, stateFile);
}
function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(body));
}
async function bodyJSON(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 1_000_000) throw new Error('Request body is too large');
  }
  return raw ? JSON.parse(raw) : {};
}
function makeId(prefix) { return `${prefix}_${randomUUID().slice(0, 8)}`; }
function encryptSecret(value) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: ciphertext.toString('hex') };
}
function decryptSecret(value) {
  const decipher = createDecipheriv('aes-256-gcm', masterKey, Buffer.from(value.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(value.tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(value.ciphertext, 'hex')), decipher.final()]).toString('utf8');
}
function publicState() {
  return { ...state, credentials: state.credentials.map(({ secret, ...credential }) => ({ ...credential, secretSet: Boolean(secret) })) };
}
function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19));
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase();
    return !/^2[0-9a-f]{3}:/i.test(normalized) || normalized.startsWith('2001:db8:') || normalized.startsWith('2002:');
  }
  return true;
}
async function publicHttpsRequest(target, method, data, token) {
  const url = new URL(target);
  const hostName = url.hostname.replace(/^\[|\]$/g, '');
  if (url.protocol !== 'https:' || url.username || url.password || hostName === 'localhost' || hostName.endsWith('.local') || hostName.endsWith('.internal')) throw new Error('Use a public HTTPS URL without embedded credentials');
  const addresses = await lookup(hostName, { all: true });
  if (!addresses.length || addresses.some(a => isPrivateAddress(a.address))) throw new Error('Private or reserved network addresses are blocked');
  const address = addresses.find(a => a.family === 4) || addresses[0];
  const headers = { 'Accept': 'application/json, text/plain, */*', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  let requestBody;
  if (data !== undefined && !['GET', 'HEAD'].includes(method)) {
    requestBody = JSON.stringify(data);
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(requestBody);
  }
  return await new Promise((resolve, reject) => {
    const req = httpsRequest({
      protocol: 'https:', hostname: hostName, port: url.port || 443, method, path: `${url.pathname}${url.search}`,
      headers, servername: net.isIP(hostName) ? undefined : hostName, timeout: 12_000,
      lookup: (_host, _options, callback) => callback(null, address.address, address.family)
    }, response => {
      let raw = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { raw += chunk; if (raw.length > 1_000_000) req.destroy(new Error('Response exceeded 1 MB')); });
      response.on('end', () => {
        let parsed = raw;
        try { parsed = JSON.parse(raw); } catch {}
        resolve({ statusCode: response.statusCode || 0, body: parsed });
      });
    });
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    if (requestBody) req.write(requestBody);
    req.end();
  });
}

async function execute(workflow, input, trigger) {
  const startedAt = new Date();
  const steps = [];
  let data = input ?? {};
  for (const node of workflow.nodes || []) {
    const began = Date.now();
    let status = 'success';
    let message = 'Step completed';
    if (node.type === 'webhook' || node.type === 'schedule') {
      message = node.type === trigger.toLowerCase() ? `Triggered by ${trigger}` : 'Trigger step passed';
    } else if (node.type === 'if') {
      let condition = node.condition;
      if (!condition) {
        const rule = String(node.detail || '').match(/^([\w.]+)\s+is greater than\s+(\d+)/i);
        const equals = String(node.detail || '').match(/^([\w.]+)\s+(?:equals|is)\s+(.+)$/i);
        condition = rule ? { path: rule[1], operator: 'greater', value: Number(rule[2]) } : equals ? { path: equals[1], operator: 'equals', value: equals[2] } : { path: 'score', operator: 'greater', value: 50 };
      }
      const actual = condition.path ? String(condition.path).split('.').reduce((v, k) => v?.[k], data) : undefined;
      const expected = condition.value;
      const passed = condition.operator === 'equals' ? String(actual) === String(expected) : condition.operator === 'exists' ? actual !== undefined : Number(actual) > Number(expected ?? 50);
      message = passed ? 'Condition matched; following the next connected step' : 'Condition did not match; step completed without a match';
    } else if (node.type === 'set') {
      data = { ...data, ...(node.fields || {}) };
      message = `Updated ${Object.keys(node.fields || {}).length} data field(s)`;
    } else if (node.type === 'wait') {
      const pause = Math.max(0, Math.min(5000, Number(node.waitMs) || 0));
      if (pause) await new Promise(resolve => setTimeout(resolve, pause));
      message = pause ? `Waited ${pause}ms` : 'Skipped: set a wait duration';
    } else if (node.type === 'http') {
      if (!node.url) { message = 'Skipped: configure a public HTTPS URL in this step first'; status = 'skipped'; }
      else {
        try {
          const method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(String(node.method || 'GET').toUpperCase()) ? String(node.method || 'GET').toUpperCase() : 'GET';
          const credential = state.credentials.find(c => c.id === node.credentialId && c.secret);
          let body = node.body;
          if (typeof body === 'string' && body.trim()) { try { body = JSON.parse(body); } catch { body = { value: body }; } }
          const result = await publicHttpsRequest(node.url, method, body, credential ? decryptSecret(credential.secret) : undefined);
          data = { ...data, httpStatus: result.statusCode, httpResponse: result.body };
          message = `HTTP ${result.statusCode}`;
          if (result.statusCode < 200 || result.statusCode >= 300) status = 'error';
        } catch (error) { status = 'error'; message = error.message || 'HTTP request failed'; }
      }
    } else if (node.type === 'slack') {
      const credential = state.credentials.find(c => c.id === node.credentialId && c.secret && /slack/i.test(c.app));
      if (!credential) { message = 'Skipped: connect a Slack credential'; status = 'skipped'; }
      else {
        try {
          const target = decryptSecret(credential.secret);
          if (new URL(target).hostname !== 'hooks.slack.com') throw new Error('Slack credential must be an incoming webhook URL');
          const result = await publicHttpsRequest(target, 'POST', { text: node.message || JSON.stringify(data) });
          message = `Slack webhook returned HTTP ${result.statusCode}`;
          if (result.statusCode < 200 || result.statusCode >= 300) status = 'error';
        } catch (error) { status = 'error'; message = error.message || 'Slack request failed'; }
      }
    } else if (node.type === 'email') {
      const credential = state.credentials.find(c => c.id === node.credentialId && c.secret && /sendgrid/i.test(c.app));
      const to = node.to || '';
      const from = process.env.RELAY_FROM_EMAIL || '';
      if (!credential || !to || !from) { message = 'Skipped: connect SendGrid, set a recipient, and configure RELAY_FROM_EMAIL'; status = 'skipped'; }
      else {
        try {
          const result = await publicHttpsRequest('https://api.sendgrid.com/v3/mail/send', 'POST', { personalizations: [{ to: [{ email: to }] }], from: { email: from }, subject: node.subject || 'Relay workflow message', content: [{ type: 'text/plain', value: node.message || JSON.stringify(data) }] }, decryptSecret(credential.secret));
          message = `SendGrid returned HTTP ${result.statusCode}`;
          if (result.statusCode < 200 || result.statusCode >= 300) status = 'error';
        } catch (error) { status = 'error'; message = error.message || 'Email request failed'; }
      }
    }
    steps.push({ nodeId: node.id, node: node.title, status, message, duration: `${Math.max(1, Date.now() - began)}ms` });
    data = { ...data, _relay: { lastNode: node.id, lastStep: status } };
  }
  const run = {
    id: makeId('run'), workflowId: workflow.id, workflow: workflow.name,
    status: steps.some(s => s.status === 'error') ? 'Failed' : steps.some(s => s.status === 'skipped') ? 'Partial' : 'Success',
    started: `Today, ${startedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`,
    duration: `${((Date.now() - startedAt.getTime()) / 1000).toFixed(2)}s`, trigger, input, steps
  };
  state.executions.unshift(run);
  state.executions = state.executions.slice(0, 200);
  workflow.runs = (workflow.runs || 0) + 1;
  workflow.updated = 'Just now';
  await persist();
  return run;
}

const scheduledRuns = new Map();
setInterval(async () => {
  const now = new Date();
  for (const workflow of state.workflows) {
    if (!workflow.active) continue;
    const schedule = workflow.nodes?.find(n => n.type === 'schedule');
    if (!schedule) continue;
    const minuteKey = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
    let matches = /every\s+minute/i.test(schedule.detail || '');
    const time = String(schedule.detail || '').match(/(\d{1,2}):(\d{2})/);
    if (time && now.getHours() === Number(time[1]) && now.getMinutes() === Number(time[2])) {
      matches = !/mon.?fri|weekday/i.test(schedule.detail || '') || (now.getDay() >= 1 && now.getDay() <= 5);
    }
    if (matches && scheduledRuns.get(workflow.id) !== minuteKey) {
      scheduledRuns.set(workflow.id, minuteKey);
      try { await execute(workflow, {}, 'Schedule'); }
      catch (error) { console.error('Scheduled workflow failed:', error); }
    }
  }
}, 15_000);

createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);
  try {
    if (pathname === '/api/health' && req.method === 'GET') return json(res, 200, { status: 'ok', storage: 'local-json', version: state.version });
    if (pathname === '/api/state' && req.method === 'GET') return json(res, 200, publicState());
    if (pathname === '/api/state' && req.method === 'PUT') {
      const next = await bodyJSON(req);
      if (!Array.isArray(next.workflows) || !Array.isArray(next.credentials) || !Array.isArray(next.executions)) return json(res, 400, { error: 'Invalid workspace state' });
      const oldCredentials = new Map(state.credentials.map(c => [c.id, c]));
      next.credentials = next.credentials.map(c => ({ ...c, secret: oldCredentials.get(c.id)?.secret }));
      state = { ...state, ...next, version: 1 };
      await persist();
      return json(res, 200, { saved: true });
    }
    if (pathname === '/api/credentials' && req.method === 'POST') {
      const payload = await bodyJSON(req);
      if (!payload.name?.trim() || !payload.app?.trim() || !payload.secret?.trim()) return json(res, 400, { error: 'Name, provider, and secret are required' });
      const credential = { id: makeId('cred'), name: payload.name.trim(), app: payload.app.trim(), secret: encryptSecret(payload.secret), used: 0, updated: 'Today' };
      state.credentials.push(credential); await persist();
      const { secret, ...safe } = credential;
      return json(res, 201, { ...safe, secretSet: true });
    }
    if (pathname === '/api/workflows' && req.method === 'POST') {
      const payload = await bodyJSON(req);
      if (!payload.name?.trim()) return json(res, 400, { error: 'Workflow name is required' });
      const nodes = Array.isArray(payload.nodes) && payload.nodes.length ? payload.nodes : [{ id: 'n1', type: 'webhook', title: 'On webhook request', detail: 'POST /new-workflow', x: 100, y: 180 }];
      if (nodes.length > 100 || nodes.some(n => !n || !/^(webhook|schedule|slack|http|email|if|set|wait)$/.test(n.type))) return json(res, 400, { error: 'Workflow contains an unsupported node' });
      const workflow = { id: makeId('wf'), name: payload.name.trim(), active: false, updated: 'Just now', runs: 0, nodes };
      state.workflows.unshift(workflow); await persist(); return json(res, 201, workflow);
    }
    const runMatch = pathname.match(/^\/api\/workflows\/([^/]+)\/run$/);
    if (runMatch && req.method === 'POST') {
      const workflow = state.workflows.find(w => w.id === runMatch[1]);
      if (!workflow) return json(res, 404, { error: 'Workflow not found' });
      const payload = await bodyJSON(req);
      const run = await execute(workflow, payload.input || {}, payload.trigger || 'Manual');
      return json(res, 200, { run, state });
    }
    const webhookMatch = pathname.match(/^\/webhooks\/([^/]+)$/);
    if (webhookMatch && req.method === 'POST') {
      const workflow = state.workflows.find(w => w.id === webhookMatch[1] && w.active && w.nodes?.some(n => n.type === 'webhook'));
      if (!workflow) return json(res, 404, { error: 'Active webhook workflow not found' });
      const payload = await bodyJSON(req);
      const run = await execute(workflow, payload, 'Webhook');
      return json(res, 202, { accepted: true, executionId: run.id, status: run.status });
    }
    const runMatchById = pathname.match(/^\/api\/executions\/([^/]+)$/);
    if (runMatchById && req.method === 'GET') {
      const run = state.executions.find(r => r.id === runMatchById[1]);
      return run ? json(res, 200, run) : json(res, 404, { error: 'Execution not found' });
    }
    if (pathname.startsWith('/api/')) return json(res, 404, { error: 'API route not found' });

    const requested = pathname === '/' ? '/index.html' : pathname;
    const file = resolve(root, `.${requested}`);
    if (file !== root && !file.startsWith(root + sep)) return res.writeHead(403).end('Forbidden');
    const content = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' });
    res.end(content);
  } catch (error) {
    if (error instanceof SyntaxError) return json(res, 400, { error: 'Invalid JSON body' });
    if (error.message === 'Request body is too large') return json(res, 413, { error: error.message });
    if (error.code === 'ENOENT') return res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
    console.error(error);
    return json(res, 500, { error: 'Internal server error' });
  }
}).listen(port, host, () => console.log(`Relay running at http://${host}:${port}`));
