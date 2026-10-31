'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const zxcvbn = require('zxcvbn');

const PORT = process.env.PORT || 3000;
const MAX_LEN = 128;
const STEP_DELAY_MS = 120;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-me';
const AUDIT_FILE = path.join(__dirname, 'audit.log');

const COMMON = new Set([
  'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd', 'passcode',
  '123456', '1234567', '12345678', '123456789', '1234567890', '111111', '000000',
  'qwerty', 'qwerty123', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
  'abc123', 'abcdef', 'abcd1234', 'letmein', 'welcome', 'welcome1', 'admin', 'admin123',
  'login', 'master', 'hello', 'freedom', 'iloveyou', 'sunshine', 'princess', 'dragon',
  'secret', 'changeme', 'default', 'guest', 'test', 'testing', 'user', 'demo'
]);

try {
  const commonFile = path.join(__dirname, 'common-passwords.txt');
  if (fs.existsSync(commonFile)) {
    fs.readFileSync(commonFile, 'utf8').split(/\r?\n/u).forEach((line) => {
      const word = line.trim().toLower();
      if (word && !word.startsWith('#')) COMMON.add(word);
    });
  }
} catch (_) {}

const LEET = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' };

function isCommon(pw) {
  const lower = pw.toLowerCase();
  const leet = lower.replace(/[013457@$!]/g, (c) => LEET[c] || c);
  const lettersOnly = leet.replace(/[^a-z]/g, '');
  const candidates = [lower, leet, lower.replace(/[\d\W_]+$/u, ''), leet.replace(/[\d\W_]+$/u, '')];
  if (lettersOnly.length >= 4) candidates.push(lettersOnly);
  if (candidates.some((c) => COMMON.has(c))) return true;
  for (const word of COMMON) {
    if (word.length >= 6 && lower.length <= word.length + 6 && (lower.includes(word) || leet.includes(word))) return true;
  }
  return false;
}

function hasSequence(password) {
  const lower = password.toLowerCase();
  const patterns = [
    'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba',
    '01234567890123456789', '98765432109876543210',
    'qwertyuiop', 'poiuytrewq', 'asdfghjkl', 'lkjhgfdsa', 'zxcvbnm', 'mnbvcxz'
  ];
  for (let i = 0; i < lower.length - 2; i++) {
    const slice = lower.slice(i, i + 4);
    if (patterns.some((pattern) => pattern.includes(slice))) return true;
  }
  return /(?:abc|bcd|cde|def|123|234|345|456|567|678|789|890)/u.test(lower);
}

function hasPersonalInfo(password, username, email) {
  const lower = password.toLowerCase();
  for (const value of [username, email]) {
    if (typeof value !== 'string') continue;
    const clean = value.trim().toLowerCase();
    if (clean.length >= 3 && lower.includes(clean)) return true;
    if (clean.includes('@')) {
      const local = clean.split('@')[0];
      if (local.length >= 3 && lower.includes(local)) return true;
    }
  }
  return false;
}

let policy = {
  minLength: 8,
  required: ['length', 'uppercase', 'lowercase', 'number', 'special', 'common', 'repeats', 'spaces', 'sequence', 'personal', 'breach']
};

function makeRules(currentPolicy) {
  const length = Number(currentPolicy.minLength) || 8;
  const definitions = [
    { id: 'length', name: 'Minimum length', test: (p) => p.length >= length, missing: `too short (minimum ${length} characters)`, fix: `Use at least ${length} characters. 12 or more is even better.` },
    { id: 'uppercase', name: 'Uppercase letter', test: (p) => /\p{Lu}/u.test(p), missing: 'missing uppercase letter', fix: 'Add at least one uppercase letter (A-Z).' },
    { id: 'lowercase', name: 'Lowercase letter', test: (p) => /\p{Ll}/u.test(p), missing: 'missing lowercase letter', fix: 'Add at least one lowercase letter (a-z).' },
    { id: 'number', name: 'Number', test: (p) => /\p{Nd}/u.test(p), missing: 'missing number', fix: 'Add at least one digit (0-9).' },
    { id: 'special', name: 'Special character', test: (p) => /[^\p{L}\p{N}\s]/u.test(p), missing: 'missing special character', fix: 'Add a symbol such as ! @ # $ % ^ & *.' },
    { id: 'common', name: 'Not a common password', test: (p) => !isCommon(p), missing: 'matches a common or weak password', fix: 'Avoid common words. Try a passphrase of unrelated words.' },
    { id: 'repeats', name: 'No repeated characters', test: (p) => !/(.)\1{2,}/su.test(p), missing: 'contains repeated characters', fix: 'Avoid three or more identical characters in a row.' },
    { id: 'spaces', name: 'No spaces', test: (p) => !/\s/u.test(p), missing: 'contains spaces', fix: 'Remove spaces or use - or _ separators.' },
    { id: 'sequence', name: 'No sequences or keyboard patterns', test: (p) => !hasSequence(p), missing: 'contains a sequence or keyboard pattern', fix: 'Avoid sequences such as 1234, abcd, qwerty, or asdf.' },
    { id: 'personal', name: 'No username or email', test: (p) => !hasPersonalInfo(p, '', ''), missing: 'contains personal information', fix: 'Do not use your username or email as part of the password.' },
    { id: 'breach', name: 'Not found in known breaches', test: (p) => true, missing: 'appears in a known breach', fix: 'Choose a password that has not appeared in a known breach.' }
  ];
  return definitions.filter((rule) => currentPolicy.required.includes(rule.id));
}

function estimateEntropy(password) {
  const pool = ((/\p{Ll}/u.test(password) ? 26 : 0) + (/\p{Lu}/u.test(password) ? 26 : 0) +
    (/\p{Nd}/u.test(password) ? 10 : 0) + (/[^ \p{L}\p{N}]/u.test(password) ? 32 : 0));
  return { bits: pool ? Math.round(password.length * Math.log2(pool)) : 0 };
}

function estimateCrackTime(password) {
  const entropy = estimateEntropy(password).bits;
  const seconds = Math.pow(2, entropy) / 1e10;
  if (!Number.isFinite(seconds)) return 'Centuries';
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
  return 'Centuries';
}

function computeScore(password, results) {
  const result = zxcvbn(password || '', []);
  let score = Math.max(0, Math.min(100, Math.round(result.score * 25)));
  const failed = results.filter((item) => !item.pass);
  if (failed.length) score = Math.min(score, 69);
  if (failed.some((item) => item.id === 'common' || item.id === 'breach')) score = Math.min(score, 20);
  return password ? score : 0;
}

async function checkBreached(password) {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true', 'User-Agent': 'Password-Validator-Security-Monitor' },
      signal: controller.signal
    });
    if (!response.ok) return null;
    const text = await response.text();
    const match = text.split(/\r?\n/u).find((line) => line.startsWith(suffix));
    return match ? Number(match.split(':')[1]) : 0;
  } catch (_) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function generatePassword(length = 20) {
  length = Math.max(12, Math.min(MAX_LEN, Number(length) || 20));
  const groups = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*_-+='];
  const all = groups.join('');
  const chars = groups.map((group) => group[crypto.randomInt(group.length)]);
  while (chars.length < length) chars.push(all[crypto.randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

function labelFor(score) {
  if (score < 25) return 'Very weak';
  if (score < 50) return 'Weak';
  if (score < 70) return 'Fair';
  if (score < 90) return 'Strong';
  return 'Excellent';
}

const stats = { total: 0, accepted: 0, rejected: 0, failed: new Map() };
function recordAudit(event) {
  fs.appendFile(AUDIT_FILE, JSON.stringify(event) + '\n', () => {});
}

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
  next();
});

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 240,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const line = `[${new Date().toISOString()}] [WARN] Rate limit triggered id=${crypto.randomBytes(4).toString('hex')}`;
    console.warn(line);
    recordAudit({ ts: new Date().toISOString(), type: 'rate_limit', level: 'WARN' });
    res.status(429).json({ error: 'Too many requests. Slow down.' });
  }
});

app.use(express.json({ limit: '4kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/rules', (req, res) => {
  res.json(makeRules(policy).map(({ id, name }) => ({ id, name })));
});
app.get('/api/policy', (req, res) => res.json(policy));
app.post('/api/policy', (req, res) => {
  const allowed = new Set(['length', 'uppercase', 'lowercase', 'number', 'special', 'common', 'repeats', 'spaces', 'sequence', 'personal', 'breach']);
  const minLength = Number(req.body?.minLength);
  const required = Array.isArray(req.body?.required) ? req.body.required.filter((id) => allowed.has(id)) : policy.required;
  if (!Number.isInteger(minLength) || minLength < 4 || minLength > MAX_LEN) {
    return res.status(400).json({ error: 'minLength must be an integer from 4 to 128.' });
  }
  policy = { minLength, required };
  res.json(policy);
});

app.get('/api/stats', (req, res) => {
  res.json({
    ...stats,
    failed: Object.fromEntries([...stats.failed.entries()].sort((a, b) => b[1] - a[1]))
  });
});

app.post('/api/generate', (req, res) => {
  const password = generatePassword(req.body?.length);
  res.json({ password });
});

app.get('/api/audit', (req, res) => {
  if (req.headers.authorization !== `Bearer ${ADMIN_TOKEN}`) return res.status(401).json({ error: 'Unauthorized.' });
  let lines = [];
  try {
    lines = fs.readFileSync(AUDIT_FILE, 'utf8').trim().split(/\r?\n/u).filter(Boolean).slice(-200).map((line) => {
      try { return JSON.parse(line); } catch (_) { return null; }
    }).filter(Boolean);
  } catch (_) {}
  res.json(lines);
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

app.post('/api/validate', limiter, async (req, res) => {
  const password = req.body?.password;
  const username = req.body?.username;
  const email = req.body?.email;
  if (typeof password !== 'string') return res.status(400).json({ error: 'Field "password" must be a string.' });
  if (password.length > MAX_LEN) return res.status(413).json({ error: `Password too long (max ${MAX_LEN} characters).` });

  const reqId = crypto.randomBytes(3).toString('hex');
  let closed = false;
  res.on('close', () => { closed = true; });
  res.status(200);
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  const send = (obj) => { if (!closed) res.write(JSON.stringify({ ts: new Date().toISOString(), ...obj }) + '\n'); };
  const log = (level, message) => send({ type: 'log', level, message });

  log('INFO', 'Password received');
  await sleep(STEP_DELAY_MS);
  const rules = makeRules(policy);
  log('INFO', `Running ${rules.length} validation rules`);

  const results = [];
  let breachCount = null;
  for (const rule of rules) {
    if (closed) return;
    await sleep(STEP_DELAY_MS);
    let pass;
    if (rule.id === 'personal') pass = !hasPersonalInfo(password, username, email);
    else if (rule.id === 'breach') {
      breachCount = await checkBreached(password);
      pass = breachCount === null ? true : breachCount === 0;
    } else pass = rule.test(password);
    results.push({ id: rule.id, name: rule.name, pass, missing: rule.missing, fix: rule.fix });
    send({ type: 'check', id: rule.id, name: rule.name, pass });
    log('CHECK', `${rule.name}: ${pass ? 'PASS' : 'FAIL'}`);
  }
  if (closed) return;

  await sleep(STEP_DELAY_MS);
  const failed = results.filter((item) => !item.pass);
  const accepted = failed.length === 0;
  const score = computeScore(password, results);
  const label = labelFor(score);
  const entropy = estimateEntropy(password);
  const crackTime = estimateCrackTime(password);
  const strength = zxcvbn(password, [username, email].filter((value) => typeof value === 'string'));

  stats.total++;
  if (accepted) stats.accepted++; else stats.rejected++;
  failed.forEach((item) => stats.failed.set(item.id, (stats.failed.get(item.id) || 0) + 1));

  log('INFO', `Strength score: ${score}/100 (${label})`);
  log('INFO', `Estimated entropy: ${entropy.bits} bits; crack time: ${crackTime}`);
  if (breachCount !== null && breachCount > 0) log('WARN', `Password appeared in at least ${breachCount} breach record(s)`);
  log('RESULT', accepted ? `Password accepted — all ${rules.length} checks passed` : `Password rejected — ${failed.map((item) => item.missing).join('; ')}`);

  send({
    type: 'summary',
    status: accepted ? 'ACCEPTED' : 'REJECTED',
    score,
    label,
    passed: results.length - failed.length,
    total: results.length,
    failed: failed.map((item) => item.id),
    suggestions: failed.map((item) => item.fix),
    entropy: entropy.bits,
    crackTime,
    zxcvbnScore: strength.score
  });
  res.end();

  recordAudit({ ts: new Date().toISOString(), type: 'validation', id: reqId, status: accepted ? 'ACCEPTED' : 'REJECTED', score, failed: failed.map((item) => item.id) });
  console.log(`[${new Date().toISOString()}] validate id=${reqId} status=${accepted ? 'ACCEPTED' : 'REJECTED'} score=${score} failed=${failed.map((item) => item.id).join(',') || 'none'}`);
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status && err.status < 500 ? err.status : 400;
  res.status(status).json({ error: 'Invalid request.' });
});

app.listen(PORT, () => {
  console.log(`Password Validator & Security Monitor running at http://localhost:${PORT}`);
});
