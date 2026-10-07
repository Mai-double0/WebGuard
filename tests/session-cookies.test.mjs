// tests/session-cookies.test.mjs
// Dependency-free tests for session-cookie detection. Run: npm test
// (or: node tests/session-cookies.test.mjs)

import assert from 'node:assert/strict';
import { classifySessionCookie, analyzeSecurity } from '../analyzers/security.js';

let failed = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err.message}`);
  }
}

// ---- classifySessionCookie ----------------------------------------------

const KNOWN = ['JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId', 'connect.sid', 'myapp_session', 'sessionid'];
const NOT_SESSION = ['SIDCC', 'activitySessionId', '_ga', 'consideration', 'insider_pref'];

for (const name of KNOWN) {
  test(`${name} is a known session cookie`, () => {
    assert.equal(classifySessionCookie(name), 'known');
  });
}

for (const name of NOT_SESSION) {
  test(`${name} is not treated as a session cookie`, () => {
    assert.equal(classifySessionCookie(name), null);
  });
}

test('whole-word "session" names are only a "maybe"', () => {
  assert.equal(classifySessionCookie('session'), 'maybe');
  assert.equal(classifySessionCookie('app-session-token'), 'maybe');
});

// ---- analyzeSecurity: evidence decides the verdict flag -----------------

function page({ cookies, hasPasswordField = false }) {
  return {
    protocol: 'https:',
    domain: 'example.com',
    hasPasswordField,
    responseHeaders: {
      headers: {
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer'
      },
      cookies
    }
  };
}

const cookieFindings = result =>
  result.findings.filter(f => /cookie/i.test(f.text));

test('SIDCC without HttpOnly: no finding, no penalty, no caution', () => {
  const r = analyzeSecurity(page({ cookies: [{ name: 'SIDCC', secure: false, httpOnly: false }] }));
  assert.equal(cookieFindings(r).length, 0);
  assert.equal(r.score, 25);
  assert.ok(!r.findings.some(f => f.caution));
});

test('known session cookie without HttpOnly: caution + penalty', () => {
  const r = analyzeSecurity(page({ cookies: [{ name: 'JSESSIONID', secure: true, httpOnly: false }] }));
  assert.ok(r.findings.some(f => f.caution && /Session cookie/.test(f.text)));
  assert.equal(r.score, 23);
});

test('"maybe" cookie without a login form: informational only', () => {
  const r = analyzeSecurity(page({ cookies: [{ name: 'session', secure: true, httpOnly: false }] }));
  const found = cookieFindings(r);
  assert.equal(found.length, 1);
  assert.equal(found[0].type, 'neutral');
  assert.ok(!found[0].caution);
  assert.match(found[0].text, /may be session cookies/);
  assert.equal(r.score, 25);
});

test('"maybe" cookie with a login form: caution + penalty, honest wording', () => {
  const r = analyzeSecurity(page({
    cookies: [{ name: 'session', secure: true, httpOnly: false }],
    hasPasswordField: true
  }));
  const found = cookieFindings(r);
  assert.equal(found.length, 1);
  assert.ok(found[0].caution);
  assert.match(found[0].text, /may be session cookies/);
  assert.equal(r.score, 23);
});

test('cookie values are never read or reported', () => {
  const r = analyzeSecurity(page({
    cookies: [{ name: 'JSESSIONID', value: 'SECRET-VALUE', secure: true, httpOnly: false }]
  }));
  assert.ok(!JSON.stringify(r).includes('SECRET-VALUE'));
});

if (failed) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log('\nAll session-cookie tests passed');
