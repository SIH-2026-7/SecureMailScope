import {test} from 'node:test';
import assert from 'node:assert/strict';
import {initialState, reducer} from '../src/state.js';
import {metrics, trace} from '../src/engine.js';
import {createReport} from '../src/reports.js';

test('remediation is immutable and preserves unknown evidence', () => {
  const before = initialState();
  const snapshot = structuredClone(before);
  const after = reducer(before, {type: 'fix', key: 'all'});
  assert.deepEqual(before, snapshot);
  assert.equal(metrics(after.sessions).score, 100);
  assert.equal(metrics(after.sessions).findings, 1);
  assert.deepEqual(after.sessions.find(s => s.id === 'SES-031').issues, ['partial']);
  assert.equal(after.sessions[0].port, 465);
  assert.ok(trace(after.sessions[0]).some(row => row[1] === 'Implicit TLS service'));
});

test('individual fixes do not remove unrelated findings; reset restores baseline', () => {
  const initial = initialState();
  const fixed = reducer(initial, {type: 'fix', key: 'legacy'});
  assert.equal(fixed.sessions[2].tls, 'TLS 1.2');
  assert.deepEqual(fixed.sessions[2].issues, ['expired', 'pfs']);
  assert.deepEqual(reducer(fixed, {type: 'reset'}), initial);
});

test('simulation starts once and loading new scenarios clears remediation', () => {
  const initial = initialState();
  const busy = reducer(initial, {type: 'start', scenario: 'downgrade'});
  assert.equal(busy.busy, true);
  assert.equal(reducer(busy, {type: 'start', scenario: 'secure'}), busy);
  assert.equal(reducer(busy, {type: 'fix', key: 'all'}), busy);
  const loaded = reducer(busy, {type: 'load', scenario: 'downgrade'});
  assert.equal(loaded.busy, false);
  assert.equal(metrics(loaded.sessions).score, 58);
  assert.equal(reducer(loaded, {type: 'load', scenario: 'invalid'}), loaded);
});

test('navigation clears filters without resetting evidence', () => {
  const initial = initialState();
  const filtered = reducer(initial, {type: 'filter', values: {query: 'smtp', filter: 'High', protocol: 'SMTP'}});
  const navigated = reducer(filtered, {type: 'navigate', page: 'Reports'});
  assert.equal(navigated.query, '');
  assert.equal(navigated.filter, 'All');
  assert.equal(navigated.sessions, initial.sessions);
});

test('exported evidence hash can be independently verified', async () => {
  const {createHash} = await import('node:crypto');
  const state = initialState();
  const report = await createReport(state.sessions, state.scenario, false);
  assert.equal(report.evidenceSha256, createHash('sha256').update(JSON.stringify(report.sessions)).digest('hex'));
  assert.equal(report.metrics.findings, 46);
  assert.equal(report.mode, 'synthetic simulation');
});
