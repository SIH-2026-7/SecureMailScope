import {generateScenario, rules, scenarios} from './engine.js';

export function initialState() {
  return {page: 'Overview', scenario: 'enterprise', selected: 'enterprise',
    sessions: generateScenario(), busy: false, step: 0, logs: [],
    filter: 'All', protocol: 'All', query: '', fixes: [], capture: null};
}

function remediate(session, key) {
  if (!session.issues.includes(key)) return session;
  const next = {...session, issues: session.issues.filter(issue => issue !== key)};
  if (key === 'legacy') next.tls = 'TLS 1.2';
  if (key === 'expired' || key === 'mismatch') next.cert = 'Valid fixture';
  if (key === 'pfs') Object.assign(next, {pfs: 'Yes', cipher: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'});
  if (key === 'cleartext') Object.assign(next, {
    port: session.protocol === 'SMTP' ? 465 : session.protocol === 'IMAP' ? 993 : 995,
    tls: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', pfs: 'Yes', cert: 'Encrypted / fixture metadata',
  });
  return next;
}

export function reducer(state, action) {
  switch (action.type) {
    case 'navigate': return {...state, page: action.page, filter: 'All', protocol: 'All', query: ''};
    case 'filter': return {...state, ...action.values};
    case 'select': return state.busy ? state : {...state, selected: action.scenario};
    case 'start': return state.busy ? state : {...state, busy: true, page: 'Simulation lab', selected: action.scenario, step: 0, logs: []};
    case 'step': return {...state, step: action.step, logs: [...state.logs, action.log]};
    case 'load':
      if (!Object.hasOwn(scenarios, action.scenario)) return state;
      return {...state, scenario: action.scenario, selected: action.scenario, sessions: generateScenario(action.scenario), fixes: [], busy: false};
    case 'reset': return state.busy ? state : {...state, sessions: generateScenario(state.scenario), fixes: [], step: 0, logs: []};
    case 'capture': return {...state, capture: action.capture};
    case 'fix': {
      if (state.busy) return state;
      const keys = action.key === 'all' ? Object.keys(rules).filter(key => rules[key].weight) : [action.key];
      const applied = keys.filter(key => rules[key]?.weight && state.sessions.some(session => session.issues.includes(key)));
      return {...state, sessions: applied.reduce((sessions, key) => sessions.map(session => remediate(session, key)), state.sessions), fixes: [...new Set([...state.fixes, ...applied])]};
    }
    default: return state;
  }
}
