import React, {useCallback, useEffect, useRef, useState} from 'react';
import './auth.css';

export default function AuthGate({children}) {
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');
  const generation = useRef(0);
  const check = useCallback(async () => {
    const attempt = ++generation.current;
    try {
      const response = await fetch('/api/auth/me', {cache: 'no-store'});
      if (!response.ok) throw Error('Cannot reach the sign-in service. Please retry.');
      const next = await response.json();
      if (attempt !== generation.current) return;
      setSession(next);
      setError('');
    } catch (failure) {if (attempt === generation.current) {setSession(null); setError(failure.message);}}
  }, []);
  useEffect(() => {
    check();
    const expired = () => {++generation.current; setSession({required: true, user: null});};
    const changed = event => {
      if (event.key === 'sms-signout') {expired(); check();}
    };
    const interval = setInterval(check, 60000);
    window.addEventListener('focus', check);
    window.addEventListener('sms-auth-expired', expired);
    window.addEventListener('storage', changed);
    return () => {
      clearInterval(interval);
      window.removeEventListener('focus', check);
      window.removeEventListener('sms-auth-expired', expired);
      window.removeEventListener('storage', changed);
    };
  }, [check]);
  async function signOut() {
    try {
      const response = await fetch('/api/auth/logout', {method: 'POST'});
      if (!response.ok && response.status !== 401) throw Error('Sign-out failed. Please retry.');
      ++generation.current;
      setSession({required: true, user: null});
      try {localStorage.setItem('sms-signout', String(Date.now()));} catch {}
    } catch (failure) {setError(failure.message);}
  }
  if (session && (!session.required || session.user)) return <>
    {error && <div className="auth-notice" role="alert">{error}</div>}
    {children({user: session.user, required: session.required, signOut})}
  </>;
  return <main className="auth-screen"><section className="auth-card">
    <div className="auth-brand">SecureMailScope<span>.</span></div>
    <p className="auth-eyebrow">YOUR PRIVATE ANALYSIS WORKSPACE</p>
    <h1>Sign in. Keep your captures yours.</h1>
    <p>Analyze email traffic and return to your saved reports. Your captures and analysis history are visible only to your account.</p>
    {error ? <><p role="alert">{error}</p><button onClick={check}>Retry connection</button></>
      : !session ? <p role="status">Connecting to your workspace…</p>
      : <a className="auth-google" href="/api/auth/login">Continue with Google <span aria-hidden="true">↗</span></a>}
    {new URLSearchParams(window.location.search).has('auth_error') && <p role="alert">Sign-in could not be completed. Please try again.</p>}
    <small>Your saved analyses stay with your account after you close this tab. Sign out when using a shared device.</small>
  </section></main>;
}
