import React from 'react';
import {Icon} from './icons.jsx';
import {usePageMeta} from './seo.js';

export default function NotFound({onEnter}) {
  usePageMeta('notfound');
  return <div className="landing not-found-page">
    <header className="landing-header">
      <a href="#" className="brand"><Icon name="mail" size={29}/><span>SecureMailScope<span className="brand-period">.</span></span></a>
      <div className="landing-header-actions">
        <button onClick={() => onEnter()}>Open workspace <Icon name="arrow" size={16}/></button>
      </div>
    </header>
    <main className="not-found-main">
      <div className="not-found-content">
        <div className="not-found-code">404</div>
        <h1>Page not found</h1>
        <p>The page you're looking for doesn't exist or has been moved. Here's where you can go instead:</p>
        <nav className="not-found-nav" aria-label="Suggested pages">
          <a href="#">
            <Icon name="mail" size={20}/>
            <div>
              <strong>Homepage</strong>
              <small>See what SecureMailScope does</small>
            </div>
            <Icon name="arrow" size={16}/>
          </a>
          <a href="#guide">
            <Icon name="layers" size={20}/>
            <div>
              <strong>How it works</strong>
              <small>Follow the mail, step by step</small>
            </div>
            <Icon name="arrow" size={16}/>
          </a>
          <button onClick={() => onEnter()}>
            <Icon name="shield" size={20}/>
            <div>
              <strong>Open workspace</strong>
              <small>Analyze a capture or explore the demo</small>
            </div>
            <Icon name="arrow" size={16}/>
          </button>
          <a href="#solution">
            <Icon name="activity" size={20}/>
            <div>
              <strong>The approach</strong>
              <small>Our evidence-first methodology</small>
            </div>
            <Icon name="arrow" size={16}/>
          </a>
        </nav>
        <p className="not-found-contact">Need help? Reach us at <a href="mailto:securemailscope@proton.me">securemailscope@proton.me</a></p>
      </div>
    </main>
  </div>;
}
