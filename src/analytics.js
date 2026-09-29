/**
 * analytics.js — Lightweight analytics abstraction for SecureMailScope.
 *
 * Fires page_view on navigation and custom events on form submit, report
 * export, and capture upload. Ships with a console-only stub. Replace the
 * `send` function with your analytics provider (e.g., Google Analytics,
 * Plausible, PostHog, or Umami).
 *
 * Usage:
 *   import { trackPageView, trackEvent } from './analytics.js';
 *   trackPageView('Overview');
 *   trackEvent('report_export', { format: 'json' });
 */

const ANALYTICS_ENABLED = typeof window !== 'undefined' && window.location.hostname !== 'localhost';

function send(eventName, properties = {}) {
  if (!ANALYTICS_ENABLED) return;

  // ─── Google Analytics 4 (gtag) ───────────────────────────────
  // Uncomment after adding the GA4 script tag to index.html:
  //   <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
  //   <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
  //   gtag('js',new Date());gtag('config','G-XXXXXXXXXX');</script>
  //
  // if (typeof window.gtag === 'function') {
  //   window.gtag('event', eventName, properties);
  // }

  // ─── Plausible Analytics ─────────────────────────────────────
  // Uncomment after adding: <script defer data-domain="yoursite.com" src="https://plausible.io/js/script.js"></script>
  //
  // if (typeof window.plausible === 'function') {
  //   window.plausible(eventName, { props: properties });
  // }

  // ─── Console stub (development) ──────────────────────────────
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[analytics] ${eventName}`, properties);
  }
}

export function trackPageView(pageName) {
  send('page_view', { page_title: pageName, page_location: window.location.href });
}

export function trackEvent(eventName, properties = {}) {
  send(eventName, properties);
}

// Pre-built event helpers
export const trackCaptureUpload = (filename, sizeBytes) =>
  trackEvent('capture_upload', { filename, size_bytes: sizeBytes });

export const trackSimulationRun = (scenario) =>
  trackEvent('simulation_run', { scenario });

export const trackReportExport = (format) =>
  trackEvent('report_export', { format });

export const trackFormSubmit = (formName) =>
  trackEvent('form_submit', { form_name: formName });
