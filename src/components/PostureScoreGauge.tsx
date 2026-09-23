import React, {useEffect, useRef, useState} from 'react';

export default function PostureScoreGauge({score}: {score: number | null}) {
  const element = useRef<HTMLDivElement>(null);
  const [theme, setTheme] = useState(document.documentElement.dataset.theme);
  useEffect(() => {
    const observer = new MutationObserver(() => setTheme(document.documentElement.dataset.theme));
    observer.observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    const node = element.current;
    if (!node || score === null) return;
    let disposed = false, plot: any;
    import('plotly.js-dist-min').then(module => {
      if (disposed) return;
      plot = module.default;
      node.textContent = '';
      const colors = getComputedStyle(document.documentElement);
      plot.newPlot(node, [{type: 'indicator', mode: 'gauge+number', value: score,
        number: {suffix: ' / 100', font: {size: 30, color: colors.getPropertyValue('--ink').trim()}},
        gauge: {axis: {range: [0, 100], tickcolor: '#87929f', tickfont: {color: '#87929f'}},
          bar: {color: score >= 90 ? '#b8b8b8' : score >= 50 ? '#eeb96b' : '#fb8189'}, bgcolor: '#3c3c3c', borderwidth: 0,
          steps: [{range: [0, 50], color: '#543039'}, {range: [50, 90], color: '#51462f'}, {range: [90, 100], color: '#505050'}]}}],
        {height: 260, margin: {t: 30, b: 25, l: 40, r: 40}, paper_bgcolor: 'transparent', font: {family: 'system-ui'}},
        {responsive: true, displayModeBar: false, staticPlot: true});
    }).catch(() => {if (!disposed) node.textContent = `${score} / 100`;});
    return () => {disposed = true; if (plot) plot.purge(node);};
  }, [score, theme]);
  if (score === null) return <div className="empty">Unassessed · insufficient evidence</div>;
  return <div ref={element} role="img" aria-label={`Security posture ${score} out of 100`} style={{height: 260, overflow: 'hidden'}} />;
}
