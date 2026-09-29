import React from 'react';
import {Icon} from './icons.jsx';

export default function StickyMobileCTA({onClick, label = 'Examine a capture', icon = 'arrow'}) {
  return <div className="sticky-mobile-cta" role="complementary" aria-label="Quick action">
    <button onClick={onClick}>
      <span>{label}</span>
      <Icon name={icon} size={18}/>
    </button>
  </div>;
}
