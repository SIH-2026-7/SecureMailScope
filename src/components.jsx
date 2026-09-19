import React, {useEffect, useRef} from 'react';
import {Icon} from './icons.jsx';

export function Badge({children, type}) {
  return <span className={`badge ${type || (typeof children === 'string' ? children.toLowerCase() : '')}`}>{children}</span>;
}

export function Button({children, icon, primary, className = '', ...props}) {
  return <button className={`${primary ? 'primary' : ''} ${className}`} {...props}>
    {icon && <><Icon name={icon} size={16} /> &nbsp; </>}{children}
  </button>;
}

export function Heading({title, subtitle, children}) {
  return <div className="heading"><div><h1>{title}</h1><p>{subtitle}</p></div>
    <div className="actions">{children}</div></div>;
}

export function Panel({title, extra, children, className = ''}) {
  return <section className={`panel ${className}`}>
    {title && <div className="panelhead"><h2>{title}</h2>{extra}</div>}{children}
  </section>;
}

export function DetailGrid({items}) {
  return <div className="detailgrid">{Object.entries(items).map(([label, value]) =>
    <div className="detailitem" key={label}><small>{label}</small><strong>{value}</strong></div>)}</div>;
}

export function Modal({title, onClose, children}) {
  const container = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    container.current.querySelector('button').focus();
    function onKey(event) {
      if (event.key === 'Escape') onClose();
      if (event.key !== 'Tab') return;
      const focusable = [...container.current.querySelectorAll('button:not(:disabled),a[href],input,select,[tabindex="0"]')];
      const first = focusable[0], last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus();}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus();}
    }
    document.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = overflow;
      document.removeEventListener('keydown', onKey);
      if (previous?.isConnected) previous.focus();
    };
  }, [onClose]);
  return <div className="modalback" onClick={event => {if (event.target === event.currentTarget) onClose();}}>
    <section className="drawer" role="dialog" aria-modal="true" aria-label={title} ref={container}>
      <div className="heading"><h1>{title}</h1><Button aria-label="Close details" onClick={onClose}><Icon name="close" /></Button></div>
      {children}
    </section>
  </div>;
}
