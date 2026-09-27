import React from 'react';
import {createRoot} from 'react-dom/client';
import Startup from './Startup.jsx';
import './style.css';
import './design.css';
import './motion.css';
import './landing-type.css';

createRoot(document.getElementById('app')).render(
  <React.StrictMode><Startup /></React.StrictMode>,
);
import './project-guide.css';
