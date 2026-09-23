import React from 'react';
import {createRoot} from 'react-dom/client';
import Startup from './Startup.jsx';
import './style.css';
import './design.css';

createRoot(document.getElementById('app')).render(
  <React.StrictMode><Startup /></React.StrictMode>,
);
