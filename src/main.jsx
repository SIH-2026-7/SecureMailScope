import React from 'react';
import {createRoot} from 'react-dom/client';
import Startup from './Startup.jsx';
import AuthGate from './AuthGate.jsx';
import './style.css';
import './design.css';
import './motion.css';
import './landing-type.css';
import './launch.css';
import './project-guide.css';

createRoot(document.getElementById('app')).render(
  <React.StrictMode><AuthGate>{auth => <Startup key={auth.user?.id || 'local'} auth={auth} />}</AuthGate></React.StrictMode>,
);
