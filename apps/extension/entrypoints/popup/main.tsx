import React from 'react';
import ReactDOM from 'react-dom/client';

import App from '../../src/ui/App';
import type { VaultOpening } from '../../src/vault-messages';

import '../../src/ui/styles/index.css';

const popup = window as Window & { readVaultOpening?: () => Promise<VaultOpening | undefined> };
const readOpening = popup.readVaultOpening;
delete popup.readVaultOpening;

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App readOpening={readOpening} />
  </React.StrictMode>,
);
