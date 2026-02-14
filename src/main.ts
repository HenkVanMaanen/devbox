import { mount } from 'svelte';

import App from './App.svelte';
import './app.css';

const target = document.querySelector('#app');
if (!target) {
  throw new Error('Could not find #app element');
}

const app = mount(App, { target });

export default app;
