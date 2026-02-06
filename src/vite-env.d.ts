/// <reference types="vite/client" />

declare const __APP_VERSION__: string;

declare module '*?html' {
  const html: string;
  export default html;
}
