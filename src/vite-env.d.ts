/// <reference types="vite/client" />

declare const __APP_VERSION__: string;

declare module '*?html' {
  const html: string;
  export default html;
}

declare module 'qrcode-svg' {
  interface QRCodeOptions {
    background?: string;
    color?: string;
    container?: 'g' | 'none' | 'svg' | 'svg-viewbox';
    content: string;
    ecl?: 'H' | 'L' | 'M' | 'Q';
    height?: number;
    join?: boolean;
    padding?: number;
    width?: number;
    xmlDeclaration?: boolean;
  }
  class QRCode {
    constructor(options: QRCodeOptions | string);
    svg(): string;
  }
  export default QRCode;
}
