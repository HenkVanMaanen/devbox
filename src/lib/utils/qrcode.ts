import QRCode from 'qrcode-svg';

export function generateQR(text: string): string {
  return new QRCode({ container: 'svg-viewbox', content: text, ecl: 'M', join: true, padding: 4 }).svg();
}
