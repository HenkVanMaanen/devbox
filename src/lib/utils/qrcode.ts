import { renderSVG } from 'uqr';

export function generateQR(text: string): string {
  return renderSVG(text, { border: 4, ecc: 'M' });
}
