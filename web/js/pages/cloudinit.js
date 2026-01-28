// Cloud-init preview page renderer

import { UI, cn, escapeHtml } from '../ui.js';
import * as storage from '../storage.js';
import { generate as generateCloudInit } from '../cloudinit.js';

export function renderCloudInit() {
    const token = storage.getHetznerToken();

    if (!token) {
        return `
            <div class="${UI.card}">
                <div class="${UI.cardBody} text-center py-12">
                    <h2 class="${UI.title} mb-2">Hetzner Token Required</h2>
                    <p class="${UI.subtitle} mb-6">Configure your Hetzner API token to preview cloud-init scripts.</p>
                    <a href="#credentials" class="${cn(UI.btn, UI.btnPrimary)}">Configure API Token</a>
                </div>
            </div>
        `;
    }

    const script = generateCloudInit('devbox', token);
    const size = new Blob([script]).size;
    const sizeKB = (size / 1024).toFixed(1);
    const sizePercent = Math.round((size / 32768) * 100);
    const sizeColor = sizePercent > 90 ? 'text-destructive' : sizePercent > 70 ? 'text-warning' : 'text-success';
    const barColor = sizePercent > 90 ? 'bg-destructive' : sizePercent > 70 ? 'bg-warning' : 'bg-success';

    return `
        <div class="${UI.card}">
            <div class="${UI.cardHeader}">
                <div class="flex items-center justify-between flex-wrap gap-4">
                    <div>
                        <h2 class="${UI.title}">Cloud-Init Script</h2>
                        <p class="${UI.subtitle}">Preview the cloud-init user-data that will be sent to Hetzner</p>
                    </div>
                    <div class="${UI.row}">
                        <button class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}" onclick="window.devbox.copyCloudInit()">Copy</button>
                        <button class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}" onclick="window.devbox.downloadCloudInit()">Download</button>
                        <button class="${cn(UI.btn, UI.btnSecondary, UI.btnSm)}" onclick="window.devbox.refreshCloudInit()">Refresh</button>
                    </div>
                </div>
                <div class="mt-4">
                    <div class="flex items-center justify-between text-sm mb-1">
                        <span>Size</span>
                        <span class="${sizeColor} font-medium">${sizeKB} KB / 32 KB (${sizePercent}%)</span>
                    </div>
                    <div class="h-2 bg-muted rounded-full overflow-hidden">
                        <div class="h-full ${barColor} transition-all" style="width: ${Math.min(sizePercent, 100)}%"></div>
                    </div>
                    ${sizePercent > 90 ? '<p class="text-xs text-destructive mt-1">Warning: Close to Hetzner\'s 32KB limit!</p>' : ''}
                </div>
            </div>
            <div class="${UI.cardBody} p-0">
                <pre class="text-xs bg-background p-4 overflow-auto font-mono leading-relaxed" style="max-height: 70vh;"><code>${escapeHtml(script)}</code></pre>
            </div>
        </div>
    `;
}
