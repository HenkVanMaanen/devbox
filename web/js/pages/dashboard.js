// Dashboard page renderer - server cards, creation form

import { UI, cn, escapeHtml, escapeAttr } from '../ui.js';
import { renderSelectCombobox } from '../combobox.js';
import { state } from '../state.js';
import * as storage from '../storage.js';
import * as hetzner from '../hetzner.js';
import { generateQR } from '../qrcode.js';

export function renderDashboard() {
    const token = storage.getHetznerToken();
    const config = storage.getDefaultProfileConfig();

    if (!token) {
        return `
            <div class="${UI.card}">
                <div class="${UI.cardBody} text-center py-12">
                    <h2 class="${UI.title} mb-2">Welcome to Devbox</h2>
                    <p class="${UI.subtitle} mb-6">Configure your Hetzner API token to get started.</p>
                    <a href="#credentials" class="${cn(UI.btn, UI.btnPrimary)}">Configure API Token</a>
                </div>
            </div>
        `;
    }

    if (state.loading) {
        return `
            <div class="${UI.card}">
                <div class="${UI.cardBody}">
                    <p class="${UI.subtitle}">Loading servers...</p>
                </div>
            </div>
        `;
    }

    if (state.error) {
        return `
            <div class="${UI.card}">
                <div class="${UI.cardBody}">
                    <div class="bg-destructive/10 border border-destructive/30 rounded-md p-4 mb-4">
                        <p class="text-sm text-destructive">${escapeHtml(state.error)}</p>
                    </div>
                    <button class="${cn(UI.btn, UI.btnSecondary)}" onclick="window.devbox.loadServers()">Retry</button>
                </div>
            </div>
        `;
    }

    const creatingCard = state.creating ? `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardBody} text-center py-12">
                <h2 class="${UI.title} mb-2">Creating Server</h2>
                <p class="${UI.subtitle} mb-4">${escapeHtml(state.createProgress)}</p>
                <div class="w-48 mx-auto h-1 bg-muted rounded-full overflow-hidden">
                    <div class="h-full bg-primary animate-pulse" style="width: 100%"></div>
                </div>
            </div>
        </div>
    ` : '';

    const serverCards = state.servers.map(server => renderServerCard(server, config)).join('');
    const createFormCard = renderCreateForm(config);

    return creatingCard + serverCards + createFormCard;
}

function renderServerCard(server, config) {
    const ip = server.public_net?.ipv4?.ip || 'N/A';
    const accessToken = storage.getServerToken(server.name);
    const urls = ip !== 'N/A' && accessToken ? hetzner.getServiceURLs(server.name, ip, config, accessToken) : null;

    const statusClass = {
        'running': UI.badgeSuccess,
        'starting': UI.badgeWarning,
        'initializing': UI.badgeWarning,
    }[server.status] || UI.badgeMuted;

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardHeader}">
                <div class="flex items-center justify-between">
                    <h2 class="${UI.title}">${escapeHtml(server.name)}</h2>
                    <span class="${cn(UI.badge, statusClass)}">${escapeHtml(server.status)}</span>
                </div>
            </div>
            <div class="${UI.cardBody}">
                <div class="${UI.grid3} text-sm mb-4">
                    <div><span class="text-muted-foreground">IP:</span> <code class="bg-muted px-1.5 py-0.5 rounded text-xs">${escapeHtml(ip)}</code></div>
                    <div><span class="text-muted-foreground">Type:</span> ${escapeHtml(server.server_type.name)}</div>
                    <div><span class="text-muted-foreground">Location:</span> ${escapeHtml(server.datacenter.name)}</div>
                </div>
                ${urls ? renderServerServices(urls, config) : ''}
            </div>
            <div class="${UI.cardFooter}">
                <button class="${cn(UI.btn, UI.btnDestructive, UI.btnSm)}" onclick="window.devbox.deleteServer(${server.id}, ${escapeAttr(JSON.stringify(server.name))})">Delete Server</button>
            </div>
        </div>
    `;
}

function renderServerServices(urls, config) {
    return `
        <div class="pt-4 border-t border-border">
            <p class="text-xs text-muted-foreground mb-2">Services</p>
            <div class="${UI.row} flex-wrap">
                ${urls.overview ? `<a href="${urls.overview}" target="_blank" class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}">Overview</a>` : ''}
                ${urls.code ? `<a href="${urls.code}" target="_blank" class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}">VS Code</a>` : ''}
                ${urls.terminal ? `<a href="${urls.terminal}" target="_blank" class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}">Terminal</a>` : ''}
            </div>
            ${urls.overview ? `
            <div class="mt-3 pt-3 border-t border-border flex justify-center">
                <div style="width:128px;height:128px;background:#fff;padding:8px;border-radius:8px">${safeGenerateQR(urls.overview).replace(/<svg /, '<svg style="width:100%;height:100%;display:block" ')}</div>
            </div>
            ` : ''}
        </div>
    `;
}

function renderCreateForm(config) {
    const profiles = storage.getProfiles();
    const defaultProfileId = storage.getDefaultProfileId();
    const selectedProfileId = state.selectedProfileId || defaultProfileId;

    // Build preview config without generating an access token (read-only summary)
    const previewConfig = buildPreviewConfig(selectedProfileId);

    const summaryParts = [];
    const serverType = state.serverTypes.find(t => t.name === previewConfig.hetzner.serverType);
    if (serverType) {
        summaryParts.push(`${serverType.name} (${serverType.cores} vCPU, ${serverType.memory}GB RAM)`);
    }
    const location = state.locations.find(l => l.name === previewConfig.hetzner.location);
    if (location) {
        summaryParts.push(location.city);
    }
    if (previewConfig.packages.mise?.length) {
        summaryParts.push(previewConfig.packages.mise.slice(0, 3).join(', ') + (previewConfig.packages.mise.length > 3 ? '...' : ''));
    }
    if (previewConfig.repos?.length) {
        summaryParts.push(`${previewConfig.repos.length} repo(s)`);
    }

    const profileOptions = Object.entries(profiles).map(([id, p]) => ({
        value: id,
        label: `${id === defaultProfileId ? '\u2605 ' : ''}${p.name}`,
        description: id === defaultProfileId ? 'Default profile' : ''
    }));

    return `
        <div class="${UI.card}">
            <div class="${UI.cardHeader}">
                <h2 class="${UI.title}">Create New Devbox</h2>
            </div>
            <div class="${UI.cardBody}">
                <div class="mb-4">
                    <label class="${UI.label}">Profile</label>
                    ${renderSelectCombobox('createServerProfile', profileOptions, selectedProfileId, 'Select profile...')}
                </div>
                ${summaryParts.length ? `
                <div class="bg-muted/30 rounded-md p-4 mb-4">
                    <p class="text-sm font-medium mb-2">Configuration Summary</p>
                    <p class="text-sm text-muted-foreground">${escapeHtml(summaryParts.join(' \u2022 '))}</p>
                </div>
                ` : ''}
                <button class="${cn(UI.btn, UI.btnPrimary, 'w-full')}"
                    onclick="window.devbox.createServer()"
                    ${state.creating ? 'disabled' : ''}>
                    ${state.creating ? 'Creating...' : 'Create Server'}
                </button>
            </div>
        </div>
    `;
}

function buildPreviewConfig(profileId) {
    const globalConfig = storage.getGlobalConfig();
    const profile = storage.getProfile(profileId);
    if (!profile) return globalConfig;
    const merged = JSON.parse(JSON.stringify(globalConfig));
    for (const [path, value] of Object.entries(profile.overrides)) {
        storage.setNestedValue(merged, path, value);
    }
    return merged;
}

function safeGenerateQR(url) {
    try {
        return generateQR(url);
    } catch {
        return '';
    }
}
