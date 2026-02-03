// Page renderers - Config, Profiles, Credentials
// Dashboard and CloudInit pages are in pages/ subdirectory

import { UI, cn, escapeHtml, escapeAttr } from './ui.js';
import { renderSelectCombobox } from './combobox.js';
import { state } from './state.js';
import { SETTINGS_SECTIONS, renderSettingsSection, renderSettingsField } from './settings.js';
import * as storage from './storage.js';

// Re-export page renderers from sub-modules
export { renderDashboard } from './pages/dashboard.js';
export { renderCloudInit } from './pages/cloudinit.js';

// ============================================================================
// PROFILES PAGE
// ============================================================================

export function renderProfiles() {
    const profiles = storage.getProfiles();
    const defaultProfileId = storage.getDefaultProfileId();

    const profileCards = Object.entries(profiles).map(([id, profile]) => {
        const isDefault = id === defaultProfileId;
        const overrideCount = Object.keys(profile.overrides).length;

        const summary = [];
        if (profile.overrides['hetzner.serverType']) {
            summary.push(profile.overrides['hetzner.serverType']);
        }
        if (profile.overrides['packages.mise']?.length) {
            summary.push(profile.overrides['packages.mise'].join(', '));
        }
        if (profile.overrides.repos?.length) {
            summary.push(`${profile.overrides.repos.length} repo(s)`);
        }
        if (overrideCount === 0) {
            summary.push('No overrides (uses global defaults)');
        }

        return `
            <div class="${UI.card} mb-3">
                <div class="${UI.cardBody}">
                    <div class="flex items-start justify-between gap-4">
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center gap-2 mb-1">
                                ${isDefault ? '<span class="text-warning" title="Default profile">\u2605</span>' : ''}
                                <h3 class="text-lg font-semibold">${escapeHtml(profile.name)}</h3>
                            </div>
                            <p class="text-sm text-muted-foreground">${escapeHtml(summary.join(' \u2022 '))}</p>
                        </div>
                        <div class="${UI.row}">
                            ${!isDefault ? `<button class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}" data-action="setDefaultProfile" data-id="${escapeAttr(id)}">Set Default</button>` : ''}
                            <button class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}" data-action="editProfile" data-id="${escapeAttr(id)}">Edit</button>
                            <button class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}" data-action="duplicateProfile" data-id="${escapeAttr(id)}">Duplicate</button>
                            ${id !== 'default' ? `<button class="${cn(UI.btn, UI.btnDestructive, UI.btnSm)}" data-action="deleteProfile" data-id="${escapeAttr(id)}">Delete</button>` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardHeader} flex items-center justify-between">
                <h2 class="${UI.title}">Profiles</h2>
                <button class="${cn(UI.btn, UI.btnPrimary, UI.btnSm)}" data-action="createNewProfile">New Profile</button>
            </div>
            <div class="${UI.cardBody}">
                <p class="text-muted-foreground mb-4">Profiles let you save different configurations. Each profile can override global defaults.</p>
                ${profileCards}
            </div>
        </div>
    `;
}

// ============================================================================
// PROFILE EDIT PAGE
// ============================================================================

export function renderProfileEdit() {
    const profileId = state.editingProfileId;
    if (!profileId) {
        return '<p>No profile selected</p>';
    }

    const profile = storage.getProfile(profileId);
    if (!profile) {
        return '<p>Profile not found</p>';
    }

    const globalConfig = storage.getGlobalConfig();
    const token = storage.getHetznerToken();

    const sectionsHtml = SETTINGS_SECTIONS.map(section =>
        renderSettingsSection(section, globalConfig, token, 'profile', profile)
    ).join('');

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardHeader} flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <button class="${cn(UI.btn, UI.btnOutline, UI.btnSm)}" data-action="backToProfiles">\u2190 Back</button>
                    <h2 class="${UI.title}">Edit Profile: ${escapeHtml(profile.name)}</h2>
                </div>
                <button class="${cn(UI.btn, UI.btnPrimary)}" data-action="saveProfileEdit">Save Changes</button>
            </div>
            <div class="${UI.cardBody}">
                <div class="mb-6">
                    <label class="${UI.label}">Profile Name</label>
                    <input type="text" id="profileName" class="${UI.input}" value="${escapeHtml(profile.name)}">
                </div>
                ${sectionsHtml}
            </div>
        </div>
    `;
}

// ============================================================================
// CONFIG PAGE (Global Defaults)
// ============================================================================

export function renderConfig() {
    const config = storage.getGlobalConfig();
    const token = storage.getHetznerToken();

    const sectionsHtml = SETTINGS_SECTIONS.map(section => {
        if (section.id === 'claude') {
            return renderClaudeSection(section, config);
        }
        return renderSettingsSection(section, config, token, 'global', null);
    }).join('');

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardBody}">
                <h2 class="${UI.title} mb-2">Global Defaults</h2>
                <p class="text-muted-foreground">These are the base settings that all profiles inherit from. Override specific settings in individual profiles.</p>
            </div>
        </div>

        ${sectionsHtml}

        <div class="${UI.row}">
            <button class="${cn(UI.btn, UI.btnSecondary)}" data-action="exportConfig">Export</button>
            <label class="${cn(UI.btn, UI.btnSecondary)} cursor-pointer" data-action="importConfig">
                Import
                <input type="file" id="importFile" accept=".json" class="hidden">
            </label>
        </div>
    `;
}

function renderClaudeSection(section, config) {
    const credentialsHtml = `
        <div>
            <label class="${UI.label}">Credentials</label>
            <div class="${UI.row} mb-2">
                <label class="${cn(UI.btn, UI.btnSecondary)} cursor-pointer" data-action="importClaudeCredentials">
                    Upload credentials.json
                    <input type="file" id="claudeCredentialsFile" accept=".json" class="hidden">
                </label>
                ${config.claude.credentialsJson ? `
                    <button class="${cn(UI.btn, UI.btnDestructive, UI.btnSm)}" data-action="clearClaudeCredentials">Clear</button>
                ` : ''}
            </div>
            ${config.claude.credentialsJson ? `
                <div class="bg-muted/30 rounded-md p-3 mb-2">
                    <div class="text-sm">
                        <span class="text-success">\u2713</span> Credentials loaded
                        ${getClaudeAccountInfo(config.claude.credentialsJson)}
                    </div>
                </div>
            ` : ''}
            <p class="${UI.hint}">Upload your ~/.claude/credentials.json file, or enter API key manually below</p>
        </div>
    `;

    const fieldsHtml = section.fields
        .filter(f => !f.globalOnly)
        .map(f => renderSettingsField(f, config, 'global', null))
        .join('');

    const apiKeyField = section.fields.find(f => f.path === 'claude.apiKey');
    const apiKeyHtml = apiKeyField ? renderSettingsField(apiKeyField, config, 'global', null) : '';

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardHeader}"><h2 class="${UI.title}">${section.title}</h2></div>
            <div class="${UI.cardBody}">
                <div class="${UI.stack}">
                    ${credentialsHtml}
                    ${apiKeyHtml}
                    ${fieldsHtml}
                </div>
            </div>
        </div>
    `;
}

export function getClaudeAccountInfo(credentials) {
    if (!credentials) return '';

    const parts = [];

    if (credentials.claudeAiOauth) {
        const oauth = credentials.claudeAiOauth;
        if (oauth.email) {
            parts.push(`<span class="text-muted-foreground">Account:</span> ${escapeHtml(String(oauth.email))}`);
        }
        if (oauth.organizationName) {
            parts.push(`<span class="text-muted-foreground">Org:</span> ${escapeHtml(String(oauth.organizationName))}`);
        }
        if (oauth.expiresAt) {
            const expiry = new Date(oauth.expiresAt);
            const isExpired = expiry < new Date();
            parts.push(`<span class="text-muted-foreground">Expires:</span> <span class="${isExpired ? 'text-destructive' : ''}">${escapeHtml(expiry.toLocaleDateString())}</span>`);
        }
    }

    if (credentials.apiKey) {
        const masked = String(credentials.apiKey).slice(0, 10) + '...' + String(credentials.apiKey).slice(-4);
        parts.push(`<span class="text-muted-foreground">API Key:</span> ${escapeHtml(masked)}`);
    }

    const accountKeys = Object.keys(credentials).filter(k => k !== 'claudeAiOauth' && k !== 'apiKey');
    if (accountKeys.length > 0) {
        parts.push(`<span class="text-muted-foreground">Keys:</span> ${escapeHtml(accountKeys.join(', '))}`);
    }

    if (parts.length === 0) {
        return '<span class="text-muted-foreground">(credentials loaded)</span>';
    }

    return '<br>' + parts.map(p => `<div class="mt-1">${p}</div>`).join('');
}

// ============================================================================
// CREDENTIALS PAGE
// ============================================================================

export function renderCredentials() {
    const token = storage.getHetznerToken();

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardHeader}">
                <h2 class="${UI.title}">Hetzner API Token</h2>
            </div>
            <div class="${UI.cardBody}">
                <div class="${UI.row} mb-2">
                    <input type="password" id="hetznerToken" class="${UI.input}" value="${escapeHtml(token)}" placeholder="Your Hetzner API token">
                    <button class="${cn(UI.btn, UI.btnSecondary)}" data-action="validateToken">Validate</button>
                </div>
                <p class="${UI.hint}">Get your token from <a href="https://console.hetzner.cloud" target="_blank" class="text-primary hover:underline">Hetzner Cloud Console</a></p>
            </div>
        </div>

        <div class="${UI.row}">
            <button class="${cn(UI.btn, UI.btnPrimary)}" data-action="saveCredentials">Save API Token</button>
            <button class="${cn(UI.btn, UI.btnDestructive)}" data-action="clearAll">Clear All Data</button>
        </div>
    `;
}
