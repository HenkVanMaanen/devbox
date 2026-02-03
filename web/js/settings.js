// Settings field definitions and rendering
// Single source of truth for both Global Config and Profile Edit pages

import { UI, cn, escapeHtml } from './ui.js';
import { renderSelectCombobox, renderCombobox } from './combobox.js';
import { getNestedValue } from './storage.js';
import { state } from './state.js';
import * as packages from './packages.js';

// ============================================================================
// SETTINGS FIELD DEFINITIONS
//
// IMPORTANT: When adding new settings:
// 1. Add the field to the appropriate section below
// 2. renderProfileEdit() uses this automatically
// 3. Update renderConfig() manually (it has extra UI like credentials, custom inputs)
// 4. Update storage.js DEFAULT_GLOBAL_CONFIG if needed
// ============================================================================

export const SETTINGS_SECTIONS = [
    {
        id: 'hetzner',
        title: 'Server Settings',
        requiresHetzner: true,
        fields: [
            { path: 'hetzner.serverType', label: 'Server Type', type: 'select', optionsKey: 'serverTypes', hint: 'Prices: 8hr workday, 22 days/month. Excl. VAT.' },
            { path: 'hetzner.location', label: 'Location', type: 'select', optionsKey: 'locations' },
            { path: 'hetzner.baseImage', label: 'Base Image', type: 'select', optionsKey: 'images', hintKey: 'imageArch' }
        ]
    },
    {
        id: 'ssh',
        title: 'SSH',
        fields: [
            { path: 'ssh.keys', label: 'SSH Public Keys (Optional)', type: 'sshKeys',
              hint: 'Add SSH public keys for SSH access. Web service access works without this.' }
        ]
    },
    {
        id: 'git',
        title: 'Git Settings',
        fields: [
            { path: 'git.userName', label: 'User Name', type: 'text', placeholder: 'Your Name' },
            { path: 'git.userEmail', label: 'User Email', type: 'email', placeholder: 'you@example.com' },
            { path: 'git.credentials', label: 'Git Credentials', type: 'gitCredentials',
              hint: 'Only add tokens that cannot delete repositories. Use scoped tokens or a machine user with write-only access.' }
        ]
    },
    {
        id: 'shell',
        title: 'Shell Settings',
        fields: [
            {
                path: 'shell.default', label: 'Default Shell', type: 'select',
                options: [
                    { value: 'fish', label: 'Fish', description: 'Modern, user-friendly shell' },
                    { value: 'zsh', label: 'Zsh', description: 'Extended Bourne shell' },
                    { value: 'bash', label: 'Bash', description: 'GNU Bourne-Again shell' }
                ]
            },
            { path: 'shell.starship', label: 'Starship Prompt', type: 'checkbox', checkboxLabel: 'Enable Starship prompt' }
        ]
    },
    {
        id: 'services',
        title: 'Services',
        fields: [
            { path: 'services.codeServer', label: 'VS Code Server', type: 'checkbox', checkboxLabel: 'Enable VS Code Server' },
            { path: 'services.shellTerminal', label: 'Shell Terminal', type: 'checkbox', checkboxLabel: 'Enable Shell Terminal' },
            {
                path: 'services.dnsService', label: 'DNS Service', type: 'select',
                options: [
                    { value: 'sslip.io', label: 'sslip.io', description: 'Wildcard DNS for any IP' },
                    { value: 'nip.io', label: 'nip.io', description: 'Dead simple wildcard DNS' }
                ]
            },
            {
                path: 'services.acmeProvider', label: 'ACME Provider', type: 'select',
                options: [
                    { value: 'zerossl', label: 'ZeroSSL', description: 'No rate limits, recommended for testing' },
                    { value: 'letsencrypt', label: "Let's Encrypt", description: 'Most popular CA' },
                    { value: 'buypass', label: 'Buypass', description: 'Norwegian CA' },
                    { value: 'actalis', label: 'Actalis', description: 'Italian CA' },
                    { value: 'custom', label: 'Custom ACME', description: 'Self-hosted or other CA' }
                ]
            },
            { path: 'services.acmeEmail', label: 'ACME Email (optional)', type: 'email', placeholder: 'you@example.com' },
            { path: 'services.zerosslEabKeyId', label: 'ZeroSSL EAB Key ID', type: 'text', placeholder: 'From zerossl.com/acme', showWhen: { path: 'services.acmeProvider', value: 'zerossl' } },
            { path: 'services.zerosslEabKey', label: 'ZeroSSL EAB HMAC Key', type: 'password', placeholder: 'From zerossl.com/acme', showWhen: { path: 'services.acmeProvider', value: 'zerossl' } },
            { path: 'services.actalisEabKeyId', label: 'Actalis EAB Key ID', type: 'text', placeholder: 'From Actalis ACME dashboard', showWhen: { path: 'services.acmeProvider', value: 'actalis' } },
            { path: 'services.actalisEabKey', label: 'Actalis EAB HMAC Key', type: 'password', placeholder: 'From Actalis ACME dashboard', showWhen: { path: 'services.acmeProvider', value: 'actalis' } },
            { path: 'services.customAcmeUrl', label: 'Custom ACME Directory URL', type: 'url', placeholder: 'https://acme.example.com/directory', showWhen: { path: 'services.acmeProvider', value: 'custom' } },
            { path: 'services.customEabKeyId', label: 'EAB Key ID (optional)', type: 'text', placeholder: 'Leave empty if not required', showWhen: { path: 'services.acmeProvider', value: 'custom' } },
            { path: 'services.customEabKey', label: 'EAB HMAC Key (optional)', type: 'password', placeholder: 'Leave empty if not required', showWhen: { path: 'services.acmeProvider', value: 'custom' } }
        ]
    },
    {
        id: 'autoDelete',
        title: 'Auto-Delete',
        fields: [
            { path: 'autoDelete.enabled', label: 'Auto-Delete', type: 'checkbox', checkboxLabel: 'Enable auto-delete on idle' },
            { path: 'autoDelete.timeoutMinutes', label: 'Timeout (minutes)', type: 'number', min: 5, max: 1440 },
            { path: 'autoDelete.warningMinutes', label: 'Warning (minutes before)', type: 'number', min: 1, max: 30 }
        ]
    },
    {
        id: 'packages',
        title: 'Packages',
        fields: [
            {
                path: 'packages.mise', label: 'Mise Tools', type: 'multiselect', optionsKey: 'miseTools', grouped: true,
                customInput: { id: 'customMiseTool', placeholder: 'tool@version (e.g., elixir@1.16)', buttonLabel: 'Add', hint: 'Add any tool from <a href="https://mise.jdx.dev/plugins.html" target="_blank" class="text-primary hover:underline">mise plugins</a>' }
            },
            {
                path: 'packages.apt', label: 'APT Packages', type: 'multiselect', optionsKey: 'aptPackages', grouped: true,
                customInput: { id: 'customAptPackage', placeholder: 'package-name (e.g., nginx)', buttonLabel: 'Add', hint: 'Add any package available in APT repositories' }
            }
        ]
    },
    {
        id: 'claude',
        title: 'Claude Code',
        globalOnly: ['credentials'],
        fields: [
            { path: 'claude.apiKey', label: 'API Key (manual)', type: 'password', placeholder: 'sk-ant-...', hint: 'Only needed if not using credentials.json', globalOnly: true },
            {
                path: 'claude.theme', label: 'Theme', type: 'select',
                options: [
                    { value: '', label: 'Default', description: 'System default' },
                    { value: 'dark', label: 'Dark', description: 'Dark theme' },
                    { value: 'light', label: 'Light', description: 'Light theme' },
                    { value: 'dark-daltonized', label: 'Dark (Daltonized)', description: 'Color blind friendly dark' },
                    { value: 'light-daltonized', label: 'Light (Daltonized)', description: 'Color blind friendly light' }
                ]
            },
            { path: 'claude.skipPermissions', label: 'Skip Permissions', type: 'checkbox', checkboxLabel: 'Enable --dangerously-skip-permissions flag' },
            { path: 'claude.settings', label: 'Custom Settings (JSON)', type: 'textarea', placeholder: '{"key": "value"}', hint: 'Raw JSON to merge into Claude Code settings.json' }
        ]
    },
    {
        id: 'repos',
        title: 'Repositories',
        fields: [
            { path: 'repos', label: 'Repositories to clone', type: 'list', placeholder: 'https://github.com/user/repo.git', addLabel: 'Add Repository' }
        ]
    }
];

// ============================================================================
// DYNAMIC OPTIONS
// ============================================================================

export function getFieldOptions(optionsKey, config) {
    switch (optionsKey) {
        case 'serverTypes':
            return state.serverTypes
                .filter(t => !t.deprecated)
                .sort((a, b) => parseFloat(a.prices[0]?.price_monthly?.gross || '0') - parseFloat(b.prices[0]?.price_monthly?.gross || '0'))
                .map(t => {
                    const locationPrice = t.prices.find(p => p.location === config?.hetzner?.location);
                    const hourly = parseFloat(locationPrice?.price_hourly?.gross || t.prices[0]?.price_hourly?.gross || 0);
                    const daily8h = (hourly * 8).toFixed(2);
                    const monthly22d = (hourly * 8 * 22).toFixed(2);
                    const arch = t.architecture === 'arm' ? 'ARM64' : 'x86';
                    const available = !!locationPrice;
                    return {
                        value: t.name,
                        label: `${t.name} [${arch}] (${t.cores} vCPU, ${t.memory}GB) - \u20AC${daily8h}/day, \u20AC${monthly22d}/mo`,
                        description: `\u20AC${hourly.toFixed(4)}/hr`,
                        disabled: !available
                    };
                });
        case 'locations':
            return state.locations.map(l => ({
                value: l.name,
                label: `${l.city} (${l.name}) - ${l.country}`,
                description: l.description || ''
            }));
        case 'images': {
            const selectedServerType = state.serverTypes.find(t => t.name === config?.hetzner?.serverType);
            const arch = selectedServerType?.architecture || 'x86';
            return state.images
                .filter(i => i.architecture === arch)
                .sort((a, b) => a.name.localeCompare(b.name))
                .map(i => ({
                    value: i.name,
                    label: i.description || i.name,
                    description: `${i.os_flavor} ${i.os_version || ''}`
                }));
        }
        case 'aptPackages':
            return packages.APT_PACKAGES.map(pkg => ({
                value: pkg.name,
                label: pkg.name,
                group: packages.APT_CATEGORY_LABELS[pkg.category] || pkg.category,
                description: pkg.description || ''
            }));
        case 'miseTools':
            return packages.MISE_TOOLS.flatMap(tool =>
                tool.versions.map(version => ({
                    value: `${tool.name}@${version}`,
                    label: `${tool.name}@${version}`,
                    group: tool.name,
                    description: tool.description || ''
                }))
            );
        default:
            return [];
    }
}

// Get dynamic hint text for settings fields
export function getFieldHint(hintKey, config) {
    switch (hintKey) {
        case 'imageArch': {
            const selectedServerType = state.serverTypes.find(t => t.name === config?.hetzner?.serverType);
            return `Showing images for ${selectedServerType?.architecture === 'arm' ? 'ARM64' : 'x86'} architecture`;
        }
        default:
            return '';
    }
}

// Format value for display in profile override header
export function formatGlobalValue(value) {
    if (Array.isArray(value)) {
        if (value.length === 0) return '(empty)';
        if (value[0] && typeof value[0] === 'object' && value[0].host) {
            const preview = value.slice(0, 3).map(v => escapeHtml(v.host)).join(', ');
            return preview + (value.length > 3 ? '...' : '');
        }
        if (value[0] && typeof value[0] === 'object' && value[0].name !== undefined) {
            const preview = value.slice(0, 3).map(v => escapeHtml(v.name || 'Unnamed')).join(', ');
            return preview + (value.length > 3 ? '...' : '');
        }
        const preview = value.slice(0, 3).map(v => escapeHtml(String(v))).join(', ');
        return preview + (value.length > 3 ? '...' : '');
    }
    if (value === true) return 'Yes';
    if (value === false) return 'No';
    if (value === '' || value === null || value === undefined) return '(empty)';
    return escapeHtml(String(value));
}

// ============================================================================
// FIELD RENDERING
// ============================================================================

// Unified field rendering for both Global Config and Profile Edit
export function renderSettingsField(field, config, mode = 'global', profile = null) {
    if (mode === 'profile' && field.globalOnly) return '';
    if (mode === 'profile' && field.showWhen) return '';

    const globalValue = getNestedValue(config, field.path);
    const isProfile = mode === 'profile' && profile;
    const hasOverride = isProfile && Object.hasOwn(profile.overrides, field.path);
    const value = hasOverride ? profile.overrides[field.path] : globalValue;

    const prefix = isProfile ? 'profile-' : '';
    const fieldId = prefix + field.path.replace(/\./g, '-');

    const options = field.options || (field.optionsKey ? getFieldOptions(field.optionsKey, config) : []);

    // Check showWhen condition (global mode only)
    if (mode === 'global' && field.showWhen) {
        const conditionValue = getNestedValue(config, field.showWhen.path);
        if (conditionValue !== field.showWhen.value) {
            return '';
        }
    }

    const hint = field.hint || (field.hintKey ? getFieldHint(field.hintKey, config) : '');
    const hintHtml = hint ? `<p class="${UI.hint}">${hint}</p>` : '';

    const shouldRenderInput = mode === 'global' || hasOverride;

    let inputHtml = '';
    if (shouldRenderInput) {
        const dataAttr = isProfile ? `data-override-input="${field.path}"` : '';
        inputHtml = renderFieldInput(field, fieldId, value, options, dataAttr, isProfile);
    }

    if (mode === 'global') {
        if (field.type === 'checkbox') {
            return inputHtml;
        }
        return `
            <div>
                <label class="${UI.label}">${field.label}</label>
                ${inputHtml}
                ${hintHtml}
            </div>`;
    }

    // Profile mode: wrap with override toggle
    return `
        <div class="border border-border rounded-md p-4 mb-3">
            <div class="flex items-center justify-between mb-2">
                <label class="${UI.label}">${field.label}</label>
                <div class="flex items-center gap-2">
                    <label class="flex items-center gap-2 cursor-pointer text-sm">
                        <input type="radio" name="override-${field.path}" value="global" ${!hasOverride ? 'checked' : ''}
                               onchange="window.devbox.toggleOverride('${field.path}', false)" class="accent-primary">
                        <span>Global</span>
                    </label>
                    <label class="flex items-center gap-2 cursor-pointer text-sm">
                        <input type="radio" name="override-${field.path}" value="override" ${hasOverride ? 'checked' : ''}
                               onchange="window.devbox.toggleOverride('${field.path}', true)" class="accent-primary">
                        <span>Override</span>
                    </label>
                </div>
            </div>
            ${!hasOverride ? `<p class="text-sm text-muted-foreground mb-2">Using global: ${formatGlobalValue(globalValue)}</p>` : ''}
            ${inputHtml}
        </div>
    `;
}

// Render the actual form input element based on field type
function renderFieldInput(field, fieldId, value, options, dataAttr, isProfile) {
    switch (field.type) {
        case 'text':
        case 'email':
        case 'url':
        case 'password':
            return `<input type="${field.type}" id="${fieldId}" class="${UI.input}" value="${escapeHtml(String(value || ''))}" placeholder="${escapeHtml(field.placeholder || '')}" ${dataAttr}>`;
        case 'number':
            return `<input type="number" id="${fieldId}" class="${UI.input}" value="${escapeHtml(String(value || ''))}" ${field.min !== undefined ? `min="${field.min}"` : ''} ${field.max !== undefined ? `max="${field.max}"` : ''} ${dataAttr}>`;
        case 'checkbox':
            return `
                <label class="flex items-center gap-3 cursor-pointer">
                    <input type="checkbox" id="${fieldId}" class="${UI.checkbox}" ${value ? 'checked' : ''} ${dataAttr}>
                    <span class="text-sm">${field.checkboxLabel || 'Enabled'}</span>
                </label>`;
        case 'select':
            return renderSelectCombobox(fieldId, options, value, 'Select...');
        case 'multiselect': {
            const customInputId = isProfile ? `profile-${field.customInput?.id}` : field.customInput?.id;
            const customFn = isProfile ? 'addCustomPackageToProfile' : 'addCustomPackage';
            const customHtml = field.customInput ? `
                <div class="mt-3">
                    <label class="${UI.label}">Add custom</label>
                    <div class="${UI.row}">
                        <input type="text" id="${customInputId}" class="${UI.input}" placeholder="${escapeHtml(field.customInput.placeholder || '')}">
                        <button class="${cn(UI.btn, UI.btnSecondary)}" onclick="window.devbox.${customFn}('${field.path === 'packages.mise' ? 'mise' : 'apt'}')">${escapeHtml(field.customInput.buttonLabel || 'Add')}</button>
                    </div>
                    ${field.customInput.hint ? `<p class="${UI.hint}">${field.customInput.hint}</p>` : ''}
                </div>` : '';
            return renderCombobox(fieldId, options, value || [], 'Search...', field.grouped || false) + customHtml;
        }
        case 'textarea':
            return `<textarea id="${fieldId}" class="${UI.textarea}" rows="3" placeholder="${escapeHtml(field.placeholder || '')}" ${dataAttr}>${escapeHtml(String(value || ''))}</textarea>`;
        case 'textarea-array':
            return `<textarea id="${fieldId}" class="${UI.textarea}" rows="4" placeholder="${escapeHtml(field.placeholder || '')}" ${dataAttr}>${escapeHtml(Array.isArray(value) ? value.join('\n') : String(value || ''))}</textarea>`;
        case 'gitCredentials': {
            const creds = Array.isArray(value) ? value : [];
            const addFn = isProfile ? 'addGitCredentialToProfile' : 'addGitCredentialToConfig';
            const removeFn = isProfile ? 'removeGitCredentialFromProfile' : 'removeGitCredentialFromConfig';
            const saveFn = isProfile ? 'saveGitCredentialEditToProfile' : 'saveGitCredentialEdit';
            const credsHtml = creds.length ? creds.map((cred, i) => {
                const isEditing = state.editingListItem?.field === field.path &&
                                  state.editingListItem?.index === i &&
                                  state.editingListItem?.isProfile === isProfile;
                if (isEditing) {
                    return `
                    <div class="bg-muted/30 rounded-md px-3 py-2 space-y-2">
                        <div class="flex gap-2 flex-wrap">
                            <input type="text" id="git-credentials-edit-host" class="${UI.input}" value="${escapeHtml(cred.host || '')}" placeholder="github.com" style="flex: 1; min-width: 100px">
                            <input type="text" id="git-credentials-edit-username" class="${UI.input}" value="${escapeHtml(cred.username || '')}" placeholder="username" style="flex: 1; min-width: 100px">
                            <input type="password" id="git-credentials-edit-token" class="${UI.input}" value="${escapeHtml(cred.token || '')}" placeholder="Personal Access Token" style="flex: 2; min-width: 150px">
                        </div>
                        <div class="flex gap-2 flex-wrap">
                            <input type="text" id="git-credentials-edit-name" class="${UI.input}" value="${escapeHtml(cred.name || '')}" placeholder="Git Name (optional)" style="flex: 1; min-width: 120px">
                            <input type="email" id="git-credentials-edit-email" class="${UI.input}" value="${escapeHtml(cred.email || '')}" placeholder="Git Email (optional)" style="flex: 1; min-width: 150px">
                        </div>
                        <div class="flex gap-2">
                            <button class="${cn(UI.btn, UI.btnSecondary, UI.btnSm)}" onclick="window.devbox.${saveFn}(${i})">Save</button>
                            <button class="${cn(UI.btn, UI.btnSm)}" onclick="window.devbox.cancelEditListItem()">Cancel</button>
                        </div>
                    </div>`;
                }
                const identityHtml = (cred.name || cred.email)
                    ? `<br><span class="text-xs text-muted-foreground">${escapeHtml(cred.name || '')}${cred.name && cred.email ? ' &lt;' + escapeHtml(cred.email) + '&gt;' : (cred.email ? '&lt;' + escapeHtml(cred.email) + '&gt;' : '')}</span>`
                    : '';
                return `
                <div class="flex items-center justify-between bg-muted/30 rounded-md px-3 py-2">
                    <span class="text-sm">${escapeHtml(cred.host)} <span class="text-muted-foreground">(${escapeHtml(cred.username)})</span>${identityHtml}</span>
                    <div class="flex gap-2">
                        <button class="${cn(UI.btn, UI.btnSecondary, UI.btnSm)}" onclick="window.devbox.startEditListItem('${field.path}', ${i}, ${isProfile})">Edit</button>
                        <button class="${cn(UI.btn, UI.btnDestructive, UI.btnSm)}" onclick="window.devbox.${removeFn}(${i})">Remove</button>
                    </div>
                </div>
            `;
            }).join('') : `<p class="${UI.subtitle}">No git credentials configured</p>`;
            return `
                <div class="space-y-2 mb-4">${credsHtml}</div>
                <div>
                    <label class="${UI.label}">Add Git Credential</label>
                    <div class="flex gap-2 flex-wrap">
                        <input type="text" id="${fieldId}-host" class="${UI.input}" placeholder="github.com" style="flex: 1; min-width: 100px">
                        <input type="text" id="${fieldId}-username" class="${UI.input}" placeholder="username" style="flex: 1; min-width: 100px">
                        <input type="password" id="${fieldId}-token" class="${UI.input}" placeholder="Personal Access Token" style="flex: 2; min-width: 150px">
                    </div>
                    <div class="flex gap-2 flex-wrap mt-2">
                        <input type="text" id="${fieldId}-name" class="${UI.input}" placeholder="Git Name (optional)" style="flex: 1; min-width: 120px">
                        <input type="email" id="${fieldId}-email" class="${UI.input}" placeholder="Git Email (optional)" style="flex: 1; min-width: 150px">
                        <button class="${cn(UI.btn, UI.btnSecondary)}" onclick="window.devbox.${addFn}()">Add</button>
                    </div>
                </div>`;
        }
        case 'sshKeys': {
            const keys = Array.isArray(value) ? value : [];
            const addFn = isProfile ? 'addSSHKeyToProfile' : 'addSSHKey';
            const removeFn = isProfile ? 'removeSSHKeyFromProfile' : 'removeSSHKey';
            const saveFn = isProfile ? 'saveSSHKeyEditToProfile' : 'saveSSHKeyEdit';
            const keysHtml = keys.length ? keys.map((key, i) => {
                const isEditing = state.editingListItem?.field === field.path &&
                                  state.editingListItem?.index === i &&
                                  state.editingListItem?.isProfile === isProfile;
                if (isEditing) {
                    return `
                    <div class="bg-muted/30 rounded-md px-3 py-2 space-y-2">
                        <div class="flex gap-2 flex-wrap">
                            <input type="text" id="ssh-keys-edit-name" class="${UI.input}" value="${escapeHtml(key.name || '')}" placeholder="Key name (e.g., work-laptop)" style="flex: 1; min-width: 120px">
                        </div>
                        <div class="flex gap-2 flex-wrap">
                            <textarea id="ssh-keys-edit-pubKey" class="${UI.textarea}" rows="2" placeholder="ssh-ed25519 AAAA... you@example.com" style="flex: 1; min-width: 200px">${escapeHtml(key.pubKey || '')}</textarea>
                        </div>
                        <div class="flex gap-2">
                            <button class="${cn(UI.btn, UI.btnSecondary, UI.btnSm)}" onclick="window.devbox.${saveFn}(${i})">Save</button>
                            <button class="${cn(UI.btn, UI.btnSm)}" onclick="window.devbox.cancelEditListItem()">Cancel</button>
                        </div>
                    </div>`;
                }
                const keyPreview = key.pubKey ? key.pubKey.substring(0, 30) + '...' : '(empty)';
                return `
                <div class="flex items-center justify-between bg-muted/30 rounded-md px-3 py-2">
                    <span class="text-sm"><strong>${escapeHtml(key.name || 'Unnamed')}</strong><br><span class="text-xs text-muted-foreground font-mono">${escapeHtml(keyPreview)}</span></span>
                    <div class="flex gap-2">
                        <button class="${cn(UI.btn, UI.btnSecondary, UI.btnSm)}" onclick="window.devbox.startEditListItem('${field.path}', ${i}, ${isProfile})">Edit</button>
                        <button class="${cn(UI.btn, UI.btnDestructive, UI.btnSm)}" onclick="window.devbox.${removeFn}(${i})">Remove</button>
                    </div>
                </div>
            `;
            }).join('') : `<p class="${UI.subtitle}">No SSH keys configured</p>`;
            return `
                <div class="space-y-2 mb-4">${keysHtml}</div>
                <div>
                    <label class="${UI.label}">Add SSH Key</label>
                    <div class="flex gap-2 flex-wrap">
                        <input type="text" id="${fieldId}-name" class="${UI.input}" placeholder="Key name (e.g., work-laptop)" style="flex: 1; min-width: 120px">
                    </div>
                    <div class="flex gap-2 flex-wrap mt-2">
                        <textarea id="${fieldId}-pubKey" class="${UI.textarea}" rows="2" placeholder="ssh-ed25519 AAAA... you@example.com" style="flex: 1; min-width: 200px"></textarea>
                    </div>
                    <div class="flex gap-2 mt-2">
                        <button class="${cn(UI.btn, UI.btnSecondary)}" onclick="window.devbox.${addFn}()">Add</button>
                    </div>
                </div>`;
        }
        case 'list': {
            const items = Array.isArray(value) ? value : [];
            const listId = fieldId + '-list';
            const removeFn = isProfile ? 'removeListItemFromProfile' : 'removeListItem';
            const addFn = isProfile ? 'addListItemToProfile' : 'addListItem';
            const itemsHtml = items.length ? items.map((item, i) => `
                <div class="flex items-center gap-2 bg-muted/30 rounded-md px-3 py-2">
                    <span class="flex-1 text-sm truncate">${escapeHtml(String(item || ''))}</span>
                    <button class="${cn(UI.btn, UI.btnDestructive, UI.btnSm)}" onclick="window.devbox.${removeFn}('${field.path}', ${i})">Remove</button>
                </div>
            `).join('') : `<p class="${UI.subtitle}">No items added</p>`;
            return `
                <div id="${listId}" class="space-y-2 mb-3">${itemsHtml}</div>
                <div class="${UI.row}">
                    <input type="text" id="${fieldId}-input" class="${UI.input}" placeholder="${escapeHtml(field.placeholder || '')}">
                    <button class="${cn(UI.btn, UI.btnSecondary)}" onclick="window.devbox.${addFn}('${field.path}')">${escapeHtml(field.addLabel || 'Add')}</button>
                </div>`;
        }
        default:
            return '';
    }
}

// ============================================================================
// SECTION RENDERING
// ============================================================================

export function renderSettingsSection(section, config, token, mode = 'global', profile = null) {
    const isProfile = mode === 'profile';

    if (section.requiresHetzner) {
        if (!token) {
            if (isProfile) {
                return `
                    <h3 class="text-lg font-semibold mb-3 mt-6">${section.title}</h3>
                    <p class="text-muted-foreground">Load Hetzner data to configure server settings</p>`;
            }
            return `
                <div class="${UI.card} mb-4">
                    <div class="${UI.cardHeader}"><h2 class="${UI.title}">${section.title}</h2></div>
                    <div class="${UI.cardBody}">
                        <p class="${UI.subtitle}">Configure your Hetzner API token in <a href="#credentials" class="text-primary hover:underline">API Token</a> to load options.</p>
                    </div>
                </div>`;
        }
        if (state.serverTypes.length === 0) {
            if (isProfile) {
                return `
                    <h3 class="text-lg font-semibold mb-3 mt-6">${section.title}</h3>
                    <p class="text-muted-foreground">Loading options from Hetzner API...</p>`;
            }
            return `
                <div class="${UI.card} mb-4">
                    <div class="${UI.cardHeader}"><h2 class="${UI.title}">${section.title}</h2></div>
                    <div class="${UI.cardBody}">
                        <p class="${UI.subtitle}">Loading options from Hetzner API...</p>
                    </div>
                </div>`;
        }
    }

    const visibleFields = isProfile
        ? section.fields.filter(f => !f.globalOnly && !f.showWhen)
        : section.fields;

    if (visibleFields.length === 0) return '';

    const regularFields = visibleFields.filter(f => !f.showWhen);
    const fieldsHtml = regularFields.map(f => renderSettingsField(f, config, mode, profile)).join('');

    let conditionalHtml = '';
    if (!isProfile) {
        const conditionalGroups = {};
        section.fields.filter(f => f.showWhen).forEach(f => {
            const key = `${f.showWhen.path}:${f.showWhen.value}`;
            if (!conditionalGroups[key]) conditionalGroups[key] = [];
            conditionalGroups[key].push(f);
        });

        conditionalHtml = Object.entries(conditionalGroups).map(([key, fields]) => {
            const sepIdx = key.indexOf(':');
            const path = key.slice(0, sepIdx);
            const value = key.slice(sepIdx + 1);
            const currentValue = getNestedValue(config, path);
            const display = currentValue === value ? 'block' : 'none';
            const groupId = `${value}Fields`;
            return `
                <div id="${groupId}" class="bg-muted/30 rounded-md p-4 space-y-4" style="display: ${display}">
                    ${fields.map(f => renderSettingsField(f, config, mode, profile)).join('')}
                </div>`;
        }).join('');
    }

    if (isProfile) {
        return `
            <h3 class="text-lg font-semibold mb-3 mt-6">${section.title}</h3>
            ${fieldsHtml}
        `;
    }

    return `
        <div class="${UI.card} mb-4">
            <div class="${UI.cardHeader}"><h2 class="${UI.title}">${section.title}</h2></div>
            <div class="${UI.cardBody}">
                <div class="${UI.stack}">
                    ${fieldsHtml}
                    ${conditionalHtml}
                </div>
            </div>
        </div>`;
}
