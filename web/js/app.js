// Main app - orchestrator that ties together all modules
// Handles initialization, API actions, and event handler wiring

import * as storage from './storage.js';
import * as hetzner from './hetzner.js';
import * as themes from './themes.js';
import { generate as generateCloudInit } from './cloudinit.js';
import { generateServerName } from './names.js';
import { initComboboxes } from './combobox.js';
import { state, setState, setRenderCallback, router, showToast, showConfirm, showPrompt } from './state.js';
import { renderDashboard, renderProfiles, renderProfileEdit, renderConfig, renderCredentials, renderCloudInit } from './pages.js';
import { copyToClipboard } from './ui.js';
import { captureFormState, isFormDirty, clearFormState, revertForm, hasAnyDirtyForm } from './dirty.js';
import {
    toggleComboboxValue, selectComboboxValue,
    addCustomPackage, addCustomPackageToProfile,
    addListItem, removeListItem, addListItemToProfile, removeListItemFromProfile,
    addGitCredentialToConfig, removeGitCredentialFromConfig,
    addGitCredentialToProfile, removeGitCredentialFromProfile,
    addSSHKey, removeSSHKey, addSSHKeyToProfile, removeSSHKeyFromProfile,
    startEditListItem, cancelEditListItem,
    saveGitCredentialEdit, saveGitCredentialEditToProfile,
    saveSSHKeyEdit, saveSSHKeyEditToProfile
} from './handlers.js';

// ============================================================================
// INITIALIZATION
// ============================================================================

async function init() {
    initTheme();
    setRenderCallback(render);
    window.addEventListener('hashchange', handleHashChange);
    router();

    const token = storage.getHetznerToken();
    if (token) {
        await loadServers();
    }

    // Global event handlers for event delegation (CSP compliant - no inline handlers)
    document.addEventListener('click', handleGlobalClick);
    document.addEventListener('change', handleGlobalChange);

    // Theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleThemeDropdown);
    }

    // Set up floating actions bar buttons
    const floatingDiscard = document.getElementById('floating-discard');
    const floatingSave = document.getElementById('floating-save');
    if (floatingDiscard) {
        floatingDiscard.addEventListener('click', handleFloatingDiscard);
    }
    if (floatingSave) {
        floatingSave.addEventListener('click', handleFloatingSave);
    }

    // Warn about unsaved changes when leaving page
    window.addEventListener('beforeunload', handleBeforeUnload);

    // Set up dirty tracking on form inputs
    document.addEventListener('input', handleFormInput);
    document.addEventListener('change', handleFormInput);
}

// ============================================================================
// EVENT DELEGATION (CSP compliant - no inline onclick handlers)
// ============================================================================

// Map of action names to handler functions
const actionHandlers = {
    // Server actions
    createServer,
    deleteServer: (el) => deleteServer(Number(el.dataset.id), el.dataset.name),
    loadServers,

    // Config actions
    saveConfig,
    saveCredentials,
    validateToken,
    exportConfig,
    importConfig: () => document.getElementById('importFile')?.click(),

    // Profile actions
    setDefaultProfile: (el) => setDefaultProfile(el.dataset.id),
    editProfile: (el) => editProfile(el.dataset.id),
    backToProfiles,
    createNewProfile,
    duplicateProfile: (el) => duplicateProfile(el.dataset.id),
    deleteProfile: (el) => deleteProfile(el.dataset.id),
    saveProfileEdit,
    toggleOverride: (el) => toggleOverride(el.dataset.path, el.dataset.enable === 'true'),

    // List/credential handlers
    addGitCredentialToConfig,
    removeGitCredentialFromConfig: (el) => removeGitCredentialFromConfig(Number(el.dataset.index)),
    addGitCredentialToProfile,
    removeGitCredentialFromProfile: (el) => removeGitCredentialFromProfile(Number(el.dataset.index)),
    addSSHKey,
    removeSSHKey: (el) => removeSSHKey(Number(el.dataset.index)),
    addSSHKeyToProfile,
    removeSSHKeyFromProfile: (el) => removeSSHKeyFromProfile(Number(el.dataset.index)),
    startEditListItem: (el) => startEditListItem(el.dataset.field, Number(el.dataset.index), el.dataset.isProfile === 'true'),
    cancelEditListItem,
    saveGitCredentialEdit: (el) => saveGitCredentialEdit(Number(el.dataset.index)),
    saveGitCredentialEditToProfile: (el) => saveGitCredentialEditToProfile(Number(el.dataset.index)),
    saveSSHKeyEdit: (el) => saveSSHKeyEdit(Number(el.dataset.index)),
    saveSSHKeyEditToProfile: (el) => saveSSHKeyEditToProfile(Number(el.dataset.index)),

    // Package handlers
    addCustomPackage: (el) => addCustomPackage(el.dataset.type),
    addCustomPackageToProfile: (el) => addCustomPackageToProfile(el.dataset.type),
    addListItem: (el) => addListItem(el.dataset.path),
    removeListItem: (el) => removeListItem(el.dataset.path, Number(el.dataset.index)),
    addListItemToProfile: (el) => addListItemToProfile(el.dataset.path),
    removeListItemFromProfile: (el) => removeListItemFromProfile(el.dataset.path, Number(el.dataset.index)),

    // Claude credentials
    importClaudeCredentials: () => document.querySelector('input[type="file"][accept=".json"]')?.click(),
    clearClaudeCredentials,

    // Cloud-init actions
    copyCloudInit,
    downloadCloudInit,
    refreshCloudInit,

    // Theme actions
    changeTheme: (el) => changeTheme(el.dataset.theme),

    // Clipboard
    copyToClipboard: (el) => copyToClipboard(el.dataset.value),

    // Data management
    clearAll
};

// Global click handler for event delegation
function handleGlobalClick(e) {
    // Close theme dropdown when clicking outside
    const dropdown = document.getElementById('theme-dropdown');
    const toggle = document.getElementById('theme-toggle');
    if (dropdown && toggle && !dropdown.contains(e.target) && !toggle.contains(e.target)) {
        dropdown.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
    }

    // Find the closest element with data-action attribute
    const actionEl = e.target.closest('[data-action]');
    if (!actionEl) return;

    // Skip radio/checkbox - they're handled by change event
    if (actionEl.type === 'radio' || actionEl.type === 'checkbox') return;

    const action = actionEl.dataset.action;
    const handler = actionHandlers[action];

    if (handler) {
        e.preventDefault();
        handler(actionEl);
    } else {
        console.warn(`Unknown action: ${action}`);
    }
}

// Global change handler for form elements with data-action (radios, checkboxes, file inputs)
function handleGlobalChange(e) {
    const actionEl = e.target.closest('[data-action]');
    if (!actionEl) {
        // Handle file inputs inside labels with data-action
        if (e.target.type === 'file') {
            const label = e.target.closest('label[data-action]');
            if (label) {
                const action = label.dataset.action;
                if (action === 'importConfig') {
                    importConfig(e.target);
                } else if (action === 'importClaudeCredentials') {
                    importClaudeCredentials(e.target);
                }
            }
        }
        return;
    }

    const action = actionEl.dataset.action;
    const handler = actionHandlers[action];

    if (handler) {
        handler(actionEl);
    } else {
        console.warn(`Unknown action: ${action}`);
    }
}

// Handle hash change with dirty check
async function handleHashChange(e) {
    if (state.formDirty && state.currentFormContainer) {
        const confirmed = await showConfirm(
            'Unsaved Changes',
            'You have unsaved changes. Are you sure you want to leave this page?',
            'Leave Page'
        );
        if (!confirmed) {
            // Prevent navigation by restoring the hash
            e.preventDefault();
            window.history.pushState(null, '', `#${state.page}`);
            return;
        }
        clearDirtyState();
    }
    router();
}

// Handle beforeunload for browser navigation
function handleBeforeUnload(e) {
    if (hasAnyDirtyForm()) {
        e.preventDefault();
        e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
        return e.returnValue;
    }
}

// Handle form input changes for dirty tracking
function handleFormInput(e) {
    const formContainer = state.currentFormContainer;
    if (!formContainer) return;

    // Check if the input is within our tracked form container
    const container = document.getElementById(formContainer);
    if (!container || !container.contains(e.target)) return;

    // Check if form is dirty
    const isDirty = isFormDirty(formContainer);
    if (isDirty !== state.formDirty) {
        setState({ formDirty: isDirty });
        updateFloatingActionsBar(isDirty);
    }
}

// Update floating actions bar visibility
function updateFloatingActionsBar(show) {
    const bar = document.getElementById('floating-actions');
    if (bar) {
        bar.classList.toggle('visible', show);
    }
}

// Handle floating discard button
function handleFloatingDiscard() {
    const formContainer = state.currentFormContainer;
    if (formContainer) {
        revertForm(formContainer);
        setState({ formDirty: false });
        updateFloatingActionsBar(false);
        showToast('Changes discarded', 'info');
    }
}

// Handle floating save button
function handleFloatingSave() {
    // Determine which save function to call based on current page
    if (state.page === 'config') {
        saveConfig();
    } else if (state.page === 'profile-edit') {
        saveProfileEdit();
    } else if (state.page === 'credentials') {
        saveCredentials();
    }
}

// Clear dirty state
function clearDirtyState() {
    if (state.currentFormContainer) {
        clearFormState(state.currentFormContainer);
    }
    setState({ formDirty: false, currentFormContainer: null });
    updateFloatingActionsBar(false);
}

function initTheme() {
    const savedTheme = storage.getTheme();
    if (savedTheme === 'system' || !savedTheme) {
        themes.applyTheme(themes.getDefaultTheme());
    } else {
        themes.applyTheme(savedTheme);
    }

    themes.watchSystemPreference((preference) => {
        const currentTheme = storage.getTheme();
        if (currentTheme === 'system' || !currentTheme) {
            themes.applyTheme(preference === 'dark' ? 'default-dark' : 'default-light');
        }
    });

    renderThemeDropdown();
}

// ============================================================================
// API ACTIONS
// ============================================================================

async function loadServers() {
    const token = storage.getHetznerToken();
    if (!token) {
        setState({ servers: [], error: null });
        return;
    }

    setState({ loading: true, error: null });
    try {
        const servers = await hetzner.listServers(token);
        const devboxServers = servers.filter(s => s.name.startsWith('devbox'));
        setState({ servers: devboxServers, loading: false });
    } catch (e) {
        setState({ servers: [], loading: false, error: e.message });
    }
}

async function createServer() {
    const token = storage.getHetznerToken();
    const selectedProfileId = state.selectedProfileId || storage.getDefaultProfileId();
    const config = storage.getConfigForProfile(selectedProfileId);
    const sshKeys = config.ssh?.keys || [];

    if (!token) {
        showToast('Hetzner token not configured', 'error');
        window.location.hash = '#credentials';
        return;
    }

    setState({ creating: true, createProgress: 'Preparing server...' });

    try {
        let sshKeyIds = [];
        if (sshKeys.length > 0) {
            setState({ createProgress: 'Ensuring SSH keys exist...' });
            for (const key of sshKeys) {
                if (key.pubKey) {
                    // Sanitize key name for Hetzner API (alphanumeric, hyphens, underscores only)
                    const safeName = key.name.replace(/[^a-zA-Z0-9_-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '') || 'key';
                    const hetznerKey = await hetzner.ensureSSHKey(token, `devbox-${safeName}`, key.pubKey);
                    sshKeyIds.push(hetznerKey.id);
                }
            }
        }

        setState({ createProgress: 'Generating cloud-init...' });
        const serverName = generateServerName();
        const userData = generateCloudInit(serverName, token, config);

        // Store access token locally (not in API-visible labels)
        storage.saveServerToken(serverName, config.services.accessToken);

        setState({ createProgress: 'Creating server...' });
        const server = await hetzner.createServer(token, {
            name: serverName,
            serverType: config.hetzner.serverType,
            image: config.hetzner.baseImage,
            location: config.hetzner.location,
            sshKeys: sshKeyIds,
            userData,
            labels: { managed: 'devbox' }
        });

        setState({ createProgress: 'Waiting for server to start...' });
        await hetzner.waitForRunning(token, server.id);

        showToast('Server created successfully!', 'success');
        setState({ creating: false, createProgress: '' });
        await loadServers();
    } catch (e) {
        showToast(`Failed to create server: ${e.message}`, 'error');
        setState({ creating: false, createProgress: '' });
    }
}

async function deleteServer(serverId, serverName) {
    if (!await showConfirm('Delete Server', 'Are you sure you want to delete this server? This action cannot be undone.', 'Delete')) return;

    const token = storage.getHetznerToken();
    setState({ loading: true });

    try {
        await hetzner.deleteServer(token, serverId);
        if (serverName) storage.removeServerToken(serverName);
        showToast('Server deleted', 'success');
        await loadServers();
    } catch (e) {
        showToast(`Failed to delete server: ${e.message}`, 'error');
        setState({ loading: false });
    }
}

async function loadHetznerOptions() {
    const token = storage.getHetznerToken();
    if (!token || state.loadingHetznerOptions) return;

    setState({ loadingHetznerOptions: true });

    try {
        const [serverTypes, locations, images] = await Promise.all([
            hetzner.listServerTypes(token),
            hetzner.listLocations(token),
            hetzner.listImages(token)
        ]);
        setState({ serverTypes, locations, images, loadingHetznerOptions: false });
    } catch (e) {
        console.error('Failed to load Hetzner options:', e);
        showToast('Failed to load Hetzner options: ' + e.message, 'error');
        setState({ loadingHetznerOptions: false, hetznerOptionsError: true });
    }
}

// ============================================================================
// RENDER
// ============================================================================

function render() {
    const app = document.getElementById('app');
    if (!app) return;

    app.innerHTML = renderPage();
    initComboboxes();

    // Set up form dirty tracking for config pages
    setupFormTracking();
}

// Set up form tracking based on current page
function setupFormTracking() {
    let containerId = null;

    switch (state.page) {
        case 'config':
            containerId = 'app';
            break;
        case 'profile-edit':
            containerId = 'app';
            break;
        case 'credentials':
            containerId = 'app';
            break;
    }

    if (containerId) {
        // Small delay to ensure DOM is fully updated
        setTimeout(() => {
            captureFormState(containerId);
            setState({ currentFormContainer: containerId, formDirty: false });
            updateFloatingActionsBar(false);
        }, 50);
    } else {
        // Clear tracking when not on a form page
        if (state.currentFormContainer) {
            clearFormState(state.currentFormContainer);
            setState({ currentFormContainer: null, formDirty: false });
            updateFloatingActionsBar(false);
        }
    }
}

function ensureHetznerOptions() {
    if (state.serverTypes.length === 0 && storage.getHetznerToken() && !state.hetznerOptionsError) {
        loadHetznerOptions();
    }
}

function renderPage() {
    switch (state.page) {
        case 'dashboard': return renderDashboard();
        case 'config':
            ensureHetznerOptions();
            return renderConfig();
        case 'profiles':
            ensureHetznerOptions();
            return renderProfiles();
        case 'profile-edit':
            ensureHetznerOptions();
            return renderProfileEdit();
        case 'cloudinit': return renderCloudInit();
        case 'credentials': return renderCredentials();
        default: return renderDashboard();
    }
}

// ============================================================================
// CONFIG & CREDENTIAL ACTIONS
// ============================================================================

function saveConfig() {
    const config = storage.getGlobalConfig();

    const getFieldValue = (path) => {
        const fieldId = path.replace(/\./g, '-');
        return document.getElementById(fieldId)?.value ?? '';
    };
    const getCheckboxValue = (path, defaultValue = true) => {
        const fieldId = path.replace(/\./g, '-');
        return document.getElementById(fieldId)?.checked ?? defaultValue;
    };

    // SSH keys are managed via addSSHKey/removeSSHKey handlers, not here

    config.git.userName = getFieldValue('git.userName');
    config.git.userEmail = getFieldValue('git.userEmail');

    config.shell.starship = getCheckboxValue('shell.starship', true);

    config.services.codeServer = getCheckboxValue('services.codeServer', true);
    config.services.claudeTerminal = getCheckboxValue('services.claudeTerminal', true);
    config.services.shellTerminal = getCheckboxValue('services.shellTerminal', true);
    config.services.acmeEmail = getFieldValue('services.acmeEmail');
    config.services.zerosslEabKeyId = getFieldValue('services.zerosslEabKeyId');
    config.services.zerosslEabKey = getFieldValue('services.zerosslEabKey');
    config.services.actalisEabKeyId = getFieldValue('services.actalisEabKeyId');
    config.services.actalisEabKey = getFieldValue('services.actalisEabKey');
    config.services.customAcmeUrl = getFieldValue('services.customAcmeUrl');
    config.services.customEabKeyId = getFieldValue('services.customEabKeyId');
    config.services.customEabKey = getFieldValue('services.customEabKey');

    config.autoDelete.enabled = getCheckboxValue('autoDelete.enabled', true);
    const parsedTimeout = parseInt(getFieldValue('autoDelete.timeoutMinutes'));
    config.autoDelete.timeoutMinutes = Number.isFinite(parsedTimeout) && parsedTimeout >= 5 ? parsedTimeout : 90;
    const parsedWarning = parseInt(getFieldValue('autoDelete.warningMinutes'));
    config.autoDelete.warningMinutes = Number.isFinite(parsedWarning) && parsedWarning >= 1 ? parsedWarning : 5;

    config.claude.apiKey = getFieldValue('claude.apiKey');
    config.claude.settings = getFieldValue('claude.settings');

    storage.saveGlobalConfig(config);

    // Clear dirty state and recapture form state
    if (state.currentFormContainer) {
        clearFormState(state.currentFormContainer);
        captureFormState(state.currentFormContainer);
    }
    setState({ formDirty: false });
    updateFloatingActionsBar(false);

    showToast('Configuration saved', 'success');
}

function saveCredentials() {
    const token = document.getElementById('hetznerToken')?.value || '';

    storage.saveHetznerToken(token);
    setState({ serverTypes: [], locations: [], images: [], hetznerOptionsError: false });

    // Clear dirty state and recapture form state
    if (state.currentFormContainer) {
        clearFormState(state.currentFormContainer);
        captureFormState(state.currentFormContainer);
    }
    setState({ formDirty: false });
    updateFloatingActionsBar(false);

    showToast('API token saved', 'success');
    loadServers();
}

async function validateToken() {
    const token = document.getElementById('hetznerToken')?.value;
    if (!token) {
        showToast('Please enter a token', 'error');
        return;
    }

    const valid = await hetzner.validateToken(token);
    showToast(valid ? 'Token is valid!' : 'Token is invalid', valid ? 'success' : 'error');
}

function importClaudeCredentials(input) {
    const file = input.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const credentials = JSON.parse(e.target.result);
            const config = storage.getGlobalConfig();
            config.claude.credentialsJson = credentials;
            storage.saveGlobalConfig(config);
            showToast('Claude credentials imported', 'success');
            render();
        } catch {
            showToast('Invalid credentials file', 'error');
        }
        input.value = '';
    };
    reader.readAsText(file);
}

function clearClaudeCredentials() {
    const config = storage.getGlobalConfig();
    config.claude.credentialsJson = null;
    storage.saveGlobalConfig(config);
    showToast('Claude credentials cleared', 'success');
    render();
}

// ============================================================================
// DATA MANAGEMENT
// ============================================================================

async function clearAll() {
    if (!await showConfirm('Clear All Data', 'Are you sure you want to clear all data? This action cannot be undone.', 'Clear All')) return;
    storage.clearAll();
    showToast('All data cleared', 'success');
    render();
}

function exportConfig() {
    const config = storage.exportAll();
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'devbox-config.json';
    a.click();
    URL.revokeObjectURL(url);
}

function importConfig(input) {
    const file = input.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const config = JSON.parse(e.target.result);
            storage.importAll(config);
            showToast('Configuration imported', 'success');
            render();
        } catch {
            showToast('Invalid config file', 'error');
        }
        input.value = '';
    };
    reader.readAsText(file);
}

function copyCloudInit() {
    const token = storage.getHetznerToken();
    if (!token) {
        showToast('Hetzner token required', 'error');
        return;
    }
    const script = generateCloudInit('devbox', token);
    navigator.clipboard.writeText(script)
        .then(() => showToast('Copied to clipboard', 'success'))
        .catch(() => showToast('Failed to copy', 'error'));
}

function downloadCloudInit() {
    const token = storage.getHetznerToken();
    if (!token) {
        showToast('Hetzner token required', 'error');
        return;
    }
    const script = generateCloudInit('devbox', token);
    const blob = new Blob([script], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cloud-init.yaml';
    a.click();
    URL.revokeObjectURL(url);
}

function refreshCloudInit() {
    render();
    showToast('Cloud-init refreshed', 'success');
}

// ============================================================================
// THEME
// ============================================================================

function renderThemeDropdown() {
    const dropdown = document.getElementById('theme-dropdown');
    if (!dropdown) return;

    const currentTheme = storage.getTheme();

    let html = `
        <button class="theme-option ${currentTheme === 'system' ? 'selected' : ''}"
                data-action="changeTheme" data-theme="system" role="option" aria-selected="${currentTheme === 'system'}">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            <span>System</span>
            ${currentTheme === 'system' ? '<span class="check">\u2713</span>' : ''}
        </button>
        <div class="theme-divider"></div>
    `;

    themes.THEME_FAMILIES.forEach(family => {
        html += `<div class="theme-family-label">${family.name}</div>`;
        family.themes.forEach(themeId => {
            const theme = themes.getTheme(themeId);
            if (!theme) return;
            const isSelected = currentTheme === themeId;
            html += `
                <button class="theme-option ${isSelected ? 'selected' : ''}"
                        data-action="changeTheme" data-theme="${themeId}" role="option" aria-selected="${isSelected}">
                    <span class="theme-preview" style="background: ${theme.colors.background}; border-color: ${theme.colors.border};">
                        <span style="background: ${theme.colors.primary};"></span>
                    </span>
                    <span>${theme.name}</span>
                    ${isSelected ? '<span class="check">\u2713</span>' : ''}
                </button>
            `;
        });
    });

    dropdown.innerHTML = html;
}

function toggleThemeDropdown() {
    const dropdown = document.getElementById('theme-dropdown');
    const toggle = document.getElementById('theme-toggle');
    if (!dropdown || !toggle) return;

    const isOpen = dropdown.classList.toggle('open');
    toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');

    if (isOpen) {
        renderThemeDropdown();
    }
}

function changeTheme(themeId) {
    storage.saveTheme(themeId);

    if (themeId === 'system') {
        themes.applyTheme(themes.getDefaultTheme());
    } else {
        themes.applyTheme(themeId);
    }

    renderThemeDropdown();

    const themeName = themeId === 'system' ? 'System' : themes.getTheme(themeId)?.name || themeId;
    showToast(`Theme: ${themeName}`, 'success');

    const dropdown = document.getElementById('theme-dropdown');
    const toggle = document.getElementById('theme-toggle');
    if (dropdown && toggle) {
        dropdown.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
    }
}

// ============================================================================
// PROFILE MANAGEMENT
// ============================================================================

function setDefaultProfile(id) {
    storage.setDefaultProfileId(id);
    showToast('Default profile updated', 'success');
    render();
}

function editProfile(id) {
    setState({ editingProfileId: id, page: 'profile-edit' });
    window.location.hash = '#profile-edit';
}

function backToProfiles() {
    setState({ editingProfileId: null, page: 'profiles' });
    window.location.hash = '#profiles';
}

async function createNewProfile() {
    const name = await showPrompt('Enter profile name:');
    if (!name) return;

    const id = storage.createProfile(name);
    showToast(`Profile "${name}" created`, 'success');
    editProfile(id);
}

async function duplicateProfile(fromId) {
    const profiles = storage.getProfiles();
    const source = profiles[fromId];
    if (!source) return;
    const name = await showPrompt('Enter new profile name:', `${source.name} Copy`);
    if (!name) return;

    storage.duplicateProfile(fromId, name);
    showToast(`Profile "${name}" created`, 'success');
    render();
}

async function deleteProfile(id) {
    const profiles = storage.getProfiles();
    const profile = profiles[id];
    if (!profile) return;

    const confirmed = await showConfirm(
        `Delete Profile "${profile.name}"?`,
        'This action cannot be undone.',
        'Delete'
    );

    if (confirmed) {
        storage.deleteProfile(id);
        showToast('Profile deleted', 'success');
        render();
    }
}

function toggleOverride(path, enable) {
    const profileId = state.editingProfileId;
    const profile = storage.getProfile(profileId);
    if (!profile) return;

    if (enable) {
        const globalConfig = storage.getGlobalConfig();
        const globalValue = storage.getNestedValue(globalConfig, path);
        profile.overrides[path] = typeof globalValue === 'object' && globalValue !== null
            ? JSON.parse(JSON.stringify(globalValue))
            : globalValue;
    } else {
        delete profile.overrides[path];
    }

    storage.saveProfile(profileId, profile);
    render();
}

function saveProfileEdit() {
    const profileId = state.editingProfileId;
    const profile = storage.getProfile(profileId);
    if (!profile) return;

    const nameInput = document.getElementById('profileName');
    if (nameInput) {
        profile.name = nameInput.value.trim() || profile.name;
    }

    document.querySelectorAll('[data-override-input]').forEach(input => {
        const path = input.dataset.overrideInput;
        if (!input.disabled && Object.hasOwn(profile.overrides, path)) {
            if (input.type === 'checkbox') {
                profile.overrides[path] = input.checked;
            } else if (input.tagName === 'TEXTAREA') {
                profile.overrides[path] = input.value;
            } else if (input.type === 'number') {
                const num = parseInt(input.value, 10);
                profile.overrides[path] = Number.isFinite(num) ? num : 0;
            } else {
                profile.overrides[path] = input.value;
            }
        }
    });

    storage.saveProfile(profileId, profile);

    // Clear dirty state and recapture form state
    if (state.currentFormContainer) {
        clearFormState(state.currentFormContainer);
        captureFormState(state.currentFormContainer);
    }
    setState({ formDirty: false });
    updateFloatingActionsBar(false);

    showToast('Profile saved', 'success');
    render();
}

// ============================================================================
// GLOBAL API (exposed to HTML onclick handlers)
// ============================================================================

window.devbox = {
    createServer,
    deleteServer,
    loadServers,
    saveConfig,
    saveCredentials,
    validateToken,
    copyToClipboard,
    addGitCredentialToConfig,
    removeGitCredentialFromConfig,
    addGitCredentialToProfile,
    removeGitCredentialFromProfile,
    addSSHKey,
    removeSSHKey,
    addSSHKeyToProfile,
    removeSSHKeyFromProfile,
    startEditListItem,
    cancelEditListItem,
    saveGitCredentialEdit,
    saveGitCredentialEditToProfile,
    saveSSHKeyEdit,
    saveSSHKeyEditToProfile,
    clearAll,
    exportConfig,
    importConfig,
    toggleComboboxValue,
    selectComboboxValue,
    importClaudeCredentials,
    clearClaudeCredentials,
    addCustomPackage,
    addCustomPackageToProfile,
    addListItem,
    removeListItem,
    addListItemToProfile,
    removeListItemFromProfile,
    copyCloudInit,
    downloadCloudInit,
    refreshCloudInit,
    toggleThemeDropdown,
    changeTheme,
    setDefaultProfile,
    editProfile,
    backToProfiles,
    createNewProfile,
    duplicateProfile,
    deleteProfile,
    toggleOverride,
    saveProfileEdit
};

document.addEventListener('DOMContentLoaded', init);
