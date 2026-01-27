// UI event handlers for combobox selections, package management, and list items

import * as storage from './storage.js';
import { state, setState, showToast } from './state.js';

// ============================================================================
// COMBOBOX HANDLERS
// ============================================================================

export function toggleComboboxValue(comboboxId, value, toggle = true) {
    if (comboboxId.startsWith('profile-')) {
        const fieldId = comboboxId.replace('profile-', '');
        const path = fieldId.replace(/-/g, '.');
        if (path && state.editingProfileId) {
            const profile = storage.getProfile(state.editingProfileId);
            if (profile && Object.hasOwn(profile.overrides, path)) {
                const arr = profile.overrides[path] || [];
                togglePackageInArray(arr, path, value, toggle);
                profile.overrides[path] = arr;
                storage.saveProfile(state.editingProfileId, profile);
                setState({});
            }
        }
        return;
    }

    const config = storage.getGlobalConfig();
    const path = comboboxId.replace(/-/g, '.');

    if (path === 'packages.apt') {
        const idx = config.packages.apt.indexOf(value);
        if (toggle && idx === -1) {
            config.packages.apt.push(value);
        } else if (idx !== -1) {
            config.packages.apt.splice(idx, 1);
        }
    } else if (path === 'packages.mise') {
        toggleMiseTool(config.packages.mise, value);
    }

    storage.saveGlobalConfig(config);
    setState({});
}

export function selectComboboxValue(comboboxId, value, label) {
    if (comboboxId === 'createServerProfile') {
        setState({ selectedProfileId: value });
        return;
    }

    if (comboboxId.startsWith('profile-')) {
        const fieldId = comboboxId.replace('profile-', '');
        const path = fieldId.replace(/-/g, '.');
        if (path && state.editingProfileId) {
            const profile = storage.getProfile(state.editingProfileId);
            if (profile) {
                profile.overrides[path] = value;
                storage.saveProfile(state.editingProfileId, profile);
                setState({});
            }
        }
        return;
    }

    const config = storage.getGlobalConfig();
    const path = comboboxId.replace(/-/g, '.');

    storage.setNestedValue(config, path, value);
    storage.saveGlobalConfig(config);

    // Fields with conditional visibility need a full re-render
    const fieldsWithDependents = ['services.acmeProvider', 'hetzner.serverType'];
    if (fieldsWithDependents.includes(path)) {
        setState({});
        return;
    }

    // Update UI immediately without full re-render
    const dropdown = document.querySelector(`[data-combobox="${comboboxId}"][data-dropdown]`);
    const input = document.querySelector(`[data-combobox="${comboboxId}"][data-search-single]`);

    if (dropdown) {
        dropdown.querySelectorAll('.combobox-option').forEach(opt => {
            const isSelected = opt.dataset.value === value;
            opt.classList.toggle('selected', isSelected);
            const check = opt.querySelector('.combobox-option-check');
            if (isSelected && !check) {
                const span = document.createElement('span');
                span.textContent = opt.dataset.label;
                const checkSpan = document.createElement('span');
                checkSpan.className = 'combobox-option-check';
                checkSpan.textContent = '\u2713';
                opt.replaceChildren(span, checkSpan);
            } else if (!isSelected && check) {
                check.remove();
            }
        });
        dropdown.classList.remove('open');
    }

    if (input) {
        input.value = '';
        input.placeholder = label;
        input.dataset.selected = value;
    }
}

// Toggle a mise tool in an array (handles version switching)
function toggleMiseTool(arr, value) {
    const toolName = value.split('@')[0];
    const existingIdx = arr.findIndex(m => m.startsWith(toolName + '@'));
    const isExactMatch = arr.includes(value);

    if (isExactMatch) {
        arr.splice(existingIdx, 1);
    } else if (existingIdx !== -1) {
        arr[existingIdx] = value;
    } else {
        arr.push(value);
    }
}

// Toggle a package in array (handles mise version switching)
function togglePackageInArray(arr, path, value, toggle) {
    if (path === 'packages.mise') {
        toggleMiseTool(arr, value);
    } else {
        const idx = arr.indexOf(value);
        if (toggle && idx === -1) {
            arr.push(value);
        } else if (idx !== -1) {
            arr.splice(idx, 1);
        }
    }
}

// ============================================================================
// PACKAGE MANAGEMENT
// ============================================================================

function validatePackageInput(type, isProfile) {
    const prefix = isProfile ? 'profile-' : '';
    const inputId = type === 'mise' ? `${prefix}customMiseTool` : `${prefix}customAptPackage`;
    const input = document.getElementById(inputId);
    const value = input?.value?.trim();

    if (!value) {
        showToast('Please enter a package name', 'error');
        return null;
    }

    if (!/^[a-zA-Z0-9@._:\/+-]+$/.test(value)) {
        showToast('Invalid package name: only alphanumeric characters, @, ., _, :, /, +, - allowed', 'error');
        return null;
    }

    return value;
}

function addPackageToList(list, type, value) {
    if (type === 'mise') {
        const formatted = value.includes('@') ? value : `${value}@latest`;
        if (!list.includes(formatted)) {
            list.push(formatted);
            showToast(`Added ${formatted}`, 'success');
            return true;
        }
        showToast('Tool already added', 'warning');
        return false;
    }
    if (!list.includes(value)) {
        list.push(value);
        showToast(`Added ${value}`, 'success');
        return true;
    }
    showToast('Package already added', 'warning');
    return false;
}

export function addCustomPackage(type) {
    const value = validatePackageInput(type, false);
    if (!value) return;

    const config = storage.getGlobalConfig();
    const list = type === 'mise' ? config.packages.mise : config.packages.apt;
    if (addPackageToList(list, type, value)) {
        storage.saveGlobalConfig(config);
        setState({});
    }
}

export function addCustomPackageToProfile(type) {
    const value = validatePackageInput(type, true);
    if (!value) return;

    const profileId = state.editingProfileId;
    const profile = storage.getProfile(profileId);
    if (!profile) return;

    const path = type === 'mise' ? 'packages.mise' : 'packages.apt';

    if (!Object.hasOwn(profile.overrides, path)) {
        const globalConfig = storage.getGlobalConfig();
        profile.overrides[path] = [...(storage.getNestedValue(globalConfig, path) || [])];
    }

    if (addPackageToList(profile.overrides[path], type, value)) {
        storage.saveProfile(profileId, profile);
        setState({});
    }
}

// ============================================================================
// LIST ITEM MANAGEMENT
// ============================================================================

function validateListInput(path, isProfile) {
    const prefix = isProfile ? 'profile-' : '';
    const fieldId = prefix + path.replace(/\./g, '-');
    const input = document.getElementById(`${fieldId}-input`);
    const value = input?.value?.trim();

    if (!value) {
        showToast('Please enter a value', 'error');
        return null;
    }

    if (path === 'repos') {
        if (!/^(https?:\/\/|git@)[\w.@:\/~-]+$/.test(value)) {
            showToast('Invalid repository URL', 'error');
            return null;
        }
    }

    return value;
}

function ensureProfileOverrideList(profile, path) {
    if (!Object.hasOwn(profile.overrides, path)) {
        const globalConfig = storage.getGlobalConfig();
        profile.overrides[path] = [...(storage.getNestedValue(globalConfig, path) || [])];
    }
}

export function addListItem(path) {
    const value = validateListInput(path, false);
    if (!value) return;

    const config = storage.getGlobalConfig();
    const currentList = storage.getNestedValue(config, path) || [];

    if (!currentList.includes(value)) {
        currentList.push(value);
        storage.setNestedValue(config, path, currentList);
        storage.saveGlobalConfig(config);
        showToast('Item added', 'success');
        setState({});
    } else {
        showToast('Item already exists', 'warning');
    }
}

export function removeListItem(path, index) {
    const config = storage.getGlobalConfig();
    const currentList = storage.getNestedValue(config, path) || [];

    if (index >= 0 && index < currentList.length) {
        currentList.splice(index, 1);
        storage.setNestedValue(config, path, currentList);
        storage.saveGlobalConfig(config);
        showToast('Item removed', 'success');
        setState({});
    }
}

export function addListItemToProfile(path) {
    const value = validateListInput(path, true);
    if (!value) return;

    const profileId = state.editingProfileId;
    const profile = storage.getProfile(profileId);
    if (!profile) return;

    ensureProfileOverrideList(profile, path);

    if (!profile.overrides[path].includes(value)) {
        profile.overrides[path].push(value);
        storage.saveProfile(profileId, profile);
        showToast('Item added', 'success');
        setState({});
    } else {
        showToast('Item already exists', 'warning');
    }
}

export function removeListItemFromProfile(path, index) {
    const profileId = state.editingProfileId;
    const profile = storage.getProfile(profileId);
    if (!profile) return;

    ensureProfileOverrideList(profile, path);

    if (index >= 0 && index < profile.overrides[path].length) {
        profile.overrides[path].splice(index, 1);
        storage.saveProfile(profileId, profile);
        showToast('Item removed', 'success');
        setState({});
    }
}
