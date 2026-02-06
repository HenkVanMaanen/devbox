// Storage module - localStorage wrapper for devbox config, profiles, and credentials

const KEYS = {
    GLOBAL_CONFIG: 'devbox:global',
    PROFILES: 'devbox:profiles',
    DEFAULT_PROFILE: 'devbox:default-profile',
    HETZNER_TOKEN: 'devbox:hetzner-token',
    THEME: 'devbox:theme',
    SERVER_TOKENS: 'devbox:server-tokens'
};

// Default global configuration
const DEFAULT_GLOBAL_CONFIG = {
    ssh: {
        keys: []  // Array of { name: string, pubKey: string }
    },
    git: {
        userName: '',
        userEmail: '',
        credentials: []
    },
    hetzner: {
        location: 'fsn1',
        serverType: 'cpx21',
        baseImage: 'ubuntu-24.04'
    },
    packages: {
        apt: ['build-essential', 'jq', 'ripgrep', 'fd-find', 'tree', 'unzip', 'sqlite3', 'htop', 'tmux', 'fzf', 'bat'],
        mise: ['python@latest']
    },
    shell: {
        default: 'fish',
        starship: true
    },
    services: {
        dnsService: 'sslip.io',
        codeServer: true,
        shellTerminal: true,
        acmeProvider: 'zerossl',
        acmeEmail: '',
        zerosslEabKeyId: '',
        zerosslEabKey: '',
        actalisEabKeyId: '',
        actalisEabKey: '',
        customAcmeUrl: '',
        customEabKeyId: '',
        customEabKey: ''
    },
    autoDelete: {
        enabled: true,
        timeoutMinutes: 90,
        warningMinutes: 5
    },
    claude: {
        apiKey: '',
        credentialsJson: null,
        theme: '',
        settings: '',
        skipPermissions: true
    },
    repos: [],
    envVars: []
};

// Default profiles
const DEFAULT_PROFILES = {
    'default': {
        name: 'Default',
        overrides: {}
    }
};

// ============================================================================
// GLOBAL CONFIG FUNCTIONS
// ============================================================================

export function getGlobalConfig() {
    const stored = localStorage.getItem(KEYS.GLOBAL_CONFIG);
    let config = {};
    if (stored) {
        try { config = JSON.parse(stored); } catch { /* corrupted data, use defaults */ }
    }
    return deepMerge(DEFAULT_GLOBAL_CONFIG, config);
}

export function saveGlobalConfig(config) {
    localStorage.setItem(KEYS.GLOBAL_CONFIG, JSON.stringify(config));
}

// ============================================================================
// PROFILE FUNCTIONS
// ============================================================================

export function getProfiles() {
    const stored = localStorage.getItem(KEYS.PROFILES);
    if (stored) {
        try { return JSON.parse(stored); } catch { /* corrupted data, use defaults */ }
    }
    return { ...DEFAULT_PROFILES };
}

export function saveProfiles(profiles) {
    localStorage.setItem(KEYS.PROFILES, JSON.stringify(profiles));
}

export function getDefaultProfileId() {
    return localStorage.getItem(KEYS.DEFAULT_PROFILE) || 'default';
}

export function setDefaultProfileId(id) {
    localStorage.setItem(KEYS.DEFAULT_PROFILE, id);
}

export function getProfile(id) {
    const profiles = getProfiles();
    return profiles[id] || null;
}

export function saveProfile(id, profile) {
    const profiles = getProfiles();
    profiles[id] = profile;
    saveProfiles(profiles);
}

export function createProfile(name) {
    const profiles = getProfiles();
    let id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    if (!id) id = 'profile';

    // Ensure unique id
    let uniqueId = id;
    let counter = 1;
    while (profiles[uniqueId]) {
        uniqueId = `${id}-${counter}`;
        counter++;
    }

    profiles[uniqueId] = {
        name: name,
        overrides: {}
    };
    saveProfiles(profiles);
    return uniqueId;
}

export function deleteProfile(id) {
    if (id === 'default') return false; // Can't delete default

    const profiles = getProfiles();
    if (!profiles[id]) return false;

    delete profiles[id];
    saveProfiles(profiles);

    // If deleted profile was the default, reset to 'default'
    if (getDefaultProfileId() === id) {
        setDefaultProfileId('default');
    }

    return true;
}

export function duplicateProfile(fromId, newName) {
    const profiles = getProfiles();
    const source = profiles[fromId];
    if (!source) return null;

    const newId = createProfile(newName);
    const newProfiles = getProfiles();
    newProfiles[newId].overrides = JSON.parse(JSON.stringify(source.overrides));
    saveProfiles(newProfiles);
    return newId;
}

// ============================================================================
// CONFIG MERGING
// ============================================================================

// Get value from nested object using dot notation path
export function getNestedValue(obj, path) {
    return path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : undefined, obj);
}

// Set value in nested object using dot notation path
export function setNestedValue(obj, path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((o, k) => {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') return {};
        if (!o[k]) o[k] = {};
        return o[k];
    }, obj);
    if (lastKey === '__proto__' || lastKey === 'constructor' || lastKey === 'prototype') return;
    target[lastKey] = value;
}

// Generate access token for a server
function generateAccessToken() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Get merged config for a profile (global + overrides)
export function getConfigForProfile(profileId) {
    const globalConfig = getGlobalConfig();
    const profile = getProfile(profileId);

    if (!profile) {
        return { ...globalConfig, services: { ...globalConfig.services, accessToken: generateAccessToken() } };
    }

    // Start with deep copy of global
    const merged = JSON.parse(JSON.stringify(globalConfig));

    // Apply overrides
    for (const [path, value] of Object.entries(profile.overrides)) {
        setNestedValue(merged, path, value);
    }

    // Always generate fresh access token per server
    merged.services.accessToken = generateAccessToken();

    return merged;
}

// Returns merged config for the default profile (global + profile overrides)
export function getDefaultProfileConfig() {
    return getConfigForProfile(getDefaultProfileId());
}

// ============================================================================
// HETZNER TOKEN
// ============================================================================

export function getHetznerToken() {
    return localStorage.getItem(KEYS.HETZNER_TOKEN) || '';
}

export function saveHetznerToken(token) {
    if (token) {
        localStorage.setItem(KEYS.HETZNER_TOKEN, token);
    } else {
        localStorage.removeItem(KEYS.HETZNER_TOKEN);
    }
}

// ============================================================================
// THEME
// ============================================================================

export function getTheme() {
    return localStorage.getItem(KEYS.THEME) || 'system';
}

export function saveTheme(themeId) {
    if (themeId === 'system') {
        localStorage.removeItem(KEYS.THEME);
    } else {
        localStorage.setItem(KEYS.THEME, themeId);
    }
}

// ============================================================================
// SERVER ACCESS TOKENS (stored locally, not in Hetzner labels)
// ============================================================================

export function getServerTokens() {
    const stored = localStorage.getItem(KEYS.SERVER_TOKENS);
    if (stored) {
        try { return JSON.parse(stored); } catch { /* corrupted */ }
    }
    return {};
}

export function saveServerToken(serverName, token) {
    const tokens = getServerTokens();
    tokens[serverName] = token;
    localStorage.setItem(KEYS.SERVER_TOKENS, JSON.stringify(tokens));
}

export function getServerToken(serverName) {
    const tokens = getServerTokens();
    return tokens[serverName] || null;
}

export function removeServerToken(serverName) {
    const tokens = getServerTokens();
    delete tokens[serverName];
    localStorage.setItem(KEYS.SERVER_TOKENS, JSON.stringify(tokens));
}

// ============================================================================
// UTILITIES
// ============================================================================

export function clearAll() {
    localStorage.removeItem(KEYS.GLOBAL_CONFIG);
    localStorage.removeItem(KEYS.PROFILES);
    localStorage.removeItem(KEYS.DEFAULT_PROFILE);
    localStorage.removeItem(KEYS.HETZNER_TOKEN);
    localStorage.removeItem(KEYS.THEME);
    localStorage.removeItem(KEYS.SERVER_TOKENS);
    // Also clear old config key
    localStorage.removeItem('devbox:config');
}

export function exportAll() {
    return {
        globalConfig: getGlobalConfig(),
        profiles: getProfiles(),
        defaultProfile: getDefaultProfileId(),
        hetznerToken: getHetznerToken(),
        theme: getTheme(),
        serverTokens: getServerTokens()
    };
}

export function importAll(data) {
    if (data.globalConfig) {
        saveGlobalConfig(data.globalConfig);
    }
    if (data.profiles) {
        saveProfiles(data.profiles);
    }
    if (data.defaultProfile) {
        setDefaultProfileId(data.defaultProfile);
    }
    if ('hetznerToken' in data) {
        saveHetznerToken(data.hetznerToken);
    }
    if (data.theme) {
        saveTheme(data.theme);
    }
    if (data.serverTokens) {
        localStorage.setItem(KEYS.SERVER_TOKENS, JSON.stringify(data.serverTokens));
    }
}

// Deep merge helper
function deepMerge(target, source) {
    const result = { ...target };
    for (const key of Object.keys(source)) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            result[key] = deepMerge(target[key] || {}, source[key]);
        } else if (source[key] !== undefined) {
            result[key] = source[key];
        }
    }
    return result;
}
