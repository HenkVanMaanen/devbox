// Validation utilities for form fields and SSH keys

// ============================================================================
// SSH KEY VALIDATION
// ============================================================================

// Supported SSH key type patterns
// These patterns match: <key-type> <key-data> [comment]
// key-data can contain letters, numbers, +, /, =
const SSH_KEY_PATTERNS = {
    'ssh-rsa': /^ssh-rsa\s+\S+/,
    'ssh-ed25519': /^ssh-ed25519\s+\S+/,
    'ecdsa-sha2-nistp256': /^ecdsa-sha2-nistp256\s+\S+/,
    'ecdsa-sha2-nistp384': /^ecdsa-sha2-nistp384\s+\S+/,
    'ecdsa-sha2-nistp521': /^ecdsa-sha2-nistp521\s+\S+/,
    'sk-ssh-ed25519@openssh.com': /^sk-ssh-ed25519@openssh\.com\s+\S+/,
    'sk-ecdsa-sha2-nistp256@openssh.com': /^sk-ecdsa-sha2-nistp256@openssh\.com\s+\S+/
};

// Minimum lengths for key data
// Set very low to just ensure there's some key data present
const MIN_KEY_LENGTHS = {
    'ssh-rsa': 1,
    'ssh-ed25519': 1,
    'ecdsa-sha2-nistp256': 1,
    'ecdsa-sha2-nistp384': 1,
    'ecdsa-sha2-nistp521': 1,
    'sk-ssh-ed25519@openssh.com': 1,
    'sk-ecdsa-sha2-nistp256@openssh.com': 1
};

/**
 * Validate an SSH public key
 * @param {string} pubKey - The SSH public key string
 * @returns {{valid: boolean, type: string|null, error: string|null}}
 */
export function validateSSHKey(pubKey) {
    if (!pubKey || typeof pubKey !== 'string') {
        return { valid: false, type: null, error: 'SSH key is required' };
    }

    const trimmed = pubKey.trim();
    if (trimmed.length === 0) {
        return { valid: false, type: null, error: 'SSH key is required' };
    }

    // Check if it looks like a private key (common mistake)
    if (trimmed.includes('PRIVATE KEY')) {
        return { valid: false, type: null, error: 'This appears to be a private key. Please use the public key (.pub file)' };
    }

    // Check if it looks like an authorized_keys file with multiple keys
    const lines = trimmed.split('\n').filter(l => l.trim().length > 0);
    if (lines.length > 1) {
        return { valid: false, type: null, error: 'Please enter only one SSH key' };
    }

    const key = lines[0].trim();

    // Try to match against known key types
    for (const [type, pattern] of Object.entries(SSH_KEY_PATTERNS)) {
        const match = key.match(pattern);
        if (match) {
            // Extract the base64 data part to check minimum length
            const parts = key.split(/\s+/);
            const keyData = parts[1] || '';

            const minLength = MIN_KEY_LENGTHS[type] || 50;
            if (keyData.length < minLength) {
                return { valid: false, type, error: `SSH key data appears too short for ${type}` };
            }

            return { valid: true, type, error: null };
        }
    }

    // Check if it starts with a known prefix but is malformed
    const knownPrefixes = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-', 'sk-ssh-', 'sk-ecdsa-'];
    const startsWithKnown = knownPrefixes.some(p => key.startsWith(p));

    if (startsWithKnown) {
        return { valid: false, type: null, error: 'SSH key format appears invalid. Please check the key data.' };
    }

    return { valid: false, type: null, error: 'Unrecognized SSH key format. Supported: ssh-rsa, ssh-ed25519, ecdsa, sk-ssh-ed25519, sk-ecdsa' };
}

/**
 * Extract the comment/name from an SSH public key
 * @param {string} pubKey - The SSH public key string
 * @returns {string|null} - The extracted name or null if not found
 */
export function extractSSHKeyName(pubKey) {
    if (!pubKey || typeof pubKey !== 'string') {
        return null;
    }

    const trimmed = pubKey.trim();
    const parts = trimmed.split(/\s+/);

    // SSH key format: type base64data [comment]
    // If there are 3+ parts, everything after the second part is the comment
    if (parts.length >= 3) {
        const comment = parts.slice(2).join(' ').trim();
        if (comment.length > 0 && comment.length <= 100) {
            // Clean up the comment to make it suitable as a name
            // Remove common email-like patterns at the end if there's more text before
            return comment;
        }
    }

    return null;
}

// ============================================================================
// GENERIC FIELD VALIDATION
// ============================================================================

/**
 * Validate a form field based on type
 * @param {string} type - Field type: 'email', 'url', 'number', 'json', 'required'
 * @param {any} value - The value to validate
 * @param {object} options - Additional options (min, max, pattern, etc.)
 * @returns {{valid: boolean, error: string|null}}
 */
export function validateField(type, value, options = {}) {
    const strValue = value === null || value === undefined ? '' : String(value).trim();

    // Check required first
    if (options.required && strValue.length === 0) {
        return { valid: false, error: options.requiredMessage || 'This field is required' };
    }

    // Empty non-required fields are valid
    if (strValue.length === 0) {
        return { valid: true, error: null };
    }

    switch (type) {
        case 'email':
            return validateEmail(strValue);

        case 'url':
            return validateUrl(strValue, options);

        case 'number':
            return validateNumber(value, options);

        case 'json':
            return validateJson(strValue);

        case 'required':
            return strValue.length > 0
                ? { valid: true, error: null }
                : { valid: false, error: options.requiredMessage || 'This field is required' };

        case 'pattern':
            if (options.pattern && !options.pattern.test(strValue)) {
                return { valid: false, error: options.patternMessage || 'Invalid format' };
            }
            return { valid: true, error: null };

        default:
            return { valid: true, error: null };
    }
}

function validateEmail(value) {
    // Basic email validation - allows most valid emails without being overly strict
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(value)) {
        return { valid: false, error: 'Please enter a valid email address' };
    }
    return { valid: true, error: null };
}

function validateUrl(value, options = {}) {
    try {
        const url = new URL(value);
        const allowedProtocols = options.protocols || ['http:', 'https:'];
        if (!allowedProtocols.includes(url.protocol)) {
            return { valid: false, error: `URL must use ${allowedProtocols.join(' or ')}` };
        }
        return { valid: true, error: null };
    } catch {
        return { valid: false, error: 'Please enter a valid URL' };
    }
}

function validateNumber(value, options = {}) {
    const num = Number(value);
    if (Number.isNaN(num)) {
        return { valid: false, error: 'Please enter a valid number' };
    }

    if (options.integer && !Number.isInteger(num)) {
        return { valid: false, error: 'Please enter a whole number' };
    }

    if (options.min !== undefined && num < options.min) {
        return { valid: false, error: `Value must be at least ${options.min}` };
    }

    if (options.max !== undefined && num > options.max) {
        return { valid: false, error: `Value must be at most ${options.max}` };
    }

    return { valid: true, error: null };
}

function validateJson(value) {
    try {
        JSON.parse(value);
        return { valid: true, error: null };
    } catch (e) {
        return { valid: false, error: 'Invalid JSON: ' + e.message };
    }
}

// ============================================================================
// REAL-TIME VALIDATION HELPERS
// ============================================================================

/**
 * Set up real-time validation on an input element
 * @param {HTMLElement} input - The input element
 * @param {string} type - Validation type
 * @param {object} options - Validation options
 * @param {function} onValidate - Callback when validation runs: (valid, error) => void
 */
export function setupFieldValidation(input, type, options = {}, onValidate = null) {
    const validate = () => {
        const result = validateField(type, input.value, options);
        input.classList.toggle('invalid', !result.valid);
        input.classList.toggle('valid', result.valid && input.value.trim().length > 0);

        // Update validation message if container exists
        const messageEl = document.getElementById(`${input.id}-validation`);
        if (messageEl) {
            messageEl.textContent = result.error || '';
            messageEl.classList.toggle('hidden', result.valid);
        }

        if (onValidate) {
            onValidate(result.valid, result.error);
        }

        return result.valid;
    };

    // Validate on blur and on input (with debounce)
    input.addEventListener('blur', validate);

    let timeout;
    input.addEventListener('input', () => {
        clearTimeout(timeout);
        timeout = setTimeout(validate, 300);
    });

    return validate;
}
