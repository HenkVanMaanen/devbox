// Form dirty tracking - detect unsaved changes

// Store for captured form states
const formStates = new Map();

/**
 * Capture the current state of all form elements within a container
 * @param {string} containerId - ID of the container element
 * @returns {boolean} - Whether the state was captured successfully
 */
export function captureFormState(containerId) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.warn(`captureFormState: Container ${containerId} not found`);
        return false;
    }

    const state = {};
    const inputs = container.querySelectorAll('input, textarea, select');

    inputs.forEach(input => {
        if (!input.id) return;

        if (input.type === 'checkbox' || input.type === 'radio') {
            state[input.id] = input.checked;
        } else {
            state[input.id] = input.value;
        }
    });

    formStates.set(containerId, state);
    return true;
}

/**
 * Check if the form has changed from its captured state
 * @param {string} containerId - ID of the container element
 * @returns {boolean} - Whether the form is dirty (has changes)
 */
export function isFormDirty(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return false;

    const savedState = formStates.get(containerId);
    if (!savedState) return false;

    const inputs = container.querySelectorAll('input, textarea, select');

    for (const input of inputs) {
        if (!input.id) continue;

        const savedValue = savedState[input.id];
        if (savedValue === undefined) {
            // New field that wasn't captured - check if it has a value
            if (input.type === 'checkbox' || input.type === 'radio') {
                if (input.checked) return true;
            } else {
                if (input.value.trim() !== '') return true;
            }
            continue;
        }

        if (input.type === 'checkbox' || input.type === 'radio') {
            if (input.checked !== savedValue) return true;
        } else {
            if (input.value !== savedValue) return true;
        }
    }

    return false;
}

/**
 * Clear the captured state for a container
 * @param {string} containerId - ID of the container element
 */
export function clearFormState(containerId) {
    formStates.delete(containerId);
}

/**
 * Revert the form to its captured state
 * @param {string} containerId - ID of the container element
 * @returns {boolean} - Whether the revert was successful
 */
export function revertForm(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return false;

    const savedState = formStates.get(containerId);
    if (!savedState) return false;

    const inputs = container.querySelectorAll('input, textarea, select');

    inputs.forEach(input => {
        if (!input.id) return;
        // Skip file inputs - they can't be reverted and dispatching events triggers file picker
        if (input.type === 'file') return;

        const savedValue = savedState[input.id];
        if (savedValue === undefined) return;

        if (input.type === 'checkbox' || input.type === 'radio') {
            input.checked = savedValue;
        } else {
            input.value = savedValue;
        }

        // Trigger change event so any listeners can react
        input.dispatchEvent(new Event('change', { bubbles: true }));
    });

    return true;
}

/**
 * Get a list of changed fields
 * @param {string} containerId - ID of the container element
 * @returns {Array<{id: string, oldValue: any, newValue: any}>} - List of changed fields
 */
export function getChangedFields(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return [];

    const savedState = formStates.get(containerId);
    if (!savedState) return [];

    const changes = [];
    const inputs = container.querySelectorAll('input, textarea, select');

    inputs.forEach(input => {
        if (!input.id) return;

        const savedValue = savedState[input.id];
        let currentValue;

        if (input.type === 'checkbox' || input.type === 'radio') {
            currentValue = input.checked;
        } else {
            currentValue = input.value;
        }

        if (savedValue !== undefined && currentValue !== savedValue) {
            changes.push({
                id: input.id,
                oldValue: savedValue,
                newValue: currentValue
            });
        }
    });

    return changes;
}

/**
 * Check if any tracked form has unsaved changes
 * @returns {boolean} - Whether any form is dirty
 */
export function hasAnyDirtyForm() {
    for (const containerId of formStates.keys()) {
        if (isFormDirty(containerId)) {
            return true;
        }
    }
    return false;
}

/**
 * Clear all captured form states
 */
export function clearAllFormStates() {
    formStates.clear();
}
