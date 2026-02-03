// Application state, router, toast notifications, and modal dialogs

// ============================================================================
// APPLICATION STATE
// ============================================================================

export const state = {
    page: 'dashboard',
    servers: [],
    loading: false,
    error: null,
    creating: false,
    createProgress: '',
    serverTypes: [],
    locations: [],
    images: [],
    loadingHetznerOptions: false,
    hetznerOptionsError: false,
    selectedProfileId: null,
    editingProfileId: null,
    editingListItem: null,  // { field: 'git.credentials', index: 2, isProfile: false }
    formDirty: false,
    currentFormContainer: null
};

let renderCallback = null;

export function setRenderCallback(fn) {
    renderCallback = fn;
}

export function setState(updates) {
    Object.assign(state, updates);
    if (renderCallback) renderCallback();
}

// ============================================================================
// ROUTER
// ============================================================================

export function router() {
    const hash = window.location.hash.slice(1) || 'dashboard';
    const page = hash.split('/')[0];
    setState({ page, error: null });
    updateNavLinks();
}

export function updateNavLinks() {
    document.querySelectorAll('[data-nav]').forEach(link => {
        const navPage = link.dataset.nav;
        const isActive = navPage === state.page ||
            (navPage === 'profiles' && state.page === 'profile-edit');
        link.classList.toggle('bg-muted', isActive);
        link.classList.toggle('text-foreground', isActive);
    });
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================

export function showToast(message, type = 'info') {
    const container = document.getElementById('toasts');
    if (!container) return;

    const colors = {
        info: 'bg-card text-foreground',
        success: 'bg-success/10 text-success',
        error: 'bg-destructive/10 text-destructive',
        warning: 'bg-warning/10 text-warning'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${colors[type] || colors.info}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.2s ease-out';
        setTimeout(() => toast.remove(), 200);
    }, 3000);
}

// ============================================================================
// MODAL DIALOGS
// ============================================================================

export function showConfirm(title, message, confirmText = 'Confirm') {
    return new Promise((resolve) => {
        const modal = document.getElementById('modal');
        const titleEl = document.getElementById('modal-title');
        const messageEl = document.getElementById('modal-message');
        const confirmBtn = document.getElementById('modal-confirm');
        const cancelBtn = document.getElementById('modal-cancel');

        if (!modal || !titleEl || !messageEl || !confirmBtn || !cancelBtn) {
            resolve(false);
            return;
        }

        titleEl.textContent = title;
        messageEl.textContent = message;
        confirmBtn.textContent = confirmText;
        modal.classList.remove('hidden');

        const cleanup = () => {
            modal.classList.add('hidden');
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn.removeEventListener('click', onCancel);
            modal.removeEventListener('click', onBackdrop);
        };

        const onConfirm = () => { cleanup(); resolve(true); };
        const onCancel = () => { cleanup(); resolve(false); };
        const onBackdrop = (e) => { if (e.target === modal) { cleanup(); resolve(false); } };

        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn.addEventListener('click', onCancel);
        modal.addEventListener('click', onBackdrop);
    });
}

export function showPrompt(title, defaultValue = '') {
    return new Promise((resolve) => {
        const modal = document.getElementById('prompt-modal');
        const titleEl = document.getElementById('prompt-title');
        const input = document.getElementById('prompt-input');
        const confirmBtn = document.getElementById('prompt-confirm');
        const cancelBtn = document.getElementById('prompt-cancel');

        if (!modal || !titleEl || !input || !confirmBtn || !cancelBtn) {
            resolve(null);
            return;
        }

        titleEl.textContent = title;
        input.value = defaultValue;
        modal.classList.remove('hidden');
        input.focus();
        input.select();

        const cleanup = () => {
            modal.classList.add('hidden');
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn.removeEventListener('click', onCancel);
            modal.removeEventListener('click', onBackdrop);
            input.removeEventListener('keydown', onKeydown);
        };

        const onConfirm = () => { cleanup(); resolve(input.value.trim()); };
        const onCancel = () => { cleanup(); resolve(null); };
        const onBackdrop = (e) => { if (e.target === modal) { cleanup(); resolve(null); } };
        const onKeydown = (e) => {
            if (e.key === 'Enter') { onConfirm(); }
            if (e.key === 'Escape') { onCancel(); }
        };

        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn.addEventListener('click', onCancel);
        modal.addEventListener('click', onBackdrop);
        input.addEventListener('keydown', onKeydown);
    });
}
