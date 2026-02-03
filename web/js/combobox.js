// Multi-select and single-select combobox component

import { escapeHtml, escapeAttr } from './ui.js';

// Single-select searchable dropdown
export function renderSelectCombobox(id, options, selectedValue, placeholder) {
    const selectedOpt = options.find(o => o.value === selectedValue);
    const displayText = selectedOpt?.label || placeholder;

    const optionsHtml = options.map(opt => `
        <div class="combobox-option ${opt.value === selectedValue ? 'selected' : ''} ${opt.disabled ? 'disabled' : ''}"
             data-combobox="${id}" data-value="${escapeAttr(String(opt.value))}" data-label="${escapeAttr(opt.label)}" data-single-select ${opt.disabled ? 'data-disabled' : ''} title="${escapeAttr(opt.description || '')}">
            <span>${escapeHtml(opt.label)}</span>
            ${opt.value === selectedValue ? '<span class="combobox-option-check">\u2713</span>' : ''}
        </div>
    `).join('');

    return `
        <div class="combobox combobox-single" data-combobox-id="${id}">
            <div class="combobox-trigger combobox-trigger-single" data-combobox="${id}" data-trigger-single>
                <input type="text" class="combobox-input combobox-input-single"
                       placeholder="${escapeAttr(displayText)}"
                       data-combobox="${id}" data-search-single data-selected="${escapeAttr(String(selectedValue))}" autocomplete="off">
                <svg class="combobox-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="combobox-dropdown" data-combobox="${id}" data-dropdown>
                ${optionsHtml}
                <div class="combobox-empty" style="display: none;">No results found</div>
            </div>
        </div>
    `;
}

// Multi-select combobox with tags
export function renderCombobox(id, options, selected, placeholder, grouped = false) {
    const selectedSet = new Set(selected);
    const tags = selected.map(val => {
        const opt = options.find(o => o.value === val);
        return `<span class="combobox-tag">
            ${escapeHtml(opt?.label || val)}
            <span class="combobox-tag-remove" data-combobox="${id}" data-remove="${escapeAttr(val)}">&times;</span>
        </span>`;
    }).join('');

    let optionsHtml;
    if (grouped) {
        const groups = {};
        options.forEach(opt => {
            const group = opt.group || 'Other';
            if (!groups[group]) groups[group] = [];
            groups[group].push(opt);
        });
        optionsHtml = Object.entries(groups).map(([group, opts]) => `
            <div class="combobox-group" data-group="${escapeAttr(group)}">
                <div class="combobox-group-label">${escapeHtml(group)}</div>
                ${opts.map(opt => `
                    <div class="combobox-option ${selectedSet.has(opt.value) ? 'selected' : ''}"
                         data-combobox="${id}" data-value="${escapeAttr(opt.value)}" data-label="${escapeAttr(opt.label)}" title="${escapeAttr(opt.description || '')}">
                        <span>${escapeHtml(opt.label)}</span>
                        ${selectedSet.has(opt.value) ? '<span class="combobox-option-check">\u2713</span>' : ''}
                    </div>
                `).join('')}
            </div>
        `).join('');
    } else {
        optionsHtml = options.map(opt => `
            <div class="combobox-option ${selectedSet.has(opt.value) ? 'selected' : ''}"
                 data-combobox="${id}" data-value="${escapeAttr(opt.value)}" data-label="${escapeAttr(opt.label)}" title="${escapeAttr(opt.description || '')}">
                <span>${escapeHtml(opt.label)}${opt.version ? ` <span class="text-muted-foreground">(${escapeHtml(opt.version)})</span>` : ''}</span>
                ${selectedSet.has(opt.value) ? '<span class="combobox-option-check">\u2713</span>' : ''}
            </div>
        `).join('');
    }

    return `
        <div class="combobox" data-combobox-id="${id}">
            <div class="combobox-trigger" data-combobox="${id}" data-trigger>
                ${tags}
                <input type="text" class="combobox-input" placeholder="${selected.length ? '' : escapeAttr(placeholder)}"
                       data-combobox="${id}" data-search autocomplete="off">
                <svg class="combobox-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="combobox-dropdown" data-combobox="${id}" data-dropdown>
                ${optionsHtml}
                <div class="combobox-empty" style="display: none;">No results found</div>
            </div>
        </div>
    `;
}

// Initialize combobox event handling using event delegation (called once)
let initialized = false;

export function initComboboxes() {
    if (initialized) return;
    initialized = true;

    // Use event delegation on document for all combobox interactions
    document.addEventListener('click', handleClick);
    document.addEventListener('input', handleInput);
    document.addEventListener('focus', handleFocus, true);
    document.addEventListener('blur', handleBlur, true);
}

function handleClick(e) {
    const target = e.target;

    // Tag removal
    const removeBtn = target.closest('[data-remove]');
    if (removeBtn) {
        e.stopPropagation();
        const id = removeBtn.dataset.combobox;
        const value = removeBtn.dataset.remove;
        window.devbox.toggleComboboxValue(id, value, false);
        return;
    }

    // Single-select option click
    const singleOption = target.closest('.combobox-option[data-single-select]');
    if (singleOption) {
        if (singleOption.dataset.disabled !== undefined) return;
        const id = singleOption.dataset.combobox;
        const value = singleOption.dataset.value;
        const label = singleOption.dataset.label;
        window.devbox.selectComboboxValue(id, value, label);
        return;
    }

    // Multi-select option click
    const multiOption = target.closest('.combobox-option:not([data-single-select])');
    if (multiOption && multiOption.closest('.combobox-dropdown')) {
        const id = multiOption.dataset.combobox;
        const value = multiOption.dataset.value;
        window.devbox.toggleComboboxValue(id, value);
        return;
    }

    // Trigger click (multi-select)
    const trigger = target.closest('[data-trigger]:not([data-trigger-single])');
    if (trigger) {
        const id = trigger.dataset.combobox;
        const dropdown = document.querySelector(`[data-combobox="${id}"][data-dropdown]`);
        if (target.closest('.combobox-chevron')) {
            dropdown.classList.toggle('open');
        } else {
            dropdown.classList.add('open');
        }
        trigger.querySelector('input')?.focus();
        return;
    }

    // Trigger click (single-select)
    const triggerSingle = target.closest('[data-trigger-single]');
    if (triggerSingle) {
        const id = triggerSingle.dataset.combobox;
        const dropdown = document.querySelector(`[data-combobox="${id}"][data-dropdown]`);
        if (target.closest('.combobox-chevron')) {
            dropdown.classList.toggle('open');
        } else {
            dropdown.classList.add('open');
        }
        triggerSingle.querySelector('input')?.focus();
        return;
    }

    // Close dropdowns on outside click
    if (!target.closest('.combobox')) {
        document.querySelectorAll('.combobox-dropdown').forEach(d => d.classList.remove('open'));
    }
}

function filterDropdown(input, isSingle) {
    const id = input.dataset.combobox;
    const dropdown = document.querySelector(`[data-combobox="${id}"][data-dropdown]`);
    if (!dropdown) return;

    const query = input.value.toLowerCase();
    let hasResults = false;

    dropdown.querySelectorAll('.combobox-option').forEach(opt => {
        const label = opt.dataset.label.toLowerCase();
        const matches = label.includes(query);
        opt.style.display = matches ? '' : 'none';
        if (matches) hasResults = true;
    });

    if (!isSingle) {
        dropdown.querySelectorAll('.combobox-group').forEach(group => {
            const hasVisible = Array.from(group.querySelectorAll('.combobox-option'))
                .some(opt => opt.style.display !== 'none');
            group.style.display = hasVisible ? '' : 'none';
        });
    }

    dropdown.querySelector('.combobox-empty').style.display = hasResults ? 'none' : '';
    dropdown.classList.add('open');
}

function handleInput(e) {
    const target = e.target;
    if (!target.matches) return;

    if (target.matches('[data-search]')) {
        filterDropdown(target, false);
    } else if (target.matches('[data-search-single]')) {
        filterDropdown(target, true);
    }
}

function handleFocus(e) {
    const target = e.target;
    if (!target.matches) return;

    if (target.matches('[data-search]')) {
        const id = target.dataset.combobox;
        const dropdown = document.querySelector(`[data-combobox="${id}"][data-dropdown]`);
        if (dropdown) dropdown.classList.add('open');
    } else if (target.matches('[data-search-single]')) {
        const id = target.dataset.combobox;
        const dropdown = document.querySelector(`[data-combobox="${id}"][data-dropdown]`);
        if (dropdown) {
            target.value = '';
            dropdown.classList.add('open');
            dropdown.querySelectorAll('.combobox-option').forEach(opt => {
                opt.style.display = '';
            });
            dropdown.querySelector('.combobox-empty').style.display = 'none';
        }
    }
}

function handleBlur(e) {
    const target = e.target;
    if (!target.matches) return;

    if (target.matches('[data-search-single]')) {
        setTimeout(() => {
            if (!document.body.contains(target)) return;
            const id = target.dataset.combobox;
            const dropdown = document.querySelector(`[data-combobox="${id}"][data-dropdown]`);
            if (dropdown && !dropdown.matches(':hover')) {
                dropdown.classList.remove('open');
                const selectedOpt = dropdown.querySelector('.combobox-option.selected');
                if (selectedOpt) {
                    target.placeholder = selectedOpt.dataset.label;
                }
                target.value = '';
            }
        }, 200);
    }
}
