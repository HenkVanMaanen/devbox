import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import perfectionist from 'eslint-plugin-perfectionist';
import security from 'eslint-plugin-security';
import svelte from 'eslint-plugin-svelte';
import unicorn from 'eslint-plugin-unicorn';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Global ignores
  {
    ignores: [
      '.stryker-tmp/**',
      'coverage/**',
      'dist/**',
      'node_modules/**',
      '**/*.test.mjs',
      '**/*.test.ts',
      'vitest.config.ts',
      'CHANGELOG.md',
      'commitlint.config.js',
      'svelte.config.js',
      'eslint.config.js',
    ],
  },

  // Base JS recommended
  js.configs.recommended,

  // TypeScript strict + stylistic (type-checked)
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  // TypeScript parser options
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        __APP_VERSION__: 'readonly',
      },
      parserOptions: {
        extraFileExtensions: ['.svelte'],
        projectService: {
          allowDefaultProject: ['eslint.config.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // Svelte
  ...svelte.configs['flat/recommended'],
  {
    files: ['**/*.svelte', '**/*.svelte.ts'],
    languageOptions: {
      parserOptions: {
        parser: tseslint.parser,
      },
    },
  },

  // Security plugin
  security.configs.recommended,

  // No-unsanitized plugin
  noUnsanitized.configs.recommended,

  // Unicorn plugin
  unicorn.configs['flat/recommended'],

  // Perfectionist plugin (import/member sorting)
  perfectionist.configs['recommended-natural'],

  // Project-wide strict rules
  {
    rules: {
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { fixStyle: 'inline-type-imports', prefer: 'type-imports' },
      ],
      // TypeScript strict
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/no-unnecessary-condition': ['error', { allowConstantLoopConditions: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/restrict-template-expressions': ['error', { allowBoolean: true, allowNumber: true }],

      curly: ['error', 'all'],
      // General strict
      eqeqeq: ['error', 'always'],
      'no-console': ['warn', { allow: ['warn', 'error'] }],

      // Perfectionist overrides
      'perfectionist/sort-imports': [
        'error',
        {
          internalPattern: [String.raw`^\$lib/`, String.raw`^\$components/`, String.raw`^\$pages/`],
          type: 'natural',
        },
      ],
      'security/detect-non-literal-regexp': 'off', // Used legitimately
      // Security overrides for legitimate patterns
      'security/detect-object-injection': 'off', // Too many false positives
      'unicorn/consistent-function-scoping': 'off', // Svelte components have nested functions in $effect
      // Unicorn overrides (disable rules that conflict with project style)
      'unicorn/filename-case': 'off', // Svelte uses PascalCase
      'unicorn/import-style': 'off', // Conflicts with perfectionist
      'unicorn/no-array-for-each': 'off', // forEach is fine
      'unicorn/no-array-push-push': 'off', // Pushing in sequence is readable for cloud-init builders
      'unicorn/prefer-single-call': 'off', // Same as above (renamed rule)
      'unicorn/no-array-reduce': 'off', // Reduce is fine
      'unicorn/no-negated-condition': 'off', // Sometimes clearer
      'unicorn/no-null': 'off', // null is used extensively with localStorage
      'unicorn/prefer-global-this': 'off', // window/document are fine in browser
      'unicorn/prefer-module': 'off', // Not applicable to all files

      'unicorn/prefer-top-level-await': 'off', // Not applicable in Svelte

      'unicorn/prevent-abbreviations': 'off', // Too aggressive
      'unicorn/switch-case-braces': 'off', // Style preference
    },
  },

  // Svelte-specific rules
  {
    files: ['**/*.svelte'],
    rules: {
      '@typescript-eslint/no-unsafe-argument': 'off',
      // Disable rules that don't apply in Svelte templates
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      'svelte/button-has-type': 'error',

      'svelte/no-at-html-tags': 'error',
      'svelte/no-dom-manipulating': 'warn',
      'svelte/no-reactive-reassign': 'error',
      'svelte/no-store-async': 'error',
      'svelte/require-each-key': 'error',
      'unicorn/no-keyword-prefix': 'off',
    },
  },

  // Vite config (Node.js environment)
  {
    files: ['vite.config.ts'],
    languageOptions: {
      globals: globals.node,
    },
    rules: {
      'no-console': 'off',
      'unicorn/prefer-module': 'off',
    },
  },

  // ESLint config file
  {
    files: ['eslint.config.js'],
    languageOptions: {
      globals: globals.node,
    },
  },

  // Prettier must be last
  prettier,
);
