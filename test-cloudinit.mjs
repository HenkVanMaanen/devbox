#!/usr/bin/env node
// Generates a sample cloud-init YAML for schema validation and LXD testing

import { generate } from './web/js/cloudinit.js';
import { THEMES } from './web/js/themes.js';

const config = {
    hetzner: {
        serverType: 'cpx21',
        baseImage: 'debian-12',
        location: 'fsn1'
    },
    packages: {
        apt: ['git', 'curl', 'wget', 'unzip', 'build-essential', 'tmux'],
        mise: ['node@22']
    },
    shell: {
        default: 'bash',
        starship: true
    },
    git: {
        userName: 'Test User',
        userEmail: 'test@example.com'
    },
    claude: {
        apiKey: '',
        credentialsJson: null,
        theme: null,
        settings: null
    },
    services: {
        codeServer: true,
        claudeTerminal: true,
        shellTerminal: true,
        dnsService: 'sslip.io',
        accessToken: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
        acmeProvider: 'letsencrypt',
        acmeEmail: 'test@example.com'
    },
    autoDelete: {
        enabled: true,
        timeoutMinutes: 60,
        warningMinutes: 5
    },
    repos: ['https://github.com/example/test-repo.git']
};

const options = {
    gitCredentials: [{ host: 'github.com', username: 'testuser', token: 'ghp_test123' }],
    sshKeys: [{ name: 'test-key', pubKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyHere test@devbox' }],
    themeColors: THEMES[0].colors
};

const yaml = generate('devbox', 'test-hetzner-token', config, options);
process.stdout.write(yaml);
