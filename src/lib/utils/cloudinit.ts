// Cloud-init YAML generation
// This is a simplified version - the full implementation would mirror web/js/cloudinit.js

import type { GlobalConfig } from '$lib/types';

// Shell escape for safe embedding in scripts
function shellEscape(str: string): string {
  if (!str) return "''";
  if (!/[^a-zA-Z0-9_\-.,/:@]/.test(str)) return str;
  return "'" + str.replace(/'/g, "'\"'\"'") + "'";
}

export function generateCloudInit(
  _serverName: string,
  _hetznerToken: string,
  config: GlobalConfig
): string {
  const lines: string[] = ['#cloud-config', ''];

  // Package updates
  lines.push('package_update: true');
  lines.push('package_upgrade: true');
  lines.push('');

  // Packages
  lines.push('packages:');
  lines.push('  - git');
  lines.push('  - curl');
  lines.push('  - wget');
  lines.push('  - htop');
  lines.push('  - tmux');
  lines.push('  - jq');
  lines.push('');

  // Write files
  lines.push('write_files:');

  // Git config
  if (config.git.userName || config.git.userEmail) {
    lines.push('  - path: /home/dev/.gitconfig');
    lines.push('    owner: dev:dev');
    lines.push('    content: |');
    lines.push('      [user]');
    if (config.git.userName) {
      lines.push(`        name = ${config.git.userName}`);
    }
    if (config.git.userEmail) {
      lines.push(`        email = ${config.git.userEmail}`);
    }
    lines.push('');
  }

  // Git credentials
  if (config.git.credentials.length > 0) {
    lines.push('  - path: /home/dev/.git-credentials');
    lines.push('    owner: dev:dev');
    lines.push('    permissions: "0600"');
    lines.push('    content: |');
    for (const cred of config.git.credentials) {
      lines.push(`      https://${cred.username}:${cred.token}@${cred.host}`);
    }
    lines.push('');
  }

  // Runcmd
  lines.push('runcmd:');

  // Create dev user
  lines.push('  - useradd -m -s /bin/bash -G sudo dev');
  lines.push('  - echo "dev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/dev');
  lines.push('');

  // SSH keys
  if (config.ssh.keys.length > 0) {
    lines.push('  - mkdir -p /home/dev/.ssh');
    lines.push('  - chmod 700 /home/dev/.ssh');
    for (const key of config.ssh.keys) {
      lines.push(`  - echo ${shellEscape(key.pubKey)} >> /home/dev/.ssh/authorized_keys`);
    }
    lines.push('  - chmod 600 /home/dev/.ssh/authorized_keys');
    lines.push('  - chown -R dev:dev /home/dev/.ssh');
    lines.push('');
  }

  // Git credential helper
  if (config.git.credentials.length > 0) {
    lines.push('  - su - dev -c "git config --global credential.helper store"');
  }

  // Install mise for runtime management
  lines.push('  - curl https://mise.run | sh');
  lines.push('  - echo \'eval "$(~/.local/bin/mise activate bash)"\' >> /home/dev/.bashrc');
  lines.push('');

  // Starship prompt
  if (config.shell.starship) {
    lines.push('  - curl -sS https://starship.rs/install.sh | sh -s -- -y');
    lines.push('  - echo \'eval "$(starship init bash)"\' >> /home/dev/.bashrc');
    lines.push('');
  }

  // Claude API key
  if (config.claude.apiKey) {
    lines.push(`  - echo "export ANTHROPIC_API_KEY=${shellEscape(config.claude.apiKey)}" >> /home/dev/.bashrc`);
    lines.push('');
  }

  // Fix ownership
  lines.push('  - chown -R dev:dev /home/dev');

  return lines.join('\n');
}
