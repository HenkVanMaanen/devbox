// Curated package lists for devbox

// Apt package categories order
export const APT_CATEGORIES = [
    'build',
    'vcs',
    'network',
    'editors',
    'utilities',
    'python',
    'database',
    'media',
    'shells'
];

// Category labels
export const APT_CATEGORY_LABELS = {
    build: 'Build Tools',
    vcs: 'Version Control',
    network: 'Networking',
    editors: 'Editors',
    utilities: 'Utilities',
    python: 'Python',
    database: 'Database Clients',
    media: 'Media',
    shells: 'Shells'
};

// Curated apt packages
export const APT_PACKAGES = [
    // Build Tools
    { name: 'build-essential', category: 'build', description: 'Essential build tools (gcc, g++, make)' },
    { name: 'gcc', category: 'build', description: 'GNU C compiler' },
    { name: 'g++', category: 'build', description: 'GNU C++ compiler' },
    { name: 'make', category: 'build', description: 'Build automation tool' },
    { name: 'cmake', category: 'build', description: 'Cross-platform build system' },
    { name: 'pkg-config', category: 'build', description: 'Manage compile and link flags' },
    { name: 'autoconf', category: 'build', description: 'Automatic configure script builder' },
    { name: 'automake', category: 'build', description: 'Makefile generator' },
    { name: 'libtool', category: 'build', description: 'Generic library support script' },
    { name: 'ninja-build', category: 'build', description: 'Small build system with focus on speed' },
    { name: 'meson', category: 'build', description: 'High performance build system' },
    { name: 'clang', category: 'build', description: 'C/C++/Objective-C compiler' },
    { name: 'llvm', category: 'build', description: 'LLVM compiler infrastructure' },

    // Version Control
    { name: 'git', category: 'vcs', description: 'Fast distributed version control' },
    { name: 'git-lfs', category: 'vcs', description: 'Git extension for large files' },
    { name: 'git-flow', category: 'vcs', description: 'Git branching model extensions' },
    { name: 'tig', category: 'vcs', description: 'Text-mode interface for Git' },
    { name: 'subversion', category: 'vcs', description: 'Centralized version control' },
    { name: 'mercurial', category: 'vcs', description: 'Distributed version control' },

    // Networking
    { name: 'curl', category: 'network', description: 'Transfer data with URLs' },
    { name: 'wget', category: 'network', description: 'Network file retriever' },
    { name: 'openssh-client', category: 'network', description: 'SSH client' },
    { name: 'openssh-server', category: 'network', description: 'SSH server' },
    { name: 'rsync', category: 'network', description: 'Fast file synchronization' },
    { name: 'mosh', category: 'network', description: 'Mobile shell with roaming support' },
    { name: 'netcat-openbsd', category: 'network', description: 'TCP/IP swiss army knife' },
    { name: 'socat', category: 'network', description: 'Multipurpose relay for bidirectional data' },
    { name: 'nmap', category: 'network', description: 'Network exploration and security scanner' },
    { name: 'dnsutils', category: 'network', description: 'DNS utilities (dig, nslookup)' },
    { name: 'iproute2', category: 'network', description: 'Networking utilities (ip, ss)' },
    { name: 'net-tools', category: 'network', description: 'Classic networking tools (ifconfig, netstat)' },
    { name: 'httpie', category: 'network', description: 'User-friendly HTTP client' },
    { name: 'aria2', category: 'network', description: 'Multi-protocol download utility' },

    // Editors
    { name: 'vim', category: 'editors', description: 'Vi improved text editor' },
    { name: 'neovim', category: 'editors', description: 'Modern vim fork' },
    { name: 'nano', category: 'editors', description: 'Simple text editor' },
    { name: 'emacs', category: 'editors', description: 'Extensible text editor' },
    { name: 'micro', category: 'editors', description: 'Modern terminal-based text editor' },
    { name: 'helix', category: 'editors', description: 'Post-modern modal text editor' },

    // Utilities
    { name: 'htop', category: 'utilities', description: 'Interactive process viewer' },
    { name: 'btop', category: 'utilities', description: 'Resource monitor with graphs' },
    { name: 'tmux', category: 'utilities', description: 'Terminal multiplexer' },
    { name: 'screen', category: 'utilities', description: 'Terminal multiplexer' },
    { name: 'jq', category: 'utilities', description: 'JSON processor' },
    { name: 'yq', category: 'utilities', description: 'YAML processor' },
    { name: 'tree', category: 'utilities', description: 'Directory listing in tree format' },
    { name: 'fzf', category: 'utilities', description: 'Fuzzy finder' },
    { name: 'ripgrep', category: 'utilities', description: 'Fast grep alternative' },
    { name: 'fd-find', category: 'utilities', description: 'Fast find alternative' },
    { name: 'bat', category: 'utilities', description: 'Cat with syntax highlighting' },
    { name: 'eza', category: 'utilities', description: 'Modern ls replacement' },
    { name: 'ncdu', category: 'utilities', description: 'Disk usage analyzer' },
    { name: 'duf', category: 'utilities', description: 'Disk usage utility' },
    { name: 'unzip', category: 'utilities', description: 'Extract ZIP archives' },
    { name: 'zip', category: 'utilities', description: 'Create ZIP archives' },
    { name: 'tar', category: 'utilities', description: 'Archive utility' },
    { name: 'gzip', category: 'utilities', description: 'GNU compression utility' },
    { name: 'bzip2', category: 'utilities', description: 'Block-sorting compressor' },
    { name: 'xz-utils', category: 'utilities', description: 'XZ compression utilities' },
    { name: 'p7zip-full', category: 'utilities', description: '7-Zip file archiver' },
    { name: 'file', category: 'utilities', description: 'Determine file type' },
    { name: 'less', category: 'utilities', description: 'Pager program' },
    { name: 'most', category: 'utilities', description: 'Pager with multiple windows' },
    { name: 'watch', category: 'utilities', description: 'Execute command periodically' },
    { name: 'parallel', category: 'utilities', description: 'Shell tool for parallel execution' },
    { name: 'pv', category: 'utilities', description: 'Monitor data through a pipe' },
    { name: 'rename', category: 'utilities', description: 'Rename files using patterns' },
    { name: 'strace', category: 'utilities', description: 'System call tracer' },
    { name: 'lsof', category: 'utilities', description: 'List open files' },
    { name: 'sudo', category: 'utilities', description: 'Execute commands as another user' },
    { name: 'ca-certificates', category: 'utilities', description: 'Common CA certificates' },
    { name: 'gnupg', category: 'utilities', description: 'GNU privacy guard' },
    { name: 'direnv', category: 'utilities', description: 'Environment switcher for shell' },

    // Python
    { name: 'python3', category: 'python', description: 'Python 3 interpreter' },
    { name: 'python3-dev', category: 'python', description: 'Python 3 development headers' },
    { name: 'python3-pip', category: 'python', description: 'Python package installer' },
    { name: 'python3-venv', category: 'python', description: 'Python virtual environments' },
    { name: 'python3-setuptools', category: 'python', description: 'Python distutils enhancements' },
    { name: 'python3-wheel', category: 'python', description: 'Python wheel package format' },
    { name: 'pipx', category: 'python', description: 'Install Python apps in isolated environments' },

    // Database Clients
    { name: 'sqlite3', category: 'database', description: 'SQLite 3 CLI' },
    { name: 'postgresql-client', category: 'database', description: 'PostgreSQL CLI (psql)' },
    { name: 'mysql-client', category: 'database', description: 'MySQL CLI' },
    { name: 'redis-tools', category: 'database', description: 'Redis CLI' },
    { name: 'mongodb-clients', category: 'database', description: 'MongoDB shell' },

    // Media
    { name: 'imagemagick', category: 'media', description: 'Image manipulation tools' },
    { name: 'ffmpeg', category: 'media', description: 'Audio/video converter' },
    { name: 'graphviz', category: 'media', description: 'Graph visualization' },
    { name: 'ghostscript', category: 'media', description: 'PostScript/PDF interpreter' },
    { name: 'poppler-utils', category: 'media', description: 'PDF utilities (pdftotext)' },
    { name: 'pandoc', category: 'media', description: 'Document converter' },

    // Shells
    { name: 'zsh', category: 'shells', description: 'Z shell' },
    { name: 'fish', category: 'shells', description: 'Friendly interactive shell' },
    { name: 'bash-completion', category: 'shells', description: 'Bash completion scripts' },
    { name: 'zsh-autosuggestions', category: 'shells', description: 'Fish-like autosuggestions for zsh' },
    { name: 'zsh-syntax-highlighting', category: 'shells', description: 'Syntax highlighting for zsh' }
];

// Common mise tools
export const MISE_TOOLS = [
    { name: 'node', versions: ['22', '20', '18'], description: 'Node.js JavaScript runtime' },
    { name: 'python', versions: ['3.13', '3.12', '3.11'], description: 'Python programming language' },
    { name: 'go', versions: ['1.23', '1.22'], description: 'Go programming language' },
    { name: 'rust', versions: ['stable', '1.83'], description: 'Rust programming language' },
    { name: 'ruby', versions: ['3.4', '3.3'], description: 'Ruby programming language' },
    { name: 'java', versions: ['23', '21', '17'], description: 'Java Development Kit' },
    { name: 'deno', versions: ['2.1', '2.0'], description: 'Deno JavaScript/TypeScript runtime' },
    { name: 'bun', versions: ['1.2', '1.1'], description: 'Bun JavaScript runtime' },
    { name: 'zig', versions: ['0.14', '0.13'], description: 'Zig programming language' },
    { name: 'terraform', versions: ['1.10', '1.9'], description: 'Infrastructure as code tool' },
    { name: 'kubectl', versions: ['1.32', '1.31'], description: 'Kubernetes CLI' },
    { name: 'helm', versions: ['3.16', '3.15'], description: 'Kubernetes package manager' }
];

// Get packages grouped by category
export function getPackagesByCategory() {
    const grouped = {};
    for (const cat of APT_CATEGORIES) {
        grouped[cat] = APT_PACKAGES.filter(p => p.category === cat);
    }
    return grouped;
}
