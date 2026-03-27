<script lang="ts">
  import bcrypt from 'bcryptjs';

  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import * as hetzner from '$lib/api/hetzner';
  import { configStore } from '$lib/stores/config.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { setupStore } from '$lib/stores/setup.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { extractSSHKeyName, sshPublicKeySchema } from '$lib/utils/validation';

  const STEPS = [
    { label: 'API Token', required: true, title: 'Hetzner API Token' },
    { label: 'Auth User', required: true, title: 'Authentication User' },
    { label: 'SSH Key', required: false, title: 'SSH Key' },
    { label: 'Git', required: false, title: 'Git Credentials' },
  ];

  let currentStep = $state(0);

  // Step 1: Hetzner Token
  let token = $state('');
  let tokenValidating = $state(false);
  let tokenValid = $state<boolean | null>(null);

  // Step 2: Auth User
  let authUsername = $state('');
  let authPassword = $state('');
  let authHashing = $state(false);
  let authUser = $state<null | { passwordHash: string; username: string }>(null);

  // Step 3: SSH Key
  let sshKeyName = $state('');
  let sshKeyPubKey = $state('');
  let sshKeyError = $state('');
  let sshKeyAdded = $state<null | { name: string; pubKey: string }>(null);

  $effect(() => {
    if (sshKeyPubKey.trim()) {
      const result = sshPublicKeySchema.safeParse(sshKeyPubKey);
      sshKeyError = result.success ? '' : (result.error.issues[0]?.message ?? '');
    } else {
      sshKeyError = '';
    }
  });

  // Step 4: Git Credentials
  let gitHost = $state('github.com');
  let gitUsername = $state('');
  let gitToken = $state('');

  const canProceed = $derived.by(() => {
    switch (currentStep) {
      case 0:
        return tokenValid === true;
      case 1:
        return authUser !== null;
      default:
        return true;
    }
  });

  async function validateToken() {
    if (!token.trim()) return;
    tokenValidating = true;
    try {
      const valid = await hetzner.validateToken(token.trim());
      tokenValid = valid;
      if (valid) {
        toast.success('Token is valid!');
      } else {
        toast.error('Token is invalid. Please check and try again.');
      }
    } catch {
      tokenValid = false;
      toast.error('Could not validate token. Check your network connection.');
    } finally {
      tokenValidating = false;
    }
  }

  async function addAuthUser() {
    const username = authUsername.trim();
    if (!username || !authPassword) {
      toast.error('Please enter both username and password');
      return;
    }
    authHashing = true;
    try {
      const passwordHash = await bcrypt.hash(authPassword, 10);
      authUser = { passwordHash, username };
      toast.success(`User "${username}" added`);
    } catch {
      toast.error('Failed to hash password');
    } finally {
      authHashing = false;
    }
  }

  function removeAuthUser() {
    authUser = null;
    authUsername = '';
    authPassword = '';
  }

  function addSSHKey() {
    if (!sshKeyPubKey.trim()) {
      toast.error('Please enter a public key');
      return;
    }
    const validation = sshPublicKeySchema.safeParse(sshKeyPubKey);
    if (!validation.success) {
      toast.error(validation.error.issues[0]?.message ?? 'Invalid SSH key');
      return;
    }
    let name = sshKeyName.trim();
    if (!name) {
      name = extractSSHKeyName(sshKeyPubKey) ?? 'key-1';
    }
    sshKeyAdded = { name, pubKey: sshKeyPubKey.trim() };
    toast.success(`SSH key "${name}" added`);
  }

  function removeSSHKey() {
    sshKeyAdded = null;
    sshKeyName = '';
    sshKeyPubKey = '';
    sshKeyError = '';
  }

  function next() {
    if (currentStep < STEPS.length - 1) {
      currentStep++;
    } else {
      finish();
    }
  }

  function back() {
    if (currentStep > 0) {
      currentStep--;
    }
  }

  function finish() {
    // Save token
    credentialsStore.token = token.trim();
    credentialsStore.save();

    // Save auth user
    if (authUser) {
      configStore.set('auth.users', [authUser]);
    }

    // Save SSH key if added
    if (sshKeyAdded) {
      configStore.set('ssh.keys', [sshKeyAdded]);
    }

    // Save git credentials if filled
    if (gitUsername.trim() && gitToken.trim()) {
      configStore.set('git.credential.host', gitHost.trim());
      configStore.set('git.credential.username', gitUsername.trim());
      configStore.set('git.credential.token', gitToken.trim());
    }

    configStore.save();
    setupStore.markComplete();
    toast.success('Setup complete! You can now create your first Devbox.');
    window.location.hash = '#dashboard';
  }
</script>

<div class="mx-auto max-w-2xl space-y-6 py-8">
  <!-- Header -->
  <div class="text-center">
    <h1 class="text-3xl font-bold">Welcome to Devbox</h1>
    <p class="text-muted-foreground mt-2">Let's get you set up. This will only take a minute.</p>
  </div>

  <!-- Stepper -->
  <div class="flex items-center justify-center gap-1 px-8">
    {#each STEPS as step, i (i)}
      {#if i > 0}
        <div class="h-0.5 flex-1 transition-colors {i <= currentStep ? 'bg-primary' : 'bg-border'}"></div>
      {/if}
      <div class="flex flex-col items-center gap-1">
        <div
          class="flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold transition-colors
                 {i < currentStep
            ? 'bg-primary text-primary-foreground'
            : i === currentStep
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground'}"
        >
          {#if i < currentStep}
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          {:else}
            {i + 1}
          {/if}
        </div>
        <span class="text-xs font-medium {i <= currentStep ? 'text-foreground' : 'text-muted-foreground'}">
          {step.label}
        </span>
      </div>
    {/each}
  </div>

  <!-- Step Content -->
  {#if currentStep === 0}
    <!-- Step 1: Hetzner API Token -->
    <Card title="Hetzner API Token" description="Required to create and manage cloud servers.">
      <div class="space-y-4">
        <p class="text-muted-foreground text-sm">
          You need a Hetzner Cloud API token with <strong>read &amp; write</strong> permissions. Create one in the
          <a
            href="https://console.hetzner.cloud/"
            target="_blank"
            rel="noopener noreferrer"
            class="text-primary hover:underline">Hetzner Cloud Console</a
          >
          under <strong>Security &rarr; API Tokens</strong>.
        </p>
        <p class="text-muted-foreground text-sm">
          Your token is stored locally in your browser and only sent to the Hetzner API.
        </p>

        <div>
          <label for="setup-token" class="mb-1.5 block text-sm font-medium">API Token</label>
          <input
            id="setup-token"
            type="password"
            bind:value={token}
            placeholder="Enter your Hetzner API token"
            class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                   min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
          />
        </div>

        <div class="flex items-center gap-3">
          <Button variant="secondary" onclick={validateToken} loading={tokenValidating} disabled={!token.trim()}>
            Validate Token
          </Button>
          {#if tokenValid === true}
            <span class="text-success text-sm font-medium">Valid</span>
          {:else if tokenValid === false}
            <span class="text-destructive text-sm font-medium">Invalid token</span>
          {/if}
        </div>
      </div>
    </Card>
  {:else if currentStep === 1}
    <!-- Step 2: Auth User -->
    <Card title="Authentication User" description="Required for accessing services on your server.">
      <div class="space-y-4">
        <p class="text-muted-foreground text-sm">
          Your Devbox uses <strong>Authelia</strong> as an authentication proxy to protect web-based services like VS Code
          Server, the terminal, and file browser. Add at least one user to log in with.
        </p>
        <p class="text-muted-foreground text-sm">
          The password is hashed in your browser before being stored. It is never saved or transmitted in plain text.
        </p>

        {#if authUser}
          <div class="bg-muted flex items-center justify-between rounded-md p-3">
            <div>
              <p class="font-medium">{authUser.username}</p>
              <p class="text-muted-foreground text-sm">Password set</p>
            </div>
            <Button variant="ghost" size="sm" onclick={removeAuthUser}>Remove</Button>
          </div>
        {:else}
          <div class="border-border space-y-3 rounded-md border p-4">
            <div>
              <label for="setup-auth-username" class="mb-1.5 block text-sm font-medium">Username</label>
              <input
                id="setup-auth-username"
                type="text"
                bind:value={authUsername}
                placeholder="alice"
                class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                       min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
              />
            </div>
            <div>
              <label for="setup-auth-password" class="mb-1.5 block text-sm font-medium">Password</label>
              <input
                id="setup-auth-password"
                type="password"
                bind:value={authPassword}
                placeholder="Enter password"
                class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                       min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
              />
            </div>
            <Button size="sm" onclick={addAuthUser} disabled={authHashing}>
              {authHashing ? 'Hashing...' : 'Add User'}
            </Button>
          </div>
        {/if}
      </div>
    </Card>
  {:else if currentStep === 2}
    <!-- Step 3: SSH Key -->
    <Card title="SSH Key" description="Add your public key to access the server via SSH.">
      <div class="space-y-4">
        <p class="text-muted-foreground text-sm">
          To connect to your Devbox via SSH, add your public key. You can usually find it at
          <code class="bg-muted rounded px-1.5 py-0.5 text-xs">~/.ssh/id_ed25519.pub</code> or
          <code class="bg-muted rounded px-1.5 py-0.5 text-xs">~/.ssh/id_rsa.pub</code>.
        </p>
        <p class="text-muted-foreground text-sm">
          If you don't have one, generate it with:
          <code class="bg-muted rounded px-1.5 py-0.5 text-xs">ssh-keygen -t ed25519</code>
        </p>

        {#if sshKeyAdded}
          <div class="bg-muted flex items-center justify-between rounded-md p-3">
            <div>
              <p class="font-medium">{sshKeyAdded.name}</p>
              <p class="text-muted-foreground max-w-md truncate font-mono text-sm">
                {sshKeyAdded.pubKey.slice(0, 50)}...
              </p>
            </div>
            <Button variant="ghost" size="sm" onclick={removeSSHKey}>Remove</Button>
          </div>
        {:else}
          <div class="border-border space-y-3 rounded-md border p-4">
            <div>
              <label for="setup-ssh-name" class="mb-1.5 block text-sm font-medium">Name (optional)</label>
              <input
                id="setup-ssh-name"
                type="text"
                bind:value={sshKeyName}
                placeholder="my-key"
                class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                       min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
              />
              <p class="text-muted-foreground mt-1 text-xs">Auto-extracted from key comment if empty</p>
            </div>
            <div>
              <label for="setup-ssh-pubkey" class="mb-1.5 block text-sm font-medium">Public Key</label>
              <textarea
                id="setup-ssh-pubkey"
                bind:value={sshKeyPubKey}
                placeholder="ssh-ed25519 AAAA..."
                class="bg-background focus:ring-focus focus:border-primary placeholder:text-placeholder
                       min-h-[88px] w-full resize-y rounded-md border-2 px-3 py-2 font-mono text-sm
                       focus:ring-3 focus:outline-none
                       {sshKeyError ? 'border-destructive' : 'border-border'}"
              ></textarea>
              {#if sshKeyError}
                <p class="text-destructive mt-1 text-sm">{sshKeyError}</p>
              {/if}
            </div>
            <Button variant="secondary" onclick={addSSHKey}>Add SSH Key</Button>
          </div>
        {/if}
      </div>
    </Card>
  {:else if currentStep === 3}
    <!-- Step 4: Git Credentials -->
    <Card title="Git Credentials" description="Configure git authentication for cloning repositories.">
      <div class="space-y-4">
        <p class="text-muted-foreground text-sm">
          Add git credentials so your Devbox can clone private repositories. For GitHub, create a
          <a
            href="https://github.com/settings/tokens"
            target="_blank"
            rel="noopener noreferrer"
            class="text-primary hover:underline">Personal Access Token</a
          >
          with <strong>repo</strong> scope.
        </p>
        <p class="text-muted-foreground text-sm">
          Your token is stored locally and injected into the server via cloud-init. It is never shared externally.
        </p>

        <div class="border-border space-y-3 rounded-md border p-4">
          <div>
            <label for="setup-git-host" class="mb-1.5 block text-sm font-medium">Host</label>
            <input
              id="setup-git-host"
              type="text"
              bind:value={gitHost}
              placeholder="github.com"
              class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                     min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
            />
          </div>
          <div>
            <label for="setup-git-username" class="mb-1.5 block text-sm font-medium">Username</label>
            <input
              id="setup-git-username"
              type="text"
              bind:value={gitUsername}
              placeholder="username"
              class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                     min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
            />
          </div>
          <div>
            <label for="setup-git-token" class="mb-1.5 block text-sm font-medium">Token</label>
            <input
              id="setup-git-token"
              type="password"
              bind:value={gitToken}
              placeholder="ghp_..."
              class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder
                     min-h-[44px] w-full rounded-md border-2 px-3 py-2 text-base focus:ring-3 focus:outline-none"
            />
          </div>
        </div>
      </div>
    </Card>
  {/if}

  <!-- Navigation Buttons -->
  <div class="flex items-center justify-between">
    <div>
      {#if currentStep > 0}
        <Button variant="secondary" onclick={back}>Back</Button>
      {/if}
    </div>
    <div class="flex gap-3">
      {#if !STEPS[currentStep]?.required}
        <Button
          variant="secondary"
          onclick={() => {
            if (currentStep === STEPS.length - 1) {
              finish();
            } else {
              next();
            }
          }}
        >
          Skip
        </Button>
      {/if}
      <Button onclick={next} disabled={!canProceed}>
        {currentStep === STEPS.length - 1 ? 'Finish' : 'Next'}
      </Button>
    </div>
  </div>

  <!-- Step indicator -->
  <p class="text-muted-foreground text-center text-sm">
    Step {currentStep + 1} of {STEPS.length}
    {#if !STEPS[currentStep]?.required}
      &mdash; optional, you can skip this
    {/if}
  </p>
</div>
