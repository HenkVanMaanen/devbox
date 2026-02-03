// Funny alliterative server name generator

const adjectives = [
  'adorable', 'brave', 'calm', 'dapper', 'eager', 'fancy', 'gentle', 'happy',
  'jolly', 'keen', 'lively', 'merry', 'nice', 'peppy', 'quick', 'radiant',
  'snappy', 'tender', 'upbeat', 'vivid', 'witty', 'zesty', 'bouncy', 'chirpy',
  'dandy', 'elegant', 'fluffy', 'groovy', 'humble', 'inventive', 'jazzy', 'kind',
];

const nouns = [
  'alpaca', 'badger', 'capybara', 'dolphin', 'elephant', 'flamingo', 'giraffe', 'hedgehog',
  'iguana', 'jaguar', 'koala', 'lemur', 'meerkat', 'narwhal', 'octopus', 'penguin',
  'quokka', 'raccoon', 'sloth', 'toucan', 'urchin', 'vulture', 'walrus', 'xerus',
  'yak', 'zebra', 'axolotl', 'beaver', 'chinchilla', 'dingo', 'echidna', 'ferret',
];

function randomFrom<T>(arr: readonly T[]): T {
  const item = arr[Math.floor(Math.random() * arr.length)];
  if (item === undefined) {
    throw new Error('Array is empty');
  }
  return item;
}

export function generateServerName(): string {
  // Pick a random letter
  const letter = String.fromCharCode(97 + Math.floor(Math.random() * 26));

  // Find adjectives and nouns starting with that letter
  const matchingAdjectives = adjectives.filter((a) => a.startsWith(letter));
  const matchingNouns = nouns.filter((n) => n.startsWith(letter));

  // If we can't find both, use any
  const adj = matchingAdjectives.length > 0 ? randomFrom(matchingAdjectives) : randomFrom(adjectives);
  const noun = matchingNouns.length > 0 ? randomFrom(matchingNouns) : randomFrom(nouns);

  // Add random suffix for uniqueness
  const suffix = Math.random().toString(36).slice(2, 6);

  return `devbox-${adj}-${noun}-${suffix}`;
}
