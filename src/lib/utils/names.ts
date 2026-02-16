import { adjectives, animals, type Config, uniqueNamesGenerator } from 'unique-names-generator';

const config: Config = {
  dictionaries: [adjectives, animals],
  length: 2,
  separator: '-',
  style: 'lowerCase',
};

export function generateServerName(): string {
  return uniqueNamesGenerator(config);
}
