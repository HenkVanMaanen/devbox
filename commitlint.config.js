export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['feat', 'fix', 'docs', 'refactor', 'test', 'chore', 'ci', 'perf', 'revert', 'build']],
    'header-max-length': [2, 'always', 100],
    'body-max-line-length': [1, 'always', 200],
  },
};
