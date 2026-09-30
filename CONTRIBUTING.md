# Contributing

Thanks for helping improve argon2w. For usage questions, start a thread in [GitHub Discussions](https://github.com/Hallaxius/argon2w/discussions). Use the issue forms for reproducible bugs and feature requests.

## Local development

The project uses Bun 1.4.2 in CI. Install dependencies and run the package checks with:

```sh
bun ci
bun run build
bun run typecheck
bun test --coverage --coverage-reporter=text
```

Node.js consumer compatibility starts at Node.js 24, as declared by `engines.node`. The CI workflow also exercises the packed npm artifact on Node.js and runs native and WebAssembly checks in Docker.

## Pull requests

- Keep changes focused and explain the user-visible behavior they affect.
- Add or update tests when changing package behavior, cost validation, PHC parsing, or runtime loading.
- Update the README when public API or runtime behavior changes.
- Never include real passwords, production PHC strings, tokens, or customer data in tests or issue reports.
- Run the applicable local checks above and describe what you ran in the pull request.
