# Changelog

## 1.0.1 (2026-11-25)

- Hooks pass git's own arguments before the options. Python 3.10's argument parser cannot take them after, so the `commit-msg` hook failed there. CI caught it on the first push.
- The hook tests now run the hooks with the interpreter running the tests, so each Python version in CI is really exercised.

## 1.0.0 (2026-11-25)

First public release.

- Scans working folders and every object in a git repository, reachable or not.
- Checks commit author, committer and tagger identities against an approved list.
- Finds and strips PNG, JPEG and SVG metadata.
- Installs `pre-commit`, `commit-msg` and `pre-push` hooks.
- An `allow` list of exact strings that no rule may flag, in the identifiers file or with `--allow`.
