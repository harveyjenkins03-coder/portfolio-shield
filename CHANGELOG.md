# Changelog

## 1.0.0 (2026-11-25)

First public release.

- Scans working folders and every object in a git repository, reachable or not.
- Checks commit author, committer and tagger identities against an approved list.
- Finds and strips PNG, JPEG and SVG metadata.
- Installs `pre-commit`, `commit-msg` and `pre-push` hooks.
- An `allow` list of exact strings that no rule may flag, in the identifiers file or with `--allow`.
