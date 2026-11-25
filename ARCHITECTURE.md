# Architecture

One file, `portfolio_shield.py`, in five parts.

## Configuration

`load_config` reads the identifiers file and any deny-list files it names. A named file that is missing is an error, not an empty list: the scan fails closed. Deny entries are compiled once into regular expressions. Approved identities add their own addresses to the mail allow list.

## Rules

`scan_text` runs every rule on each line: the deny list, a table of fixed patterns, an IPv4 pass that classifies each address with the `ipaddress` module, a mail pass with an allow list, and in strict mode an entropy pass over long runs. `scan_name` applies the file-name rules. `scan_bytes` decides what a blob is: a PNG or JPEG (checked chunk by chunk or segment by segment), UTF-8 text, or other binary. Binary data is still searched for deny-list words, read byte for byte, with NUL bytes removed, and as UTF-16 at both offsets, so a word stored in a wide encoding is not missed.

## Repositories

`scan_repo` asks git for every object in the database with `cat-file --batch-all-objects --batch`, reachable or not. Blobs are scanned as files, under the first path `rev-list --all --reflog --objects` gives them. Trees give file names. Commits and tags give author, committer and tagger headers, checked against the approved identities, and a message. Every git call uses `--no-optional-locks`, so scanning another tool's repository never takes its index lock.

## Hooks

`install_hooks` writes small `sh` scripts that call the tool with the identifiers path baked in. `pre-commit` reads staged blobs with `cat-file blob :<path>` and reads the identity with `git var`. `pre-push` lists the objects reachable from each pushed commit and scans them with the same code as a full scan.

## Pictures

`strip_png` keeps only the chunks a picture needs (`IHDR`, `PLTE`, `IDAT`, `IEND` and the colour chunks) and copies them byte for byte, so the pixels and CRCs are unchanged. `strip_jpeg` drops APP1 to APP15 and comments, keeping the plain JFIF and Adobe blocks. `strip_svg` removes `<metadata>`, editor attributes and comments.

## Decisions

- **Standard library only.** The tool guards against supply-chain mistakes, so it should not bring any of its own.
- **Never print the value.** A report is often pasted into a chat or a ticket. It shows the first two characters and the length.
- **Strict mode needs an identity list.** Without one, the identity check cannot run, and a scan that silently skips a rule is worse than one that stops.
- **Pushes to github.com only, by default.** Private forges hold private detail on purpose. `--all-remotes` is there if you want it.

## What the first runs caught

- The tool flagged its own source on the first strict run. Its rule names and comments contained words that were on my private deny list. The rules were renamed and the address ranges are now built from numbers at run time.
- The test fixtures did the same. Every "bad" string in the tests is now joined from pieces when the test runs, and the release check is that both files scan clean.
- An audit of my older public repositories found a machine user name and personal addresses in commit author headers. A file scan never sees those, which is why identity checks and the object-database scan exist.
