#!/usr/bin/env python3
"""portfolio-shield: stop private data reaching a public git repository.

It scans a working folder, every object in a repository's database (so deleted files, old commits and dangling
objects are read too), commit author and committer headers, commit messages, file names, and the metadata of
PNG, JPEG and SVG files. It can strip that metadata, and it installs pre-commit, commit-msg and pre-push hooks
so the same checks run on every commit and on every push to github.com.

Standard library only. Exit codes: 0 clean, 1 findings, 2 a usage or configuration error.

The private values (your user name, private domains, mail addresses, address ranges, approved identities) live
in a JSON file that is never committed anywhere. See private-identifiers.example.json.
"""
from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import zlib
from collections import Counter
from pathlib import Path

VERSION = "1.0.1"
ENV_CONFIG = "PORTFOLIO_SHIELD_IDENTIFIERS"
DEFAULT_CONFIGS = (Path.home() / ".portfolio-shield" / "private-identifiers.json",
                   Path(__file__).resolve().parent / "private-identifiers.json")
ZERO_SHA = "0" * 40
LETTER = r"[^\W\d_]"

# ---------------------------------------------------------------------------------------------- configuration


class ConfigError(Exception):
    pass


@dataclasses.dataclass
class Config:
    deny: list[str] = dataclasses.field(default_factory=list)
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = dataclasses.field(default_factory=list)
    allowed_emails: set[str] = dataclasses.field(default_factory=set)
    approved_identities: set[str] = dataclasses.field(default_factory=set)
    allow: list[str] = dataclasses.field(default_factory=list)
    source: str = "(none)"

    def __post_init__(self):
        self.compile()

    def compile(self):
        self.patterns: list[re.Pattern[str]] = []
        for entry in (d.strip() for d in self.deny):
            if not entry:
                continue
            if entry.startswith("=") and len(entry) > 1:
                self.patterns.append(re.compile(f"(?<!{LETTER}){re.escape(entry[1:])}(?!{LETTER})"))
            else:
                self.patterns.append(re.compile(re.escape(entry), re.IGNORECASE))
        for ident in self.approved_identities:
            match = re.search(r"<([^>]+)>", ident)
            if match:
                self.allowed_emails.add(match.group(1).lower())

    def with_extra(self, extra: list[str], allow: list[str] | None = None) -> "Config":
        if extra:
            self.deny = self.deny + list(extra)
            self.compile()
        self.allow = self.allow + list(allow or [])
        return self

    def unallow(self, text: str) -> str:
        """Blank out each exact allowed string, longest first, so no rule sees it."""
        for value in sorted(self.allow, key=len, reverse=True):
            if value:
                text = text.replace(value, " " * len(value))
        return text

    def mask(self, text: str) -> str:
        for pattern in self.patterns:
            text = pattern.sub("***", text)
        return text


def read_denylist(path: Path) -> list[str]:
    text = path.read_bytes().decode("utf-8-sig")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def load_config(path: Path | str) -> Config:
    """Read the identifiers file. A listed deny-list file that is missing is an error: the scan fails closed."""
    path = Path(path).expanduser()
    if not path.is_file():
        raise ConfigError(f"identifiers file not found: {path.name}")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError as err:
        raise ConfigError(f"identifiers file is not valid JSON: {err}") from None
    deny = [str(d) for d in data.get("deny", [])]
    for name in data.get("denylist_files", []):
        listed = Path(os.path.expandvars(str(name))).expanduser()
        if not listed.is_file():
            raise ConfigError(f"a deny-list file named in the identifiers file is missing: {listed.name}")
        deny += read_denylist(listed)
    try:
        cidrs = [ipaddress.ip_network(c, strict=False) for c in data.get("cidrs", [])]
    except ValueError as err:
        raise ConfigError(f"bad CIDR in identifiers file: {err}") from None
    return Config(deny=deny, cidrs=cidrs,
                  allowed_emails={e.lower() for e in data.get("allowed_emails", [])},
                  approved_identities={" ".join(i.split()) for i in data.get("approved_identities", [])},
                  allow=[str(a) for a in data.get("allow", [])], source=path.name)


def find_config(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    if os.environ.get(ENV_CONFIG):
        return Path(os.environ[ENV_CONFIG])
    for candidate in DEFAULT_CONFIGS:
        if candidate.is_file():
            return candidate
    return None

# ---------------------------------------------------------------------------------------------- findings


@dataclasses.dataclass(frozen=True)
class Finding:
    where: str
    line: int
    rule: str
    hint: str = ""

    def render(self) -> str:
        return f"{self.where}:{self.line}: {self.rule}" + (f" ({self.hint})" if self.hint else "")


def peek(value: str) -> str:
    """Enough to find the spot, never the value itself."""
    value = value.strip()
    return f"{value[:2]}.. {len(value)} chars"

# ---------------------------------------------------------------------------------------------- text rules


PATTERN_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("windows-user-path", re.compile(r"[A-Za-z]:(?:\\\\|\\|/)+Users(?:\\\\|\\|/)+[^\\/\s\"'<>]+", re.I)),
    ("home-path", re.compile(r"(?<![\w.~-])/(?:home|Users)/[A-Za-z_][\w.-]*")),
    ("ts-ipv6", re.compile("fd7a" + ":115c" + ":a1e0:", re.I)),   # a mesh VPN's IPv6 prefix
    ("ts-hostname", re.compile(r"(?<![\w-])(?:[\w-]+\.)+ts\.net(?![\w-])", re.I)),
    ("mac-address", re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("api-key", re.compile(r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}|[rs]k_live_[A-Za-z0-9]{16,}|xox[abpr]-[A-Za-z0-9-]{10,}"
                           r"|AIza[0-9A-Za-z_-]{35})")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")),
    ("webhook", re.compile(r"hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|outlook\.office\.com/webhook", re.I)),
    ("tunnel", re.compile(r"cfargo" r"tunnel\.com|trycloudflare\.com|ngrok(?:-free)?\.(?:io|app|dev)", re.I)),
    ("secret-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|client[_-]?secret|password|passwd|pwd|token|access[_-]?key|auth[_-]?key)\b"
        r"[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']")),
]
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
TOKEN = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
FILE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "css", "js", "ts", "md", "html", "json"}
SAFE_EMAIL = re.compile(r"(?:^noreply@|^no-reply@|@users\.noreply\.github\.com$|@example\.(?:com|org|net)$"
                        r"|\.(?:example|invalid|test)$|^git@github\.com$)", re.I)
LOCKFILES = {"cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "go.sum", "uv.lock",
             "composer.lock", "gemfile.lock", "flake.lock"}
def _net(a: int, b: int, bits: int) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(f"{a}.{b}.0.0/{bits}")


CGNAT_V4 = _net(100, 64, 10)   # carrier-grade NAT, also used by mesh VPNs
PRIVATE_V4 = [_net(10, 0, 8), _net(172, 16, 12), _net(192, 168, 16), _net(169, 254, 16)]


def entropy(token: str) -> float:
    counts = Counter(token)
    return -sum(c / len(token) * math.log2(c / len(token)) for c in counts.values())


def _email_ok(address: str, cfg: Config) -> bool:
    address = address.lower()
    if address in cfg.allowed_emails or SAFE_EMAIL.search(address):
        return True
    return address.rsplit(".", 1)[-1] in FILE_EXTENSIONS   # icon@2x.png and the like


def _ip_rule(text: str, cfg: Config) -> str | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip in CGNAT_V4:
        return "cgnat-ip"
    if any(ip in net for net in PRIVATE_V4):
        return "private-ip"
    if any(ip.version == net.version and ip in net for net in cfg.cidrs):
        return "custom-cidr"
    return None


def scan_text(path: str, text: str, cfg: Config, strict: bool = True) -> list[Finding]:
    found: dict[tuple, Finding] = {}
    where = cfg.mask(path)
    check_entropy = strict and Path(path).name.lower() not in LOCKFILES and not path.lower().endswith(".lock")

    def add(line: int, rule: str, hint: str = ""):
        found.setdefault((line, rule, hint), Finding(where, line, rule, hint))

    for number, line in enumerate(cfg.unallow(text).split("\n"), 1):
        for pattern in cfg.patterns:
            if pattern.search(line):
                add(number, "deny-list")
        for rule, pattern in PATTERN_RULES:
            for match in pattern.finditer(line):
                add(number, rule, peek(match.group(0)))
        for match in IPV4.finditer(line):
            rule = _ip_rule(match.group(0), cfg)
            if rule:
                add(number, rule, peek(match.group(0)))
        for match in EMAIL.finditer(line):
            if not _email_ok(match.group(0), cfg):
                add(number, "email", peek(match.group(0)))
        if check_entropy and "integrity" not in line:
            for match in TOKEN.finditer(line):
                token = match.group(0)
                classes = sum(bool(re.search(c, token)) for c in ("[a-z]", "[A-Z]", "[0-9]"))
                if classes == 3 and entropy(token) >= 4.5:
                    add(number, "high-entropy", peek(token))
    return sorted(found.values(), key=lambda f: (f.line, f.rule))

# ---------------------------------------------------------------------------------------------- file names


SENSITIVE_NAMES = re.compile(
    r"(?:^|/)(?:\.env(?:\.(?!example$|sample$|template$|dist$)[^/]+)?"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pem|key|p12|pfx|dpapi|keystore|jks|kdbx|ovpn)"
    r"|\.claude|CLAUDE\.local\.md|\.mcp\.json|[^/]+\.jsonl|credentials[^/]*\.json|\.npmrc|\.pypirc"
    r"|\.netrc|\.git-credentials|private-identifiers\.json|[^/]*\.tfstate)(?:/|$)", re.I)


def scan_name(name: str, cfg: Config) -> list[Finding]:
    name = name.replace("\\", "/")
    where = cfg.mask(name)
    out = []
    if SENSITIVE_NAMES.search(name):
        out.append(Finding(where, 0, "sensitive-file"))
    if any(p.search(cfg.unallow(name)) for p in cfg.patterns):
        out.append(Finding(where, 0, "deny-list"))
    for f in scan_text(name, name, cfg, strict=False):
        if f.rule != "deny-list":
            out.append(Finding(where, 0, f.rule, f.hint))
    return out

# ---------------------------------------------------------------------------------------------- pictures


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"sRGB", b"pHYs", b"cHRM", b"sBIT", b"bKGD"}


def png_chunks(data: bytes):
    pos = len(PNG_SIG)
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        end = pos + 12 + length
        yield kind, data[pos + 8:pos + 8 + length], data[pos:end]
        pos = end
        if kind == b"IEND":
            break


def strip_png(data: bytes) -> bytes:
    return PNG_SIG + b"".join(raw for kind, _body, raw in png_chunks(data) if kind in PNG_KEEP)


def _png_findings(data: bytes) -> tuple[list[str], list[bytes]]:
    rules, extra_text = [], []
    for kind, body, _raw in png_chunks(data):
        if kind not in PNG_KEEP:
            rules.append(kind.decode("latin-1"))
            if kind in (b"zTXt", b"iTXt", b"iCCP"):
                for start in range(len(body)):
                    try:
                        extra_text.append(zlib.decompress(body[start:]))
                        break
                    except zlib.error:
                        continue
    return rules, extra_text


def jpeg_segments(data: bytes):
    """(marker, raw bytes) for each segment; the scan data and everything after it come as one last piece."""
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            yield None, data[pos:]
            return
        while pos + 1 < len(data) and data[pos + 1] == 0xFF:
            pos += 1
        marker = data[pos + 1]
        if marker == 0xD9 or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            yield marker, data[pos:pos + 2]
            pos += 2
            continue
        if marker == 0xDA:
            yield marker, data[pos:]
            return
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        yield marker, data[pos:pos + 2 + length]
        pos += 2 + length


def _jpeg_metadata(marker: int | None, raw: bytes) -> bool:
    if marker is None:
        return False
    body = raw[4:]
    if marker == 0xE0:
        return not body.startswith(b"JFIF\x00")
    if marker == 0xEE:
        return not body.startswith(b"Adobe")
    return 0xE1 <= marker <= 0xEF or marker == 0xFE


def strip_jpeg(data: bytes) -> bytes:
    return data[:2] + b"".join(raw for marker, raw in jpeg_segments(data) if not _jpeg_metadata(marker, raw))


SVG_META = re.compile(r"<metadata\b|sodipodi:|inkscape:|<rdf:RDF\b|xmlns:dc=|<dc:", re.I)


def strip_svg(text: str) -> str:
    text = re.sub(r"<metadata\b[\s\S]*?</metadata>|<metadata\b[^>]*/>", "", text)
    text = re.sub(r"<sodipodi:namedview\b[\s\S]*?(?:/>|</sodipodi:namedview>)", "", text)
    text = re.sub(r"\s(?:sodipodi|inkscape):[\w-]+=\"[^\"]*\"", "", text)
    text = re.sub(r"\sxmlns:(?:sodipodi|inkscape|rdf|dc|cc)=\"[^\"]*\"", "", text)
    return re.sub(r"<!--[\s\S]*?-->", "", text)


def _readings(data: bytes) -> list[str]:
    return [data.decode("latin-1"), data.replace(b"\x00", b"").decode("latin-1")] + [
        data[skip:].decode(codec, errors="ignore") for codec in ("utf-16-le", "utf-16-be") for skip in (0, 1)]


def _as_text(data: bytes) -> str | None:
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")   # text with a stray byte is still text: every rule must still read it


def scan_bytes(path: str, data: bytes, cfg: Config, strict: bool = True) -> list[Finding]:
    where = cfg.mask(path)
    out: list[Finding] = []
    binary_texts: list[bytes] = [data]
    if data.startswith(PNG_SIG):
        kinds, extra = _png_findings(data)
        out += [Finding(where, 0, "image-metadata", f"PNG {k} chunk") for k in kinds]
        binary_texts += extra
    elif data.startswith(b"\xff\xd8"):
        out += [Finding(where, 0, "image-metadata", f"JPEG marker {m:02X}")
                for m, raw in jpeg_segments(data) if _jpeg_metadata(m, raw)]
    else:
        text = _as_text(data)
        if text is not None:
            out += scan_text(path, text, cfg, strict)
            if path.lower().endswith(".svg") or "<svg" in text[:4096]:
                if SVG_META.search(text):
                    out.append(Finding(where, 0, "image-metadata", "SVG editor metadata"))
            return out
    readings = [cfg.unallow(r) for blob in binary_texts for r in _readings(blob)]
    if any(p.search(r) for p in cfg.patterns for r in readings):
        out.append(Finding(where, 0, "deny-list", "inside binary data"))
    for rule, pattern in PATTERN_RULES:
        if rule in ("github-token", "aws-key", "api-key", "private-key", "jwt") and any(pattern.search(r) for r in readings):
            out.append(Finding(where, 0, rule, "inside binary data"))
    return out

# ---------------------------------------------------------------------------------------------- trees and repositories


def scan_tree(root: Path | str, cfg: Config, strict: bool = True) -> list[Finding]:
    root = Path(root)
    out: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            out += scan_name(rel, cfg)
            out += scan_bytes(rel, full.read_bytes(), cfg, strict)
    return out


def _git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    cmd = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(repo), *args]
    result = subprocess.run(cmd, input=data, capture_output=True)
    if result.returncode != 0:
        raise ConfigError(f"git {args[0]} failed: {result.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return result.stdout


def _parse_batch(stream: bytes):
    pos = 0
    while pos < len(stream):
        nl = stream.index(b"\n", pos)
        header = stream[pos:nl].decode()
        parts = header.split()
        if len(parts) < 3 or parts[1] == "missing":
            pos = nl + 1
            continue
        sha, kind, size = parts[0], parts[1], int(parts[2])
        body = stream[nl + 1:nl + 1 + size]
        pos = nl + 1 + size + 1
        yield sha, kind, body


def _tree_names(body: bytes) -> list[str]:
    names, pos = [], 0
    while pos < len(body):
        space = body.index(b" ", pos)
        nul = body.index(b"\x00", space)
        names.append(body[space + 1:nul].decode("utf-8", "replace"))
        pos = nul + 21
    return names


def _identity_findings(where: str, header: str, cfg: Config) -> list[Finding]:
    out = []
    for line in header.split("\n"):
        role, _, rest = line.partition(" ")
        if role not in ("author", "committer", "tagger"):
            continue
        ident = " ".join(re.sub(r"\s+\d+\s+[+-]\d{4}$", "", rest).split())
        if cfg.approved_identities:
            if ident not in cfg.approved_identities:
                out.append(Finding(where, 0, "identity", f"{role} not approved: {peek(ident)}"))
        else:
            out += [Finding(where, 0, f.rule, f"{role}: {f.hint}") for f in scan_text(role, ident, cfg, strict=False)]
        if any(p.search(cfg.unallow(ident)) for p in cfg.patterns):
            out.append(Finding(where, 0, "deny-list", f"in the {role} header"))
    return out


def scan_objects(repo: Path, cfg: Config, strict: bool, shas: list[str] | None, paths: dict[str, str]) -> list[Finding]:
    if shas is None:
        stream = _git(repo, "cat-file", "--batch-all-objects", "--batch", "--unordered")
    else:
        stream = _git(repo, "cat-file", "--batch", data=("\n".join(shas) + "\n").encode())
    out: list[Finding] = []
    seen_names: set[str] = set()
    for sha, kind, body in _parse_batch(stream):
        short = sha[:10]
        if kind == "blob":
            path = paths.get(sha, "(unreachable)")
            out += [dataclasses.replace(f, where=f"blob {short} {f.where}") for f in scan_bytes(path, body, cfg, strict)]
        elif kind == "tree":
            for name in _tree_names(body):
                if name not in seen_names:
                    seen_names.add(name)
                    out += [dataclasses.replace(f, where=f"tree {short} {f.where}") for f in scan_name(name, cfg)]
        elif kind in ("commit", "tag"):
            text = body.decode("utf-8", "replace")
            header, _, message = text.partition("\n\n")
            header = re.sub(r"\ngpgsig [\s\S]*?-----END [A-Z ]+-----", "", header)
            where = f"{kind} {short}"
            out += _identity_findings(where, header, cfg)
            out += [dataclasses.replace(f, where=f"{where} message") for f in scan_text("message", message, cfg, strict)]
    return out


def _paths(repo: Path, *revs: str) -> tuple[list[str], dict[str, str]]:
    listing = _git(repo, "rev-list", "--objects", *revs).decode("utf-8", "replace")
    shas, paths = [], {}
    for line in listing.splitlines():
        sha, _, path = line.partition(" ")
        shas.append(sha)
        if path and sha not in paths:
            paths[sha] = path
    return shas, paths


def scan_repo(repo: Path | str, cfg: Config, strict: bool = True) -> list[Finding]:
    """Every object in the repository's database, reachable or not."""
    repo = Path(repo)
    has_refs = bool(_git(repo, "for-each-ref", "--count=1").strip())
    paths = _paths(repo, "--all", "--reflog")[1] if has_refs else {}
    return scan_objects(repo, cfg, strict, None, paths)

# ---------------------------------------------------------------------------------------------- hooks


HOOKS = ("pre-commit", "commit-msg", "pre-push")


def _python_command() -> str:
    if os.name == "nt" and shutil.which("py"):
        return "py -3"
    return "python3"


def install_hooks(repo: Path, identifiers: Path, extra: list[str], all_remotes: bool, python: str | None,
                  allow: list[str] | None = None) -> list[Path]:
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir").decode().strip())
    hooks = git_dir / "hooks"
    hooks.mkdir(exist_ok=True)
    me = Path(__file__).resolve().as_posix()
    # Every value is quoted for sh, so a $ or a backtick in a deny entry is never run.
    options = "--identifiers " + shlex.quote(identifiers.resolve().as_posix())
    options += "".join(" --deny " + shlex.quote(d) for d in extra)
    options += "".join(" --allow " + shlex.quote(a) for a in allow or [])
    options += " --all-remotes" if all_remotes else ""
    written = []
    for name in HOOKS:
        # git's own arguments come straight after the hook name: Python 3.10's argparse cannot take
        # positionals that follow options.
        script = ("#!/bin/sh\n"
                  "# Installed by portfolio-shield. Do not bypass with --no-verify.\n"
                  f'exec {python or _python_command()} {shlex.quote(me)} hook {name} "$@" {options} '
                  f'--repo "$(git rev-parse --show-toplevel)"\n')
        target = hooks / name
        target.write_text(script, encoding="utf-8", newline="\n")
        target.chmod(0o755)
        written.append(target)
    return written


def _ident(var: str, repo: Path) -> str:
    raw = _git(repo, "var", var).decode("utf-8", "replace").strip()
    return " ".join(re.sub(r"\s+\d+\s+[+-]\d{4}$", "", raw).split())


def hook_pre_commit(repo: Path, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    names = _git(repo, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT").decode("utf-8").split("\0")
    for name in filter(None, names):
        out += scan_name(name, cfg)
        out += scan_bytes(name, _git(repo, "cat-file", "blob", f":{name}"), cfg, strict=True)
    for var, role in (("GIT_AUTHOR_IDENT", "author"), ("GIT_COMMITTER_IDENT", "committer")):
        out += _identity_findings("identity", f"{role} {_ident(var, repo)}", cfg)
    return out


def hook_commit_msg(message_file: Path, cfg: Config) -> list[Finding]:
    text = message_file.read_text(encoding="utf-8", errors="replace")
    text = "\n".join(line for line in text.split("\n") if not line.startswith("#"))
    return scan_text("commit message", text, cfg, strict=True)


def hook_pre_push(repo: Path, cfg: Config, url: str, stdin: str, all_remotes: bool) -> list[Finding] | None:
    if not all_remotes and "github.com" not in url.lower():
        return None
    out: list[Finding] = []
    for line in stdin.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == ZERO_SHA:
            continue
        shas, paths = _paths(repo, parts[1])
        out += scan_objects(repo, cfg, True, shas, paths)
    return out

# ---------------------------------------------------------------------------------------------- command line


def _report(findings: list[Finding], what: str) -> int:
    unique = list(dict.fromkeys(findings))
    for f in unique:
        print(f.render())
    if unique:
        print(f"portfolio-shield: {len(unique)} finding(s) in {what}. Nothing was changed.", file=sys.stderr)
        return 1
    print(f"portfolio-shield: [VERIFIED] 0 findings in {what}.")
    return 0


def _load(args, strict: bool) -> Config:
    path = find_config(args.identifiers)
    if path is None:
        if strict:
            raise ConfigError("strict mode needs an identifiers file (--identifiers or " + ENV_CONFIG + ")")
        print("portfolio-shield: no identifiers file; running the built-in rules only.", file=sys.stderr)
        cfg = Config()
    else:
        cfg = load_config(path)
    if strict and not cfg.approved_identities:
        raise ConfigError("strict mode needs approved_identities in the identifiers file")
    return cfg.with_extra(args.deny or [], args.allow or [])


def main(argv: list[str] | None = None, stdin: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog="portfolio_shield", description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--identifiers", help="the private identifiers JSON file")
        p.add_argument("--deny", action="append", help="an extra deny-list entry for this run (repeatable)")
        p.add_argument("--allow", action="append", help="an exact string no rule may flag, for this run (repeatable)")

    scan = sub.add_parser("scan", help="scan files, folders and whole repositories")
    scan.add_argument("paths", nargs="+")
    scan.add_argument("--strict", action="store_true", help="also flag high-entropy runs; require identities")
    scan.add_argument("--no-history", action="store_true", help="skip the repository object database")
    common(scan)

    strip = sub.add_parser("strip", help="remove metadata from PNG, JPEG and SVG files in place")
    strip.add_argument("paths", nargs="+")

    hook = sub.add_parser("install-hook", help="install pre-commit, commit-msg and pre-push hooks")
    hook.add_argument("repo")
    hook.add_argument("--all-remotes", action="store_true", help="check pushes to every remote, not only github.com")
    hook.add_argument("--python", help="the command the hooks use to run Python")
    common(hook)

    run = sub.add_parser("hook", help=argparse.SUPPRESS)
    run.add_argument("kind", choices=HOOKS)
    run.add_argument("rest", nargs="*")
    run.add_argument("--repo", default=".")
    run.add_argument("--all-remotes", action="store_true")
    common(run)

    args = parser.parse_args(argv)
    try:
        if args.command == "strip":
            return _strip(args.paths)
        if args.command == "install-hook":
            ids = find_config(args.identifiers)
            if ids is None or not ids.is_file():
                raise ConfigError("install-hook needs an existing identifiers file")
            load_config(ids)
            for path in install_hooks(Path(args.repo), ids, args.deny or [], args.all_remotes, args.python, args.allow or []):
                print(f"installed {path.name}")
            return 0
        cfg = _load(args, strict=args.command == "hook" or args.strict)
        if args.command == "scan":
            findings: list[Finding] = []
            for raw in args.paths:
                path = Path(raw)
                if path.is_file():
                    findings += scan_name(path.name, cfg) + scan_bytes(path.name, path.read_bytes(), cfg, args.strict)
                elif path.is_dir():
                    findings += scan_tree(path, cfg, args.strict)
                    if (path / ".git").exists() and not args.no_history:
                        findings += scan_repo(path, cfg, args.strict)
                else:
                    raise ConfigError(f"no such file or folder: {path.name}")
            return _report(findings, f"{len(args.paths)} path(s)")
        repo = Path(args.repo)
        if args.kind == "pre-commit":
            return _report(hook_pre_commit(repo, cfg), "the staged changes")
        if args.kind == "commit-msg":
            return _report(hook_commit_msg(Path(args.rest[0]), cfg), "the commit message")
        url = args.rest[1] if len(args.rest) > 1 else ""
        found = hook_pre_push(repo, cfg, url, sys.stdin.read() if stdin is None else stdin, args.all_remotes)
        if found is None:
            print("portfolio-shield: not a github.com remote; push not checked (use --all-remotes to check every push).")
            return 0
        return _report(found, "the commits being pushed")
    except ConfigError as err:
        print(f"portfolio-shield: {err}", file=sys.stderr)
        return 2


def _strip(paths: list[str]) -> int:
    targets: list[Path] = []
    for raw in paths:
        p = Path(raw)
        targets += [q for q in p.rglob("*") if q.is_file()] if p.is_dir() else [p]
    for path in targets:
        suffix = path.suffix.lower()
        data = path.read_bytes()
        if suffix == ".png" and data.startswith(PNG_SIG):
            new = strip_png(data)
        elif suffix in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8"):
            new = strip_jpeg(data)
        elif suffix == ".svg":
            new = strip_svg(data.decode("utf-8")).encode("utf-8")
        else:
            continue
        if new != data:
            path.write_bytes(new)
            print(f"stripped {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
