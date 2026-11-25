"""Tests for portfolio_shield. Standard library only: run with `python -m unittest` or pytest.

Every string a rule should catch is built at run time from pieces, so this file itself scans clean.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import portfolio_shield as ps  # noqa: E402

GOOD_NAME = "Test Person"
GOOD_MAIL = "1+tester" + "@" + "users.noreply.github.com"
GOOD_IDENT = f"{GOOD_NAME} <{GOOD_MAIL}>"

# Pieces, joined at run time.
WIN_PATH = "C:" + "\\" + "Users" + "\\" + "alice" + "\\" + "notes.txt"
NIX_PATH = "/" + "home" + "/" + "alice" + "/project"
LAN = "192." + "168.4.20"
LAN10 = "10." + "1.2.3"
CGNAT = "100." + "101.7.9"
TS_V6 = "fd7a:" + "115c:a1e0::1"
TS_NAME = "box." + "tail1234.ts" + ".net"
MAC = "3c:" + "22:fb:01:aa:9e"
GH_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9" + "j0K1l2M3n4O5p6Q7r8"
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
JWT = "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0.abc"
HOOK = "https://hooks." + "slack.com/services/T000/B000/XXXX"
ASSIGN = "api_key" + ' = "' + "Zq8wPl3mN0vR7tY2" + '"'
BAD_MAIL = "someone" + "@" + "privatemail.net"
ENTROPY = "aZ3" + "kP9qL2xW7vB4nM8rT1yU6sD5fG0hJcE" + "Qo"
DENY = "zorblax"
# The hooks must run under the interpreter running these tests, so every supported version is really tested.
PY = shlex.quote(Path(sys.executable).as_posix())


def config(tmp: Path, **extra) -> Path:
    data = {
        "deny": [DENY, "=Vorpex", ":4242"],
        "cidrs": ["203.0.113.0/24"],
        "allowed_emails": ["hello" + "@" + "public.example"],
        "approved_identities": [GOOD_IDENT],
    }
    data.update(extra)
    path = tmp / "ids.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def rules_of(findings):
    return {f.rule for f in findings}


def png(extra_chunks=()):
    """A 1x1 RGB PNG, with any extra chunks placed before IDAT."""
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x80\x00")
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    for kind, body in extra_chunks:
        out += chunk(kind, body)
    return out + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def jpeg(with_exif: bool):
    seg = lambda marker, body: b"\xff" + bytes([marker]) + struct.pack(">H", len(body) + 2) + body
    out = b"\xff\xd8" + seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    if with_exif:
        out += seg(0xE1, b"Exif\x00\x00" + b"camera-owner")
        out += seg(0xFE, b"a comment")
    out += seg(0xDB, b"\x00" + bytes(64))
    out += seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x12\x34\xff\x00\x56" + b"\xff\xd9"
    return out


def git(repo: Path, *args: str, env=None, check=True) -> subprocess.CompletedProcess:
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=e, check=check)


def ident_env(name=GOOD_NAME, mail=GOOD_MAIL):
    return {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": mail, "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": mail}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="shield-"))
        self.cfg = ps.load_config(config(self.tmp))

    def tearDown(self):
        def retry(func, path, _info):
            os.chmod(path, 0o700)
            func(path)
        if sys.version_info >= (3, 12):
            shutil.rmtree(self.tmp, onexc=retry)
        else:
            shutil.rmtree(self.tmp, onerror=retry)

    def scan(self, text, path="notes.md", strict=True):
        return ps.scan_text(path, text, self.cfg, strict=strict)


class TextRules(Base):
    def test_each_rule_fires(self):
        cases = {
            "windows-user-path": WIN_PATH, "home-path": NIX_PATH, "private-ip": LAN, "private-ip ": LAN10,
            "cgnat-ip": CGNAT, "ts-ipv6": TS_V6, "ts-hostname": TS_NAME, "mac-address": MAC,
            "github-token": GH_TOKEN, "aws-key": AWS, "private-key": PEM, "jwt": JWT, "webhook": HOOK,
            "secret-assignment": ASSIGN, "email": BAD_MAIL, "deny-list": "a " + DENY.upper() + " b",
            "custom-cidr": "203." + "0.113.9", "high-entropy": "token " + ENTROPY,
        }
        for rule, text in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule.strip(), rules_of(self.scan(f"line one\nsay {text} here\n")))

    def test_line_numbers(self):
        found = self.scan("ok\nok\n" + LAN + "\n")
        self.assertEqual([f.line for f in found], [3])

    def test_clean_text(self):
        at = "@"
        text = ("Public DNS 8.8.8.8, version 1.2.3, git sha " + "3f786850e387550f" + "dab836ed7e6dc881de23001b,\n"
                f"contact hello{at}public.example or 1+x{at}users.noreply.github.com, icon{at}2x.png, user{at}example.com\n")
        self.assertEqual(self.scan(text), [])

    def test_case_sensitive_word_entry(self):
        self.assertIn("deny-list", rules_of(self.scan("by Vorpex today")))
        self.assertIn("deny-list", rules_of(self.scan("Vorpex_v2")))
        self.assertNotIn("deny-list", rules_of(self.scan("vorpex lowercase and Vorpexes plural")))

    def test_port_entry(self):
        self.assertIn("deny-list", rules_of(self.scan("ssh://h" + ":4242/x")))

    def test_entropy_only_when_strict(self):
        self.assertNotIn("high-entropy", rules_of(self.scan(ENTROPY, strict=False)))
        self.assertNotIn("high-entropy", rules_of(self.scan(ENTROPY, path="Cargo.lock", strict=True)))

    def test_report_never_prints_the_value(self):
        for text in (GH_TOKEN, DENY, BAD_MAIL, LAN):
            for f in self.scan(text):
                self.assertNotIn(text, f.render())
                self.assertNotIn(DENY, f.render().lower())


class FileNames(Base):
    def test_sensitive_names(self):
        for name in (".env", "app/.env.production", "id_rsa", "keys/server.pem", "x.key", "vault.dpapi",
                     ".claude/settings.json", "CLAUDE.local.md", ".mcp.json", "logs/session.jsonl",
                     "credentials.json"):
            with self.subTest(name=name):
                self.assertIn("sensitive-file", rules_of(ps.scan_name(name, self.cfg)))

    def test_ordinary_names(self):
        for name in (".env.example", "README.md", "src/keyboard.rs", "docs/claude-code.md"):
            with self.subTest(name=name):
                self.assertEqual(ps.scan_name(name, self.cfg), [])

    def test_deny_in_name(self):
        self.assertIn("deny-list", rules_of(ps.scan_name("docs/" + DENY + "-plan.md", self.cfg)))


class Pictures(Base):
    def test_png_text_chunks_found_and_stripped(self):
        for kind in (b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"tIME"):
            with self.subTest(kind=kind):
                data = png([(kind, b"Author\x00someone")])
                self.assertIn("image-metadata", rules_of(ps.scan_bytes("a.png", data, self.cfg, strict=True)))
                clean = ps.strip_png(data)
                self.assertEqual(clean, png())
                self.assertEqual(ps.scan_bytes("a.png", clean, self.cfg, strict=True), [])

    def test_png_deny_string_inside_text_chunk(self):
        data = png([(b"tEXt", b"Comment\x00" + DENY.encode())])
        self.assertIn("deny-list", rules_of(ps.scan_bytes("a.png", data, self.cfg, strict=True)))

    def test_jpeg_exif_found_and_stripped(self):
        data = jpeg(with_exif=True)
        self.assertIn("image-metadata", rules_of(ps.scan_bytes("a.jpg", data, self.cfg, strict=True)))
        clean = ps.strip_jpeg(data)
        self.assertEqual(clean, jpeg(with_exif=False))

    def test_svg_metadata_found_and_stripped(self):
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" xmlns:sodipodi="x" sodipodi:docname="draft.svg">'
               '<metadata><rdf:RDF>owner</rdf:RDF></metadata><rect width="1" height="1"/></svg>')
        self.assertIn("image-metadata", rules_of(ps.scan_bytes("a.svg", svg.encode(), self.cfg, strict=True)))
        clean = ps.strip_svg(svg)
        self.assertNotIn("metadata", clean)
        self.assertNotIn("docname", clean)
        self.assertIn('<rect width="1" height="1"/>', clean)

    def test_strip_command_rewrites_files(self):
        target = self.tmp / "pic.png"
        target.write_bytes(png([(b"tEXt", b"Software\x00x")]))
        self.assertEqual(ps.main(["strip", str(target)]), 0)
        self.assertEqual(target.read_bytes(), png())

    def test_text_with_a_stray_byte_is_still_text(self):
        data = b"caf\xe9 at " + LAN.encode() + b"\n"
        self.assertIn("private-ip", rules_of(ps.scan_bytes("notes.txt", data, self.cfg, strict=True)))

    def test_binary_wide_string(self):
        data = b"\x00\x01" + DENY.encode("utf-16-le") + b"\x00\xff"
        self.assertIn("deny-list", rules_of(ps.scan_bytes("blob.bin", data, self.cfg, strict=True)))


class RepoMixin:
    tmp: Path

    def make_repo(self) -> Path:
        repo = self.tmp / "repo"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "commit.gpgsign", "false")
        return repo

    def commit(self, repo, files: dict, message="add", env=None):
        for name, text in files.items():
            p = repo / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", message, env=env or ident_env())


class GitHistory(RepoMixin, Base):
    def test_clean_repo(self):
        repo = self.make_repo()
        self.commit(repo, {"README.md": "hello\n"})
        self.assertEqual(ps.scan_repo(repo, self.cfg, strict=True), [])

    def test_unapproved_author(self):
        repo = self.make_repo()
        self.commit(repo, {"a.txt": "x\n"}, env=ident_env("Someone", "someone@" + "laptop.local"))
        found = ps.scan_repo(repo, self.cfg, strict=True)
        self.assertIn("identity", rules_of(found))
        self.assertTrue(all(len(f.where) >= 7 for f in found))

    def test_deleted_secret_still_found_in_history(self):
        repo = self.make_repo()
        self.commit(repo, {"cfg.txt": "token " + GH_TOKEN + "\n"})
        (repo / "cfg.txt").unlink()
        self.commit(repo, {"README.md": "clean now\n"}, message="remove")
        self.assertEqual(ps.scan_tree(repo, self.cfg, strict=True), [])
        found = ps.scan_repo(repo, self.cfg, strict=True)
        self.assertIn("github-token", rules_of(found))
        self.assertTrue(any("cfg.txt" in f.where for f in found))

    def test_unreachable_object_found(self):
        repo = self.make_repo()
        self.commit(repo, {"README.md": "one\n"})
        self.commit(repo, {"leak.txt": LAN + "\n"}, message="oops")
        git(repo, "reset", "-q", "--hard", "HEAD~1")
        found = ps.scan_repo(repo, self.cfg, strict=True)
        self.assertIn("private-ip", rules_of(found))

    def test_commit_message_and_file_name(self):
        repo = self.make_repo()
        self.commit(repo, {".env": "A=1\n"}, message="notes for " + DENY)
        found = rules_of(ps.scan_repo(repo, self.cfg, strict=True))
        self.assertIn("sensitive-file", found)
        self.assertIn("deny-list", found)


class Hooks(RepoMixin, Base):
    def install(self, repo):
        cfg_path = config(self.tmp)
        self.assertEqual(ps.main(["install-hook", str(repo), "--identifiers", str(cfg_path), "--python", PY]), 0)
        for name in ("pre-commit", "commit-msg", "pre-push"):
            self.assertTrue((repo / ".git" / "hooks" / name).is_file(), name)
        return cfg_path

    def test_pre_commit_blocks_and_allows(self):
        repo = self.make_repo()
        self.install(repo)
        (repo / "a.txt").write_text("server at " + LAN + "\n", encoding="utf-8")
        git(repo, "add", "a.txt")
        bad = git(repo, "commit", "-q", "-m", "add", env=ident_env(), check=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("private-ip", bad.stdout + bad.stderr)
        self.assertEqual(git(repo, "rev-list", "--all").stdout.strip(), "")
        (repo / "a.txt").write_text("all clean\n", encoding="utf-8")
        git(repo, "add", "a.txt")
        ok = git(repo, "commit", "-q", "-m", "add", env=ident_env(), check=False)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

    def test_hook_arguments_are_quoted(self):
        repo = self.make_repo()
        cfg_path = config(self.tmp)
        planted = "x$(touch PLANTED)`touch PLANTED2`y"
        self.assertEqual(ps.main(["install-hook", str(repo), "--identifiers", str(cfg_path), "--deny", planted,
                                  "--python", PY]), 0)
        (repo / "a.txt").write_text("fine\n", encoding="utf-8")
        git(repo, "add", "a.txt")
        git(repo, "commit", "-q", "-m", "add", env=ident_env(), check=False)
        self.assertFalse((repo / "PLANTED").exists())
        self.assertFalse((repo / "PLANTED2").exists())

    def test_pre_commit_blocks_wrong_identity(self):
        repo = self.make_repo()
        self.install(repo)
        (repo / "a.txt").write_text("fine\n", encoding="utf-8")
        git(repo, "add", "a.txt")
        bad = git(repo, "commit", "-q", "-m", "add", env=ident_env("Me", "me@" + "pc.local"), check=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("identity", bad.stdout + bad.stderr)

    def test_commit_msg_blocks(self):
        repo = self.make_repo()
        self.install(repo)
        (repo / "a.txt").write_text("fine\n", encoding="utf-8")
        git(repo, "add", "a.txt")
        bad = git(repo, "commit", "-q", "-m", "for " + DENY, env=ident_env(), check=False)
        self.assertNotEqual(bad.returncode, 0)

    def test_pre_push(self):
        repo = self.make_repo()
        cfg_path = self.install(repo)
        self.commit(repo, {"a.txt": "fine\n"})
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        line = f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
        args = ["hook", "pre-push", "origin", "https://github.com/x/y.git", "--identifiers", str(cfg_path),
                "--repo", str(repo)]
        self.assertEqual(ps.main(args, stdin=line), 0)
        # A bad commit bypassing the commit hooks is still caught at push time.
        (repo / "b.txt").write_text(PEM + "\n", encoding="utf-8")
        git(repo, "add", "b.txt")
        git(repo, "commit", "-q", "--no-verify", "-m", "b", env=ident_env())
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        line = f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
        self.assertEqual(ps.main(args, stdin=line), 1)
        other = ["hook", "pre-push", "origin", "ssh://git" + "@" + "forge.internal/x.git", "--identifiers", str(cfg_path),
                 "--repo", str(repo)]
        self.assertEqual(ps.main(other, stdin=line), 0)


class Cli(Base):
    def test_exit_codes(self):
        (self.tmp / "clean").mkdir()
        (self.tmp / "clean" / "a.md").write_text("fine\n", encoding="utf-8")
        cfg_path = str(config(self.tmp))
        self.assertEqual(ps.main(["scan", str(self.tmp / "clean"), "--strict", "--identifiers", cfg_path]), 0)
        (self.tmp / "clean" / "b.md").write_text(LAN + "\n", encoding="utf-8")
        self.assertEqual(ps.main(["scan", str(self.tmp / "clean"), "--strict", "--identifiers", cfg_path]), 1)

    def test_strict_needs_identifiers(self):
        (self.tmp / "d").mkdir()
        missing = str(self.tmp / "nope.json")
        self.assertEqual(ps.main(["scan", str(self.tmp / "d"), "--strict", "--identifiers", missing]), 2)

    def test_extra_deny(self):
        (self.tmp / "d").mkdir()
        (self.tmp / "d" / "a.md").write_text("about quillfeather\n", encoding="utf-8")
        cfg_path = str(config(self.tmp))
        self.assertEqual(ps.main(["scan", str(self.tmp / "d"), "--identifiers", cfg_path]), 0)
        self.assertEqual(ps.main(["scan", str(self.tmp / "d"), "--identifiers", cfg_path,
                                  "--deny", "quillfeather"]), 1)

    def test_allow_waives_exact_strings_only(self):
        cfg = ps.load_config(config(self.tmp, allow=["zorblax-public"]))
        self.assertEqual(ps.scan_text("a.md", "see zorblax-public/repo", cfg, strict=True), [])
        self.assertIn("deny-list", rules_of(ps.scan_text("a.md", "see zorblax-public and Zorblax", cfg, strict=True)))
        (self.tmp / "d").mkdir()
        (self.tmp / "d" / "a.md").write_text("charset " + ENTROPY + "\n", encoding="utf-8")
        cfg_path = str(config(self.tmp))
        self.assertEqual(ps.main(["scan", str(self.tmp / "d"), "--strict", "--identifiers", cfg_path]), 1)
        self.assertEqual(ps.main(["scan", str(self.tmp / "d"), "--strict", "--identifiers", cfg_path,
                                  "--allow", ENTROPY]), 0)

    def test_allowed_string_inside_approved_identity(self):
        ident = "Some One <9+" + DENY + "-public" + "@" + "users.noreply.github.com>"
        cfg = ps.load_config(config(self.tmp, approved_identities=[ident], allow=[DENY + "-public"]))
        self.assertEqual(ps._identity_findings("commit x", "author " + ident + " 1700000000 +0000", cfg), [])
        bad = "Some One <" + DENY + "@" + "users.noreply.github.com>"
        found = rules_of(ps._identity_findings("commit x", "author " + bad + " 1700000000 +0000", cfg))
        self.assertEqual(found, {"identity", "deny-list"})

    def test_denylist_files_are_read(self):
        extra = self.tmp / "deny.txt"
        extra.write_text("# comment\nmoonpetal\n", encoding="utf-8")
        cfg = ps.load_config(config(self.tmp, denylist_files=[str(extra)]))
        self.assertIn("deny-list", rules_of(ps.scan_text("a.md", "the Moonpetal plan", cfg, strict=True)))


if __name__ == "__main__":
    unittest.main()
