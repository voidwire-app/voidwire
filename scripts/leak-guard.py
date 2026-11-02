#!/usr/bin/env python3
"""Leak guard: fail if the tree or the pushed commit messages match the denylist.

    REPO_DENYLIST='a,b\\.example' scripts/leak-guard.py [--range BASE..HEAD]
    scripts/leak-guard.py --github     # in Actions: range from the push or pull request
    scripts/leak-guard.py --self-test

REPO_DENYLIST is a GitHub Actions secret: comma-separated patterns, matched
case-insensitively as regular expressions (a plain word is a valid regex).
The patterns are never stored in the repository and are never printed: a hit
reports only the file and line (or the commit and message line), so the log
doesn't repeat what it is guarding. If the secret is unset (a fork's pull
request, or not configured yet) the guard warns and passes.

Scanned: every tracked file (path and contents; binary files by path only)
and, with --range, the message of every commit in the range."""
import os, re, subprocess, sys

sys.dont_write_bytecode = True


def patterns(raw):
    out = []
    for i, p in enumerate(x.strip() for x in raw.split(",")):
        if not p:
            continue
        try:
            out.append(re.compile(p, re.I))
        except re.error:
            sys.exit(f"leak-guard: denylist entry #{i + 1} is not a valid regex")
    return out


def hit(pats, text):
    return any(p.search(text) for p in pats)


def scan_files(pats, root="."):
    found = []
    names = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True,
                           capture_output=True).stdout.decode("utf-8", "surrogateescape").split("\0")
    for name in filter(None, names):
        if hit(pats, name):
            found.append(f"{name}: file path")
        path = os.path.join(root, name)
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        if b"\0" in data[:8192]:
            continue
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            if hit(pats, line):
                found.append(f"{name}:{n}")
    return found


def scan_commits(pats, rng, root="."):
    found = []
    out = subprocess.run(["git", "-C", root, "log", "--format=%H%x00%B%x01", rng], check=True,
                         capture_output=True).stdout.decode("utf-8", "replace")
    for rec in filter(str.strip, out.split("\x01")):
        sha, _, msg = rec.strip("\n").partition("\0")
        for n, line in enumerate(msg.splitlines(), 1):
            if hit(pats, line):
                found.append(f"commit {sha[:12]} message line {n}")
        # author and committer identities too
        ident = subprocess.run(["git", "-C", root, "log", "-1", "--format=%an %ae %cn %ce", sha],
                               check=True, capture_output=True, text=True).stdout
        if hit(pats, ident):
            found.append(f"commit {sha[:12]} author/committer")
    return found


def github_range():
    """BASE..HEAD for the event that started the run. A new branch or a force
    push whose old head is gone falls back to the head commit alone."""
    import json
    ev = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
    if "pull_request" in ev:
        base, head = ev["pull_request"]["base"]["sha"], ev["pull_request"]["head"]["sha"]
    else:
        base, head = ev.get("before", ""), os.environ.get("GITHUB_SHA", "HEAD")
    known = base and set(base) != {"0"} and subprocess.run(
        ["git", "cat-file", "-e", f"{base}^{{commit}}"], capture_output=True).returncode == 0
    if not known:
        print("::warning::leak-guard: push range unknown (new branch or force push); scanning the head commit only")
        return f"{head}~1..{head}" if subprocess.run(["git", "rev-parse", "-q", "--verify", f"{head}~1"],
                                                    capture_output=True).returncode == 0 else head
    return f"{base}..{head}"


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        g = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
        g("init", "-q")
        g("config", "user.name", "T"); g("config", "user.email", "t@example.invalid")
        open(os.path.join(d, "ok.txt"), "w").write("nothing here\n")
        g("add", "."); g("commit", "-qm", "first")
        open(os.path.join(d, "a.txt"), "w").write("line one\nSecret-Host.example here\n")
        open(os.path.join(d, "bin.dat"), "wb").write(b"\0secret-host.example")
        g("add", "."); g("commit", "-qm", "second\n\nmentions SECRET-HOST.EXAMPLE")
        pats = patterns(r" secret-host\.example , ,")
        assert scan_files(pats, d) == ["a.txt:2"], scan_files(pats, d)
        assert scan_commits(pats, "HEAD~1..HEAD", d) == [f"commit {subprocess.run(['git','-C',d,'rev-parse','HEAD'],capture_output=True,text=True).stdout[:12]} message line 3"]
        assert scan_commits(pats, "HEAD~1", d) == []
        assert scan_files(patterns("nomatch"), d) == []
        try:
            patterns("ok,(")
            raise AssertionError("accepted a bad regex")
        except SystemExit as e:
            assert "(" not in str(e)
    print("leak-guard self-test: ok")


def main():
    a = sys.argv[1:]
    if a == ["--self-test"]:
        return self_test()
    raw = os.environ.get("REPO_DENYLIST", "")
    if not raw.strip():
        print("::warning::REPO_DENYLIST is not set; leak guard skipped")
        return
    rng = a[a.index("--range") + 1] if "--range" in a else (github_range() if "--github" in a else "")
    pats = patterns(raw)
    found = scan_files(pats)
    if rng:
        found += scan_commits(pats, rng)
    if found:
        for f in found:
            print(f"::error::leak-guard: denylisted text in {f}")
        sys.exit(f"leak-guard: {len(found)} hit(s); remove them (patterns are not shown)")
    print(f"leak-guard: ok ({len(pats)} patterns, tree{' + ' + rng if rng else ''})")


if __name__ == "__main__":
    main()
