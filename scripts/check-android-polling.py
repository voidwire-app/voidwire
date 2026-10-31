#!/usr/bin/env python3
"""Gate: no polling in the Android app (owner rule: no timers, no polling,
no keep-alive, never hurt phone battery). The app refreshes on core change
events (IncomingEvents.kt). Fails on:
- Thread.sleep;
- repeating timers and schedulers: java.util.Timer, kotlin timer/fixedRateTimer,
  scheduleAtFixedRate/scheduleWithFixedDelay, ScheduledExecutorService and
  scheduled thread pools, coroutine ticker, WorkManager periodic work,
  AlarmManager setRepeating/setInexactRepeating;
- a Handler runnable that re-posts itself (postDelayed(this, ...) or
  postDelayed(<its own name>, ...));
- a while, do-while, for or repeat loop whose body waits (delay, sleep,
  awaitNanos, postDelayed), so it wakes on a timer.
A line may be allowed only with `// polling-allowed: <reason>` on it.
`--self-test` checks the gate against known bad and good snippets."""
import pathlib, re, sys

TIMERS = [
    (r"\bTimer\s*\(", "java.util.Timer"),
    (r"\b(fixedRateTimer|timer)\s*\(", "kotlin.concurrent timer"),
    (r"\bschedule(AtFixedRate|WithFixedDelay)\s*\(", "fixed-rate schedule"),
    (r"\bScheduledExecutorService\b|\bnewScheduledThreadPool\b|\bnewSingleThreadScheduledExecutor\b|\bScheduledThreadPoolExecutor\b", "scheduled executor"),
    (r"\bticker\s*\(", "coroutine ticker"),
    (r"\bPeriodicWorkRequest|\benqueueUniquePeriodicWork\b", "WorkManager periodic work"),
    (r"\bset(Inexact)?Repeating\s*\(", "AlarmManager repeating alarm"),
    (r"\bThread\.sleep\s*\(", "Thread.sleep"),
]
WAITS = r"\b(delay|sleep|awaitNanos|postDelayed)\s*\("


def strip_comments(src):
    return "\n".join(l.split("//", 1)[0] for l in src.split("\n"))


def block_end(src, j):
    """`src[j]` is '{': index just past its matching '}'."""
    k, depth = j + 1, 1
    while k < len(src) and depth:
        depth += {"{": 1, "}": -1}.get(src[k], 0)
        k += 1
    return k


def after_parens(src, i):
    """`src[i-1]` is '(': index just past its matching ')'."""
    depth = 1
    while i < len(src) and depth:
        depth += {"(": 1, ")": -1}.get(src[i], 0)
        i += 1
    return i


def next_brace(src, i):
    while i < len(src) and src[i] in " \t\r\n":
        i += 1
    return i if i < len(src) and src[i] == "{" else None


def check(name, src):
    raw_lines = src.split("\n")
    code = strip_comments(src)
    bad = []

    def allowed(ln):
        return "polling-allowed:" in raw_lines[ln - 1]

    def line_of(pos):
        return code.count("\n", 0, pos) + 1

    for pat, what in TIMERS:
        for m in re.finditer(pat, code):
            ln = line_of(m.start())
            if not allowed(ln):
                bad.append(f"{name}:{ln}: {what}")
    for m in re.finditer(r"\bpostDelayed\s*\(\s*this\b", code):
        ln = line_of(m.start())
        if not allowed(ln):
            bad.append(f"{name}:{ln}: Handler runnable re-posts itself")
    for m in re.finditer(r"\b(?:val|var)\s+(\w+)\b[^=\n]*=\s*(?:object\s*:\s*)?Runnable\b[^{]*", code):
        j = next_brace(code, m.end())
        if j is None:
            continue
        body = code[j:block_end(code, j)]
        if re.search(r"\bpostDelayed\s*\(\s*" + re.escape(m.group(1)) + r"\b", body):
            ln = line_of(m.start())
            if not allowed(ln):
                bad.append(f"{name}:{ln}: Handler runnable re-posts itself")
    loops = []
    for m in re.finditer(r"\b(while|for|repeat)\s*\(", code):
        loops.append((m.start(), next_brace(code, after_parens(code, m.end()))))
    for m in re.finditer(r"\bdo\s*\{", code):
        loops.append((m.start(), m.end() - 1))
    for start, j in loops:
        if j is None:
            continue
        ln = line_of(start)
        if allowed(ln):
            continue
        if re.search(WAITS, code[j:block_end(code, j)]):
            bad.append(f"{name}:{ln}: loop waits on a timer (polling)")
    return sorted(set(bad))


BAD = {
    "java Timer": "fun start() { java.util.Timer().schedule(object : TimerTask() { override fun run() { poll() } }, 0, 2000) }",
    "kotlin timer": "val t = fixedRateTimer(period = 2000) { poll() }",
    "scheduleAtFixedRate": "exec.scheduleAtFixedRate({ poll() }, 0, 2, TimeUnit.SECONDS)",
    "scheduleWithFixedDelay": "exec.scheduleWithFixedDelay({ poll() }, 0, 2, TimeUnit.SECONDS)",
    "scheduled executor": "val e: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()",
    "handler self-repost this": "handler.post(object : Runnable { override fun run() { poll(); handler.postDelayed(this, 2000) } })",
    "handler self-repost name": "val tick = Runnable { poll(); handler.postDelayed(tick, 2000) }",
    "while delay": "scope.launch { while (true) { poll(); delay(2000) } }",
    "do-while delay": "scope.launch { do { poll(); delay(2000) } while (true) }",
    "repeat delay": "scope.launch { repeat(Int.MAX_VALUE) { poll(); delay(2000) } }",
    "for delay": "scope.launch { for (i in 0..Int.MAX_VALUE) { poll(); delay(2000) } }",
    "ticker": "val t = ticker(2000)",
    "workmanager periodic": "val r = PeriodicWorkRequestBuilder<PollWorker>(15, TimeUnit.MINUTES).build()",
    "alarm repeating": "am.setRepeating(AlarmManager.RTC, 0, 60000, pi)",
    "inexact alarm": "am.setInexactRepeating(AlarmManager.RTC, 0, 60000, pi)",
    "sleep": "Thread.sleep(2000)",
}
GOOD = {
    "one-shot delay": "scope.launch { delay(1500); done() }",
    "one-shot postDelayed": "handler.postDelayed({ armed = true }, 600)",
    "plain loops": "for (pc in pcs) { show(pc) }\nrepeat(3) { add() }\nwhile (i < n) { i++ }",
    "allowed": "while (showing) { // polling-allowed: on-screen countdown\n delay(1000) }",
    "comment": "// a Timer( would be bad\nval x = 1",
}


def self_test():
    fails = [k for k, s in BAD.items() if not check(k, s)]
    fails += [k for k, s in GOOD.items() if check(k, s)]
    for k in fails:
        print(f"      self-test: {k}")
    return not fails


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(0 if self_test() else 1)
    if not self_test():
        sys.exit(1)
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "android/app/src/main")
    bad = []
    for f in sorted(root.rglob("*.kt")):
        if "uniffi" in f.parts:
            continue
        bad += check(str(f), f.read_text())
    for b in bad:
        print("      " + b)
    sys.exit(1 if bad else 0)
