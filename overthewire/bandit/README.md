# OverTheWire: Bandit

**Status:** Complete (bandit0 → bandit33)

Grouped by technique/vulnerability class rather than by individual level — several levels share the same underlying lesson. See [raw-notes.txt](raw-notes.txt) for the per-level command log kept during the exercise.

---

## 1. Cron job exploitation (bandit21–24)

**Objective:** escalate to the next user by exploiting scheduled jobs running as that user.

**Recon:** listed `/etc/cron.d/`, read the scripts directly (`cat`) to see what each job did and where it wrote output.

**Vulnerability / weak point:** jobs staged secrets through world-readable or predictably-named files in shared temp directories, and one job ran from a directory writable by the current user.

**Exploitation:**

Read the job script to see where it wrote the secret, then timed reads against
the cron schedule to catch it in `/tmp` before cleanup:
```
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/<leaked_filename>
```

Next job computed its output filename from a fixed string via md5sum instead
of randomizing it, so the filename could be derived directly:
```
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
cat /tmp/<derived_filename>
```

Last one ran a script from a directory writable by the current user, so a
self-authored payload could be dropped in and would run as the target user
on the next tick:
```
mktemp -d
# write payload script that copies the target password to a path we own
cp payload.sh /var/spool/<target_job_dir>/payload.sh
# wait for next cron tick, then read the result
```

**Root cause:** scheduled jobs trusted shared, world-accessible temp locations and writable directories as safe staging areas for secrets/scripts — the exposure window and the directory permissions were the actual bug, not any single command.

**Remediation:** never stage secrets through shared temp paths, even briefly; cron job working directories should not be writable by lower-privileged users; predictable filenames for anything containing a secret should be avoided entirely.

---

## 2. Restricted shell escapes (bandit25, 32)

**Objective:** get a normal, unfiltered shell where the login environment tries to prevent one.

**Recon:** inspected what ran on login — `/usr/bin/showtext` for bandit26 (`cat /etc/passwd` showed the custom shell entry), and for bandit32 simply tried typing normal commands and noticed everything came back uppercased.

**Vulnerability / weak point:** bandit26's "shell" was a script that piped a text file into `more` and exited — never a real login shell. bandit32's shell uppercased every command before executing it, which breaks most commands but doesn't block shell substitution.

**Exploitation:**

For bandit26, shrank the terminal window before connecting so `more` would
pause instead of exiting, giving access to `more`'s command mode, then
escalated further from there:
```
# small terminal window, then:
ssh bandit26@bandit.labs.overthewire.org -p 2220
v                          # opens $PAGER (vim) from within more
:e /etc/bandit_pass/bandit26
:set shell=/bin/bash
:shell                     # drops into a real shell
```

For bandit32, `$0` re-invokes the current shell and isn't itself transformed
by the uppercase filter:
```
$0
cd /etc/bandit_pass
cat bandit33
```

**Root cause:** both "restrictions" filtered or wrapped the shell at the input/output layer instead of actually removing shell capability — any path that still reaches an interpreter (a pager's command mode, shell self-invocation) bypasses a cosmetic restriction.

**Remediation:** don't rely on wrapping or filtering a real shell to restrict it — use a genuinely restricted shell (e.g. `rbash` with a locked-down `PATH` and no shell escapes in any allowed program) or, better, avoid giving shell access at all for the restricted use case.

---

## 3. Setuid helper binaries (bandit19, 20, 26)

**Objective:** run a command as a higher-privileged target user via a purpose-built binary instead of `sudo`.

**Recon:** looked for setuid binaries left in the target user's home directory (`ls -la`) and checked their behavior (`file`, running them with no args).

**Vulnerability / weak point:** setuid helper binaries (`bandit20-do`, `suconnect`, `bandit27-do`) ran arbitrary or semi-arbitrary commands as the next user, effectively acting as a scoped `sudo` without `sudo`'s auditing/logging.

**Exploitation:**

Direct command execution as the target user via the helper binary:
```
./bandit20-do cat /etc/bandit_pass/bandit20
```

`suconnect` required proving knowledge of the current password over a raw
socket before handing back the next one, so a listener had to be stood up
first:
```
echo "<current_password>" | nc -l -p 9999 &
./suconnect 9999
```

Same pattern again one level later with a differently-named helper:
```
./bandit27-do cat /etc/bandit_pass/bandit27
```

**Root cause:** privilege was bridged through custom setuid binaries with narrow, undocumented trust assumptions (a password over a socket, a hardcoded command) instead of a standard, auditable privilege-escalation mechanism.

**Remediation:** avoid custom setuid binaries for privilege bridging; use `sudo` with an explicit, logged command allowlist instead — it gives the same "run this one thing as another user" capability with an audit trail and no bespoke trust logic to get wrong.

---

## 4. Git internals (bandit27–31)

**Objective:** recover a secret that isn't present in the current working tree.

**Recon:** cloned each level's repo over SSH into a local scratch dir, then looked beyond the working tree — `git log`, `git branch -a`, `git tag`.
```
git clone ssh://banditNN-git@bandit.labs.overthewire.org:2220/home/banditNN-git/repo
```

**Vulnerability / weak point:** the secret had been removed from the current tree but still lived in git's history — an old commit, a non-default branch, or a tag — none of which are visible from a plain `ls`/`cat` of the checked-out files.

**Exploitation:**

Old commit before the password was overwritten with `x`s:
```
git log
git show <commit_hash>
```

Password only present on a non-default branch:
```
git branch -a
git switch dev
cat README.md
```

Password only reachable via a tag:
```
git tag
git show secret
```

Final level required proving write access by force-adding a normally
gitignored file and pushing it:
```
touch key.txt
echo <content> > key.txt
git add -f key.txt
git commit -m "add key"
git push origin master
```

**Root cause:** git never truly deletes anything by default — "removing" a secret from the working tree or `.gitignore`-ing it after the fact leaves it fully recoverable from history, branches, or tags.

**Remediation:** a leaked secret in git history must be treated as permanently exposed and rotated immediately; `.gitignore` only prevents *future* commits, and rewriting history (`filter-repo`/BFG) is required — and still assumes no one already cloned the repo — to actually remove it.

---

## 5. Remote/network protocol basics (bandit13–16, 20)

**Objective:** authenticate to the next level over various non-SSH (or SSH-key-based) channels.

**Recon:** for bandit16, didn't know which port in a range ran what, so scanned it first.
```
nmap -sV localhost -p 31000-32000
```

**Vulnerability / weak point:** several levels exposed plaintext or TLS-wrapped services on nonstandard ports expecting exact protocol handshakes, plus an SSH private key retrieved over `scp` that the client refused to use until its permissions were tightened.

**Exploitation:**

SSH key retrieved via `scp`, then had to fix permissions before it would be accepted:
```
scp -P 2220 bandit13@bandit.labs.overthewire.org:sshkey.private .
chmod 700 sshkey.private
ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```

Plain TCP service on localhost, reached with `telnet`:
```
telnet localhost 30000
```

TLS-wrapped service, needed `openssl s_client` rather than a raw connection:
```
openssl s_client -connect localhost:30001
```

Port found via nmap turned out to also be TLS, and required piping the
current password into the handshake to get a key back:
```
echo "<current_password>" | openssl s_client -connect localhost:31790
```

**Root cause:** each level used a different protocol convention (raw TCP vs TLS vs key auth) with no visible labeling — the only way to know which was to either scan (`nmap -sV`) or just try the standard tool and read the failure.

**Remediation:** not really an application security lesson at this level — more a personal-process one: always confirm the protocol a service is speaking before assuming raw TCP will work; a failed raw connection to a TLS port looks like nothing happened, which wastes time if not recognized quickly.

---

## 6. Encoding & compression identification (bandit10–12)

**Objective:** recover a password hidden behind one or more layers of encoding/compression.

**Recon:** ran `file` on the payload where possible; when the file had no useful extension or `file` was ambiguous, inspected the raw bytes directly.
```
xxd data.txt | head
```

**Vulnerability / weak point:** none, really — this group is about recognizing standard encodings by signature rather than exploiting a flaw.

**Exploitation:**

Base64:
```
base64 -d data.txt
```

ROT13 (via `tr`, both the naive and the compact form):
```
tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt
```

Multiple layers of compression with no extensions — identified each layer
by its hex file signature (`1f8b` = gzip, `425a` = bzip2, `7461` in header =
tar) before running the matching tool, renaming to add the required
extension each time:
```
xxd data.bin | head -1
mv data.bin data.gz && gzip -d data.gz
# repeat: xxd -> identify -> rename with correct extension -> decompress
```

**Root cause:** N/A (identification exercise, not a vulnerability).

**Remediation:** N/A — the transferable lesson is knowing common file signatures well enough to identify a file type when the extension is missing or wrong, which comes up in real forensics/malware-analysis contexts.

---

## 7. Linux fundamentals (bandit0–9)

**Objective:** locate and read a password hidden behind unusual filenames, file attributes, or noisy data.

**Recon:** `ls -la` to catch hidden/dotfiles and filenames with leading dashes or spaces; `find` with attribute filters when a plain listing wasn't enough.

**Vulnerability / weak point:** N/A — these are CLI fluency exercises (special filenames, `find` predicates, filtering noisy output), not vulnerabilities.

**Exploitation:**

Filename that `cat` interprets as a flag (leading dash) or that contains a space:
```
cat ./-filename
cat "file name with spaces"
```

Finding a specific file by size/owner/group across the filesystem rather than by name:
```
find / -size 33c -user bandit7 -group bandit6 2>/dev/null
```

Extracting a needle from noisy data:
```
grep "millionth" data.txt
sort data.txt | uniq -u
strings data.txt | grep "==" | sort -n
```

**Root cause:** N/A.

**Remediation:** N/A — foundational tooling fluency (grep/sort/uniq/strings/find) that everything later in the game and in real recon work assumes you already have.

---

## 3. Setuid helper binaries (bandit19, 20, 26)

**Objective:**

**Recon:**

**Vulnerability / weak point:**

**Exploitation:**

**Root cause:**

**Remediation:**

---

## 4. Git internals (bandit27–31)

**Objective:**

**Recon:**

**Vulnerability / weak point:**

**Exploitation:**

**Root cause:**

**Remediation:**

---

## 5. Remote/network protocol basics (bandit13–16, 20)

**Objective:**

**Recon:**

**Vulnerability / weak point:**

**Exploitation:**

**Root cause:**

**Remediation:**

---

## 6. Encoding & compression identification (bandit10–12)

**Objective:**

**Recon:**

**Vulnerability / weak point:**

**Exploitation:**

**Root cause:**

**Remediation:**

---

## 7. Linux fundamentals (bandit0–9)

**Objective:**

**Recon:**

**Vulnerability / weak point:**

**Exploitation:**

**Root cause:**

**Remediation:**
