# OverTheWire: Bandit

**Status:** Complete (bandit0 → bandit33)
**What it is:** A wargame of 34 sequential Linux levels. Each level is an SSH login; solving it reveals the password for the next level. Focus is Linux fundamentals — shell, permissions, basic crypto/encoding, git internals, cron, and simple network protocols — rather than exploitation per se.

Connect: `ssh banditN@bandit.labs.overthewire.org -p 2220`

Passwords are per-player and regenerate per session, so they're omitted below — this is a methodology log, not a solution key.

## Skills demonstrated

- Core CLI: `ls`, `cd`, `cat`, `file`, `grep`, `sort`, `uniq`
- Encoding/compression: `base64`, `tr`, `xxd`, `tar`, `gzip`, `bzip2`, file-signature identification
- Remote access basics: `ssh`, `scp`, `telnet`, `openssl s_client`, `nc`
- Permissions: `chmod`, SSH key permission requirements
- Recon: `nmap` port/service scanning
- Automation surfaces: cron jobs, setuid helper binaries
- Git internals: `log`, `show`, `branch`, `tag`, force-adding ignored files

## Notable levels

**bandit12 — nested compression identification.** A file was compressed multiple times with mixed formats (gzip/bzip2/tar) with no extension hints. Used `xxd` to read the file signature at each stage (`1f8b` = gzip, `425a` = bzip2, `7461` in the header = tar) rather than guessing — each tool needs a matching extension to work, so files had to be renamed at each step before the next decompression.

**bandit13 — SSH key permission enforcement.** Retrieved a private key via `scp`, but SSH refused to use it ("permissions are too open"). Fixed with `chmod 700` before connecting — a reminder that SSH enforces key file permissions client-side regardless of the key's actual sensitivity.

**bandit16 — service fingerprinting on an unknown port range.** Given a port range (31000–32000) with no other info, used `nmap -sV` to identify which port ran what. One port answered but needed an SSL handshake first — connecting directly with `nc` didn't work, but `openssl s_client -connect` did, and piping the current password into that connection was what actually retrieved a private key in return.

**bandit21 — reading a live cron job for credential leakage.** Found a script in `/etc/cron.d/` that copied the next password into a `chmod 644` file under `/tmp/` with a random name — findable in the time window after the cron fired. Root cause pattern worth remembering: cron jobs that stage secrets to shared temp locations, even briefly and randomly named, are a real leakage vector.

**bandit26 — abusing a restricted default shell.** The next user's shell was set to a custom binary that ran `more` on a text file and then exited (`showtext`), never dropping to a real shell. Bypassed it by shrinking the terminal window before connecting, so `more` would pause and offer its command mode (`v` to open `$PAGER`/vim), then used `:set shell=/bin/bash` + `:shell` inside vim to escape into a real shell.

**bandit29–31 — git history and branch/tag inspection.** Several levels hid the password in git history rather than the working tree: an old commit that had since overwritten the value with `x`s (`git show <commit>`), a password only present on a non-default branch (`git branch -a` / `git switch`), and one only reachable via a tag (`git tag` / `git show <tag>`). Consistent lesson: a clean working tree tells you nothing about what a repo's history exposes.

**bandit32 — shell escape via a "shell within a shell" gimmick.** The level intentionally uppercased any command typed, so normal commands failed. `$0` (re-invoking the current shell) bypassed the uppercase filter and dropped into a normal, unfiltered shell.

## Takeaway

Bandit's value isn't any single hard technique — it's forcing fast, low-friction fluency across the tools you use constantly in real recon and post-exploitation work (SSH tooling, permissions, cron, git, basic protocol interaction), so none of it costs thinking time later.
