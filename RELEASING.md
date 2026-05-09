# Releasing MarlinSpike

Every release of MarlinSpike is **signed**, **hashed**, **OpenTimestamped**,
and **archived externally**. This document is the operator runbook for
cutting a new release.

## What "released" means here

A release is the union of:

1. A **signed git commit** on `main` carrying the version bump
2. A **signed git tag** (`vX.Y.Z`) on that commit
3. A **GitHub Release** object with:
   - The tag
   - Human-readable release notes
   - A source `.tar.gz` archive (deterministic, from `git archive`)
   - A `SHA256SUMS` file with the archive's hash
   - A `SHA256SUMS.asc` GPG-detached signature of the hash file
   - A `SHA256SUMS.ots` OpenTimestamps proof anchored to the Bitcoin blockchain
4. An **OpenTimestamps proof** for `SHA256SUMS` (anchored across 4 calendar servers)
5. A **Software Heritage Project** archival submission
6. A **Internet Archive Wayback Machine** snapshot of the GitHub release page

This stack means anyone can verify *who released what, when*, without
trusting any single party (including the GitHub release infrastructure).

## Signing identity

All releases are signed by the **ERISFORGE Ltd.** GPG key:

```
8C4879D492DE808D52D2C3F02CBC9B8E1FBAF06C
ERISFORGE Ltd. (a Rwanda Corp) <erisforge@erisforge.com>
```

The public key is published on the GPG keyserver pool. Anyone verifying
a release should `gpg --recv-keys 2CBC9B8E1FBAF06C` first.

If the signing key ever changes, the new key must be:
- Cross-signed by the old key during a transition window
- Announced in `releases.md`
- Updated in this document and in every signed-release verification flow

## Cutting a release — step by step

Replace `vX.Y.Z` with the actual version throughout.

### 1. Bump version + finalize release notes

```sh
# Bump the version string
$EDITOR marlinspike/__init__.py   # __version__ = "X.Y.Z"

# Add the release entry to releases.md (top of the Web UI Releases table)
$EDITOR releases.md

# Add the upgrade section if there are migration notes
$EDITOR UPGRADING.md

# Run the full test suite — it must pass
python3 -m pytest tests/ -q
```

### 2. Commit + tag (signed)

```sh
# Confirm git signing config is set
git config --get user.signingkey   # should output: 2CBC9B8E1FBAF06C
git config --get commit.gpgsign    # should output: true
git config --get tag.gpgsign       # should output: true

# Stage everything
git add -A

# Commit (signed automatically because commit.gpgsign=true)
git commit -m "vX.Y.Z — <one-line summary>

<body>"

# Tag (signed automatically because tag.gpgsign=true)
git tag -s vX.Y.Z -m "vX.Y.Z — <one-line summary>

<body>"

# Verify both signatures locally before pushing
git log -1 --show-signature
git tag -v vX.Y.Z
```

Both should show `Good signature from "ERISFORGE Ltd. ..." [ultimate]`.

### 3. Push to origin

```sh
git push origin main
git push origin vX.Y.Z
```

### 4. Build deterministic source archive + hash file

```sh
mkdir -p release-artifacts
git archive --format=tar.gz --prefix=marlinspike-vX.Y.Z/ vX.Y.Z \
  -o release-artifacts/marlinspike-vX.Y.Z.tar.gz

cd release-artifacts
sha256sum marlinspike-vX.Y.Z.tar.gz > SHA256SUMS

# GPG-sign the SHA256SUMS file (detached, ASCII-armored)
gpg --local-user 2CBC9B8E1FBAF06C --armor --detach-sign SHA256SUMS
# produces SHA256SUMS.asc
```

`git archive` is deterministic for a given tag — anyone can reproduce
the same `.tar.gz` (and therefore the same hash) by checking out the
tag and running the same command.

### 5. OpenTimestamp the hash file

```sh
ots stamp SHA256SUMS
# produces SHA256SUMS.ots — submitted to 4 calendar servers
# (a.pool.opentimestamps.org, b.pool.opentimestamps.org,
#  a.pool.eternitywall.com, ots.btc.catallaxy.com)

# The proof is initially "pending" — calendars confirm within ~1-6h
# when the next Bitcoin block they aggregate into is mined. Verify later:
ots upgrade SHA256SUMS.ots   # rerun until "Bitcoin block N attests" appears
ots verify SHA256SUMS.ots    # confirms the timestamp against the blockchain
```

We stamp the `SHA256SUMS` file (not the archives directly) because
hashing the archive once and stamping that hash is functionally
equivalent and produces a much smaller proof file.

### 6. Create GitHub Release with attached artifacts

```sh
gh release create vX.Y.Z \
  --title "vX.Y.Z — <one-line summary>" \
  --notes-file release-notes-vX.Y.Z.md \
  marlinspike-vX.Y.Z.tar.gz \
  SHA256SUMS \
  SHA256SUMS.asc \
  SHA256SUMS.ots
```

The release notes should include a "Verifying this release" section
with the standard verify commands (see existing release pages for the
template).

### 7. Submit to external archives

```sh
# Software Heritage — re-ingests the public Git origin
curl -X POST \
  "https://archive.softwareheritage.org/api/1/origin/save/git/url/https://github.com/eris-ot/marlinspike/"
# Returns a task ID; check completion at:
# https://archive.softwareheritage.org/api/1/origin/save/<task_id>/

# Wayback Machine — snapshots the release page
curl -I "https://web.archive.org/save/https://github.com/eris-ot/marlinspike/releases/tag/vX.Y.Z"
curl -I "https://web.archive.org/save/https://github.com/eris-ot/marlinspike"

# (Optional) snapshot the README and docs index too
curl -I "https://web.archive.org/save/https://github.com/eris-ot/marlinspike/blob/vX.Y.Z/README.md"
```

### 8. Post-release verification

After ~1-6 hours, verify the OTS proof has been attested:

```sh
cd release-artifacts
ots upgrade SHA256SUMS.ots
ots verify SHA256SUMS.ots
# expect: "Success! Bitcoin block <NNNN> attests existence as of <date>"
```

Re-upload the upgraded `SHA256SUMS.ots` to the GitHub Release (replacing
the pending one):

```sh
gh release upload vX.Y.Z SHA256SUMS.ots --clobber
```

## Verifying a downloaded release

Any consumer of a release should run:

```sh
# Get the signing key
gpg --recv-keys 2CBC9B8E1FBAF06C

# Verify tag signature
git clone https://github.com/eris-ot/marlinspike
cd marlinspike
git tag -v vX.Y.Z

# Or download artifacts and verify locally
gh release download vX.Y.Z

# Verify hashes
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS

# Verify blockchain timestamp
ots verify SHA256SUMS.ots
```

All four checks should pass. If any fail, **do not trust the release**
— report it to `erisforge@erisforge.com`.

## What's archived where

| Artifact | Location | Verifiable by |
|---|---|---|
| Signed commit | `main` branch on GitHub | `git log --show-signature` |
| Signed tag | `vX.Y.Z` on GitHub | `git tag -v vX.Y.Z` |
| Source tarball + hash file + sig + ots | GitHub Release page | `gh release download vX.Y.Z` |
| Source tree mirror | [Software Heritage](https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/eris-ot/marlinspike/) | SWH's own auth |
| Release page snapshot | [Wayback Machine](https://web.archive.org/web/*/https://github.com/eris-ot/marlinspike/) | Internet Archive's own auth |
| Blockchain timestamp | Bitcoin blockchain (via OpenTimestamps) | `ots verify` against any Bitcoin node |

## Rationale

Why all this infrastructure for a defender-grade open-source tool?

- **Sign**: anyone can verify *who* released the code.
- **Hash**: anyone can verify the bits they got match what was released.
- **OpenTimestamp**: anyone can verify the release existed *no later than*
  a specific Bitcoin block, without trusting GitHub's timeline.
- **Software Heritage**: the source is preserved even if GitHub disappears
  (or removes the repo).
- **Wayback Machine**: the release notes / web context is preserved
  similarly.

For a tool that defenders deploy on engagement networks to triage OT
captures, supply-chain trust isn't optional. This stack is the minimum
viable supply-chain assurance for a security tool.

## See also

- [GPG signing setup for git](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
- [OpenTimestamps documentation](https://opentimestamps.org/)
- [Software Heritage save-code-now API](https://archive.softwareheritage.org/api/1/origin/save/)
- [Wayback Machine save API](https://archive.org/help/wayback_api.php)
