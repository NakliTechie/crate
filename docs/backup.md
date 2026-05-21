# Backup + disaster recovery

Crate's privacy guarantee — *we can't read your files, even if we wanted to* — cuts both ways. If you lose your passphrase, we can't help. If you lose your bucket, we can't restore. **Your bucket is your only copy unless you make another.**

This page covers four ways to add redundancy and three disaster scenarios.

## Four ways to keep a redundant copy

### 1. Run `crate-agent`, back up the local folder (recommended)

[`crate-agent`](https://github.com/NakliTechie/crate-agent) is a small Go daemon that mirrors your bucket to `~/crate/` on macOS or Linux. The folder there is plaintext — regular files. Point your existing backup tool at it:

- **Time Machine** (macOS): include `~/crate/` in the backup set. Done.
- **restic** / **borg**: `restic backup ~/crate/` to a destination of your choosing.
- **rsync to a NAS**: `rsync -aHX ~/crate/ /Volumes/NAS/crate-backup/`.
- **External HDD**: drag-drop `~/crate/` periodically.

Restore: drop the files back into `~/crate/`, daemon re-encrypts + re-uploads on next sync tick.

This is the cleanest option because you're using audited backup tools you already trust. The plaintext lives on hardware you control. Crate stays out of the loop.

### 2. Mirror the bucket (ciphertext-preserving)

`rclone sync` or Cloudflare's native R2 → R2 replication copies the bucket bytes verbatim. The mirror is still ciphertext; restoring is just pointing the wizard at the mirror bucket with the same passphrase.

```sh
# One-off mirror, ciphertext-preserving
rclone sync r2:my-crate-primary r2:my-crate-backup
```

Good for: an offsite copy where you don't trust any other machine to ever hold the plaintext. The mirror bucket's owner (Cloudflare, in the R2→R2 case) sees the same ciphertext + access patterns as the primary.

### 3. Turn on R2 object versioning

In the Cloudflare R2 dashboard → your bucket → Settings → Object Versioning → Enable. Every overwrite + delete now keeps the prior version. You can roll back individual objects through the dashboard or `rclone`.

Useful for: point-in-time recovery from accidental deletes or ransomware that re-encrypted your bucket. Doesn't protect against losing the bucket itself or losing the passphrase.

### 4. Export the folder from the browser

The folder UI has an "Export folder" button. For folders ≤500 MB it generates a zip in memory; for larger folders (on Chrome / Edge / Brave) it streams files directly to a folder you pick on disk. The exported plaintext is yours to back up however you like.

Useful for: a one-shot "I want to know I can get my data out of here." Less useful for regular backup — use option 1 for that.

## Three disaster scenarios

### "I lost my passphrase"

Your files are gone. There is no reset, no support email, no recovery flow — v1 has only one credential (the passphrase). The same property that keeps Cloudflare from reading your files keeps anyone — including us — from helping you recover them.

This is why redundancy matters: pick at least one of the four options above before you have data you can't afford to lose.

### "I lost my bucket / my Cloudflare account"

Restore from the most recent of your redundant copies (above). Concretely:

- **From `crate-agent`'s local folder**: create a new bucket, run the wizard with the same passphrase + the new bucket creds, drop the local files back in. They'll re-encrypt + re-upload.
- **From an rclone mirror**: just point the wizard at the mirror bucket. Same passphrase, you're back.
- **From an exported zip**: create a new bucket, run the wizard, unzip the export into the daemon's local folder OR upload individually via the browser folder UI.

### "I want to migrate from R2 to Hetzner / Backblaze / AWS"

Pick whichever's faster:

- **`rclone sync` between buckets** — ciphertext-preserving. After sync completes, run the wizard against the new bucket with the same passphrase + the new creds. Same files, new home, zero plaintext exposure.
- **Plaintext re-upload via the daemon** — if you'd rather start fresh on the new provider (e.g., different folder layout): run the daemon against the old bucket, copy `~/crate/` to a local archive, set up a new Crate against the new bucket, drop the archive in.

### "I want to rotate my bucket credentials"

You rotated your R2 token in the Cloudflare dashboard (or revoked the old one). To pick up the new credentials in Crate:

1. Refresh the browser tab (or open a new one).
2. Choose **Unlock an existing folder** on Welcome.
3. Enter the same bucket name + Account ID + passphrase, with the **new** Access Key + Secret.
4. The folder unlocks against the new credentials.

You don't need to migrate any data. The bucket creds aren't stored anywhere — they live in browser memory for the active session only. Crate validates them against R2 on each operation; the new ones take over the moment you re-unlock.

If you're running `crate-agent` too: re-pair the daemon with the new transport credentials, or restart it pointing at the new R2 token directly (see `crate-agent --help`).

## Threat model reminder

Backups inherit Crate's threat model. The daemon's local folder is plaintext — anyone with read access to your home directory can read your Crate files there. The bucket-to-bucket mirror is ciphertext, but the mirror's owner sees access patterns. The exported zip is plaintext — handle it like any other sensitive file.

Pick the option that matches what you're actually defending against.
