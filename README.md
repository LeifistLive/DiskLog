# Unraid Disk Access Monitor

This local Docker image detects Unraid `diskN` spin-ups and correlates them
with fanotify events from `/mnt/user` and `/mnt/diskN`.

## Important security note

The container uses the host PID namespace and `CAP_SYS_ADMIN`/`SYS_PTRACE` so
it can enter the Unraid host's mount namespace and create mount-wide fanotify
marks. Concretely, `monitor.py` does `setns()` into `/proc/1/ns/mnt` and then
`chroot()`s into `/proc/1/root` — after that, the process is running with the
same filesystem access any root process on the Unraid host would have. The
container's read-only rootfs and reduced capability set only constrain it
*before* that chroot happens, not after — so despite running "in a
container", this is functionally equivalent to giving something a root shell
on the host. Don't run untrusted code here, and review changes to
`monitor.py` before deploying them.

Within that trust boundary, the code itself is deliberately narrow: no
Docker socket (it can't control other containers), and it only ever *writes*
to the data directory (`events.jsonl`, `status.json`) — everything else
(`disks.ini`, `/mnt/user`, `/mnt/diskN`, `/var/lib/docker/containers`) is
opened read-only. The image is also built locally from the `Dockerfile` in
this repo, not pulled from a registry.

## CI

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs on every push and
pull request:

- `test` — runs the unit tests in `tests/` (pure logic only: env parsing,
  path/cgroup/ini parsing — nothing that needs root or an Unraid host).
- `docker-build` — builds the image from the `Dockerfile` to catch build
  breakage early (no push to a registry).

Run the tests locally:
```bash
pip install -r requirements-dev.txt
pytest -v
```

## Install

### Option A: Portainer, pulled from GitHub

1. Push this repository to GitHub (this repo has no remote configured —
   create an empty GitHub repo and push these files to it yourself).
2. On the Unraid host, create the data directory once:
   ```bash
   mkdir -p /mnt/user/appdata/disk-access-monitor/data
   ```
3. In Portainer: **Stacks → Add stack → Repository**.
   - Repository URL: `https://github.com/<you>/<repo>.git`
   - Reference: `refs/heads/main` (or whichever branch)
   - Compose path: `compose.yaml`
4. Deploy the stack. Portainer clones the repo and runs
   `docker compose up -d --build`, so the image is built locally from the
   `Dockerfile` in this repo — nothing needs to be pushed to a registry.
5. To update: push new commits to GitHub, then use **Pull and redeploy** in
   the stack view (or enable the GitOps webhook/polling option in the
   stack's settings for automatic redeploys on push).

### Option B: Manual, local files

```bash
mkdir -p /mnt/user/appdata/disk-access-monitor/data
cd /mnt/user/appdata/disk-access-monitor
# Put compose.yaml, Dockerfile and monitor.py in this directory.
docker compose up -d --build
```

## Check

```bash
docker compose ps
docker logs -f disk-access-monitor
cat /mnt/user/appdata/disk-access-monitor/data/status.json
tail -f /mnt/user/appdata/disk-access-monitor/data/events.jsonl
```

## Stop old Bash logger first

```bash
pkill -TERM -f '/tmp/user.scripts/tmpScripts/Log/script'
pkill -TERM fatrace
```

Disable its User Scripts schedule so it does not start again.

## Rebuild after editing

Portainer stack: push the change to GitHub, then **Pull and redeploy**.

Manual (Option B):
```bash
cd /mnt/user/appdata/disk-access-monitor
docker compose up -d --build --force-recreate
```

## Remove

Portainer stack: **Stacks → disk-access-monitor → Remove**.

Manual (Option B):
```bash
cd /mnt/user/appdata/disk-access-monitor
docker compose down
```
