#!/usr/bin/env python3
"""
Unraid Disk Access Monitor

Purpose:
- Detect transitions from spundown=1 to spundown=0 in Unraid disks.ini.
- Record fanotify events on /mnt/user and /mnt/diskN before and after spin-up.
- Correlate host PID, command and Docker container without mounting docker.sock.
- Write JSONL reports to /data/events.jsonl and a status file to /data/status.json.
- Optionally mirror concise messages into the Unraid syslog.

Security characteristics:
- No Docker socket - cannot control other containers.
- The code itself only ever writes to DATA_DIR (events.jsonl, status.json);
  everything else it touches (disks.ini, /mnt/user, /mnt/diskN,
  /var/lib/docker/containers) is opened read-only.
- That said: this process runs as root and deliberately enters the host's
  mount + PID namespace (setns + chroot into /proc/1/root) so it can see
  host-level fanotify events at all. Once that happens it has the same
  filesystem access any root process on the host would - the container's
  own read-only rootfs and reduced capability set only constrain it *before*
  that point, not after. Treat this image like a trusted root process on the
  host, not like a sandboxed container.
"""

from __future__ import annotations

import ctypes
import errno
import heapq  # noqa: F401 - see note below, do not remove
import json
import os
import re
import select
import signal
import struct
import sys
import syslog
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# heapq is never called directly in this file, but Counter.most_common(n)
# (used in summarize_events()) imports it lazily on first use. By the time
# that first happens (the first completed spin-up report), this process has
# already setns()+chroot()'d into the host root (see
# enter_host_mount_namespace()), so Python's import machinery would search
# the *host's* filesystem for heapq.py and fail with ModuleNotFoundError -
# confirmed in production. Importing it here, before the chroot, caches it
# in sys.modules so the later lazy import inside collections is a no-op.
# The same risk applies to any other stdlib module imported for the first
# time after the chroot; see main()'s exception handler.


# Linux namespace / fanotify constants.
CLONE_NEWNS = 0x00020000

FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_NOTIF = 0x00000000

FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_OPEN = 0x00000020
FAN_EVENT_ON_CHILD = 0x08000000
FAN_Q_OVERFLOW = 0x00004000

FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010

AT_FDCWD = -100

EVENT_MASK = (
    FAN_ACCESS
    | FAN_MODIFY
    | FAN_CLOSE_WRITE
    | FAN_OPEN
    | FAN_EVENT_ON_CHILD
)

METADATA = struct.Struct("=IBBHQii")
FANOTIFY_METADATA_VERSION = 3

DISKS_INI = Path("/var/local/emhttp/disks.ini")
VAR_INI = Path("/var/local/emhttp/var.ini")
CONTAINERS_ROOT = Path("/var/lib/docker/containers")
DATA_DIR = Path("/data")
EVENTS_FILE = DATA_DIR / "events.jsonl"
STATUS_FILE = DATA_DIR / "status.json"

DISK_RE = re.compile(r"^disk\d+$")
CONTAINER_ID_PATTERNS = (
    re.compile(r"(?:^|/)docker[-/](?P<id>[0-9a-f]{12,64})(?:\.scope)?(?:$|/)"),
    re.compile(r"(?:^|/)docker-(?P<id>[0-9a-f]{12,64})\.scope(?:$|/)"),
    re.compile(r"(?:^|/)(?P<id>[0-9a-f]{64})(?:$|/)"),
)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def env_float(name: str, default: float, minimum: float = 0.1) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        return default


WATCH_DISKS_RAW = os.getenv("WATCH_DISKS", "").strip()
WATCH_DISKS = {
    item.strip()
    for item in WATCH_DISKS_RAW.split(",")
    if item.strip() and DISK_RE.fullmatch(item.strip())
}

POLL_INTERVAL = env_float("POLL_INTERVAL", 0.5)
SECONDS_BEFORE = env_int("SECONDS_BEFORE", 12)
SECONDS_AFTER = env_int("SECONDS_AFTER", 3)
COOLDOWN_SECONDS = env_int("COOLDOWN_SECONDS", 120)
MAX_EVENTS = env_int("MAX_EVENTS", 10000, 1000)
MAX_PROCESSES = env_int("MAX_PROCESSES", 8, 1)
MAX_PATHS = env_int("MAX_PATHS", 8, 1)
LOG_FULL_PATHS = env_bool("LOG_FULL_PATHS", False)
WRITE_SYSLOG = env_bool("WRITE_SYSLOG", True)
EVENTS_MAX_BYTES = env_int("EVENTS_MAX_BYTES", 25 * 1024 * 1024, 1024 * 1024)
EVENTS_BACKUP_COUNT = env_int("EVENTS_BACKUP_COUNT", 3, 0)


@dataclass(slots=True)
class FsEvent:
    epoch: float
    monotonic: float
    pid: int
    process: str
    command: str
    container_id: str | None
    container_name: str | None
    path: str
    operation: str
    source: str


class MonitorError(RuntimeError):
    pass


class HostFanotifyMonitor:
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = -1
        self.data_dir_fd = -1
        self.events: deque[FsEvent] = deque(maxlen=MAX_EVENTS)
        self.stop_requested = False
        self.last_states: dict[str, str] = {}
        self.last_alert: dict[str, float] = {}
        self.pending: list[dict[str, Any]] = []
        self.container_name_cache: dict[str, tuple[float, str | None]] = {}
        self.marked_paths: set[str] = set()
        self.overflow_count = 0
        self.event_read_errors = 0
        self.last_event_read_error: str | None = None
        self.last_event_read_error_epoch: float | None = None
        self.started_epoch = time.time()
        self.last_status_write = 0.0
        self.last_state_poll = 0.0

    def log(self, message: str, priority: int = syslog.LOG_NOTICE) -> None:
        print(message, flush=True)
        if WRITE_SYSLOG:
            try:
                syslog.syslog(priority, message)
            except Exception:
                pass

    def open_data_dir(self) -> None:
        # Must run before enter_host_mount_namespace(): once this process
        # has chrooted into the host root, plain path strings like "/data"
        # no longer resolve to the docker-managed bind mount, they resolve
        # against the host's own root. A directory file descriptor opened
        # now stays valid (and still points at the bind-mounted volume) no
        # matter what the process's root/mount namespace does afterwards,
        # so all later data writes go through this fd instead of by path.
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.data_dir_fd = os.open(DATA_DIR, os.O_RDONLY | os.O_DIRECTORY)

    def enter_host_mount_namespace(self) -> None:
        namespace_fd = os.open("/proc/1/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        try:
            result = self.libc.setns(namespace_fd, CLONE_NEWNS)
            if result != 0:
                error = ctypes.get_errno()
                raise MonitorError(
                    f"setns(/proc/1/ns/mnt) failed: {os.strerror(error)}"
                )
        finally:
            os.close(namespace_fd)

        # setns(CLONE_NEWNS) alone does not repoint this process's root/cwd
        # at the target namespace's filesystem tree (see setns(2), NOTES).
        # Without this chroot, absolute paths such as /mnt/user or
        # /var/local/emhttp/disks.ini would keep resolving inside the
        # container's own rootfs instead of the host's.
        try:
            os.chdir("/proc/1/root")
            os.chroot(".")
            os.chdir("/")
        except OSError as exc:
            raise MonitorError(
                f"failed to chroot into host root via /proc/1/root: {exc}"
            )

    def init_fanotify(self) -> None:
        flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        event_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_LARGEFILE"):
            event_flags |= os.O_LARGEFILE

        fd = self.libc.fanotify_init(flags, event_flags)
        if fd < 0:
            error = ctypes.get_errno()
            raise MonitorError(f"fanotify_init failed: {os.strerror(error)}")
        self.fd = fd

    def mark_mount(self, path: str) -> bool:
        if path in self.marked_paths:
            return True
        if not os.path.exists(path):
            return False

        encoded = os.fsencode(path)
        result = self.libc.fanotify_mark(
            self.fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            ctypes.c_uint64(EVENT_MASK),
            AT_FDCWD,
            ctypes.c_char_p(encoded),
        )
        if result != 0:
            error = ctypes.get_errno()
            self.log(
                f"WARN: fanotify mark failed for {path}: {os.strerror(error)}",
                syslog.LOG_WARNING,
            )
            return False

        self.marked_paths.add(path)
        self.log(f"Monitoring filesystem mount: {path}")
        return True

    @staticmethod
    def parse_ini_sections(path: Path) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        current: str | None = None
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        current = line[1:-1].strip('"')
                        result.setdefault(current, {})
                        continue
                    if current and "=" in line:
                        key, value = line.split("=", 1)
                        result[current][key] = value.strip().strip('"')
        except FileNotFoundError:
            return {}
        return result

    def read_disk_states(self) -> dict[str, str]:
        sections = self.parse_ini_sections(DISKS_INI)
        states: dict[str, str] = {}
        for disk, values in sections.items():
            if not DISK_RE.fullmatch(disk):
                continue
            if WATCH_DISKS and disk not in WATCH_DISKS:
                continue
            state = values.get("spundown")
            if state in {"0", "1"}:
                states[disk] = state
        return states

    @staticmethod
    def array_started() -> bool:
        try:
            content = VAR_INI.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return 'mdState="STARTED"' in content

    def refresh_marks(self, states: dict[str, str]) -> None:
        # /mnt/user captures the original application hitting a User Share.
        self.mark_mount("/mnt/user")
        # /mnt/diskN captures the actual backing-disk activity.
        for disk in states:
            self.mark_mount(f"/mnt/{disk}")

    @staticmethod
    def operation_from_mask(mask: int) -> str:
        operations: list[str] = []
        if mask & FAN_OPEN:
            operations.append("open")
        if mask & FAN_ACCESS:
            operations.append("access")
        if mask & FAN_MODIFY:
            operations.append("modify")
        if mask & FAN_CLOSE_WRITE:
            operations.append("close_write")
        return "+".join(operations) or f"mask:0x{mask:x}"

    @staticmethod
    def write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]

    @staticmethod
    def read_text(path: str, limit: int = 4096) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read(limit).strip()
        except OSError:
            return ""

    def process_details(self, pid: int) -> tuple[str, str, str | None, str | None]:
        if pid <= 0:
            return "kernel/unknown", "", None, None

        process = self.read_text(f"/proc/{pid}/comm", 256) or f"pid-{pid}"
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()[:8192]
            command = raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            command = ""

        cgroup = self.read_text(f"/proc/{pid}/cgroup", 16384)
        container_id = self.extract_container_id(cgroup)
        container_name = self.container_name(container_id) if container_id else None
        return process, command, container_id, container_name

    @staticmethod
    def extract_container_id(cgroup: str) -> str | None:
        for line in cgroup.splitlines():
            path = line.rsplit(":", 1)[-1]
            for pattern in CONTAINER_ID_PATTERNS:
                match = pattern.search(path)
                if match:
                    return match.group("id")
        return None

    def container_name(self, container_id: str) -> str | None:
        now = time.monotonic()
        cached = self.container_name_cache.get(container_id)
        if cached and now - cached[0] < 300:
            return cached[1]

        name: str | None = None
        candidates: list[Path] = []

        exact = CONTAINERS_ROOT / container_id / "config.v2.json"
        if exact.exists():
            candidates = [exact]
        else:
            # A plain prefix scan instead of Path.glob(): glob() pulls in
            # fnmatch on first use, which is one more lazily-imported stdlib
            # module that would break post-chroot (see the heapq import
            # note above) for no real benefit here - it's a fixed prefix
            # match, not a pattern.
            try:
                candidates = [
                    CONTAINERS_ROOT / entry / "config.v2.json"
                    for entry in os.listdir(CONTAINERS_ROOT)
                    if entry.startswith(container_id)
                ][:2]
            except OSError:
                candidates = []

        for config_path in candidates:
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
                raw_name = data.get("Name")
                if isinstance(raw_name, str):
                    name = raw_name.lstrip("/") or None
                    break
            except (OSError, json.JSONDecodeError):
                continue

        self.container_name_cache[container_id] = (now, name)
        return name

    @staticmethod
    def classify_source(path: str) -> str:
        if path.startswith("/mnt/user/"):
            return "user-share"
        if re.match(r"^/mnt/disk\d+/", path):
            return "physical-disk"
        return "other"

    def consume_fanotify(self) -> None:
        while True:
            try:
                data = os.read(self.fd, 1024 * 256)
            except BlockingIOError:
                return
            except OSError as exc:
                if exc.errno in {errno.EAGAIN, errno.EINTR}:
                    return
                raise

            if not data:
                return

            offset = 0
            data_len = len(data)
            while offset + METADATA.size <= data_len:
                (
                    event_len,
                    version,
                    _reserved,
                    metadata_len,
                    mask,
                    event_fd,
                    pid,
                ) = METADATA.unpack_from(data, offset)

                if event_len < metadata_len or event_len <= 0:
                    break
                offset += event_len

                if version != FANOTIFY_METADATA_VERSION:
                    self.log(
                        f"WARN: unsupported fanotify metadata version {version}",
                        syslog.LOG_WARNING,
                    )
                    continue

                if mask & FAN_Q_OVERFLOW:
                    self.overflow_count += 1
                    self.log(
                        "WARN: fanotify queue overflow; some events were lost.",
                        syslog.LOG_WARNING,
                    )
                    continue

                if event_fd < 0:
                    continue

                try:
                    path = os.readlink(f"/proc/self/fd/{event_fd}")
                    process, command, container_id, container_name = (
                        self.process_details(pid)
                    )
                    event = FsEvent(
                        epoch=time.time(),
                        monotonic=time.monotonic(),
                        pid=pid,
                        process=process,
                        command=command,
                        container_id=container_id,
                        container_name=container_name,
                        path=path,
                        operation=self.operation_from_mask(mask),
                        source=self.classify_source(path),
                    )
                    self.events.append(event)
                except OSError as exc:
                    self.event_read_errors += 1
                    self.last_event_read_error = errno.errorcode.get(
                        exc.errno, str(exc.errno)
                    )
                    self.last_event_read_error_epoch = time.time()
                    # ENOENT is the common case (the fd's target vanished
                    # before readlink/proc could resolve it) and would just
                    # flood the syslog if logged every time.
                    if exc.errno != errno.ENOENT:
                        self.log(
                            f"DEBUG: dropped fanotify event (pid={pid}): {exc}",
                            syslog.LOG_DEBUG,
                        )
                finally:
                    try:
                        os.close(event_fd)
                    except OSError:
                        pass

    def detect_spinups(self, now: float) -> None:
        states = self.read_disk_states()
        self.refresh_marks(states)

        for disk, state in states.items():
            previous = self.last_states.get(disk)
            self.last_states[disk] = state

            if previous != "1" or state != "0":
                continue

            last = self.last_alert.get(disk, 0.0)
            if now - last < COOLDOWN_SECONDS:
                continue

            self.last_alert[disk] = now
            self.pending.append(
                {
                    "disk": disk,
                    "spinup_epoch": time.time(),
                    "spinup_monotonic": now,
                    "report_after": now + SECONDS_AFTER,
                }
            )

    @staticmethod
    def sanitize_path(path: str) -> str:
        if LOG_FULL_PATHS:
            return path

        parts = Path(path).parts
        if len(parts) >= 4 and parts[:3] == ("/", "mnt", "user"):
            return f"/mnt/user/{parts[3]}/..."
        if (
            len(parts) >= 4
            and parts[0:2] == ("/", "mnt")
            and DISK_RE.fullmatch(parts[2])
        ):
            return f"/mnt/{parts[2]}/{parts[3]}/..."
        return path

    def event_window(self, spinup_monotonic: float) -> list[FsEvent]:
        start = spinup_monotonic - SECONDS_BEFORE
        end = spinup_monotonic + SECONDS_AFTER
        return [event for event in self.events if start <= event.monotonic <= end]

    def summarize_events(
        self, events: list[FsEvent]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        process_counts: Counter[tuple[str, str | None, int]] = Counter()
        path_counts: Counter[str] = Counter()

        for event in events:
            process_counts[(event.process, event.container_name, event.pid)] += 1
            path_counts[self.sanitize_path(event.path)] += 1

        processes = [
            {
                "process": process,
                "container": container,
                "pid": pid,
                "events": count,
            }
            for (process, container, pid), count in process_counts.most_common(
                MAX_PROCESSES
            )
        ]
        paths = [
            {"path": path, "events": count}
            for path, count in path_counts.most_common(MAX_PATHS)
        ]
        return processes, paths

    def build_report(self, disk: str, spinup_epoch: float, spinup_monotonic: float) -> dict[str, Any]:
        window = self.event_window(spinup_monotonic)
        disk_prefix = f"/mnt/{disk}/"

        direct = [event for event in window if event.path.startswith(disk_prefix)]
        user = [event for event in window if event.path.startswith("/mnt/user/")]

        # Direct events prove activity on *this* disk. User-share events only
        # prove activity on *some* share in the time window - shfs may have
        # routed a concurrent request to a completely different disk, so
        # they are summarized separately instead of merged into one counter
        # (merging would misattribute e.g. a concurrent write to another
        # disk's share to this disk's spin-up).
        direct_processes, direct_paths = self.summarize_events(direct)
        indirect_processes, indirect_paths = self.summarize_events(user)
        operation_counts: Counter[str] = Counter(
            event.operation for event in direct + user
        )

        # "high" requires the *same* process/container to show up in both
        # groups - direct and user-share events from unrelated processes
        # merely overlapping in time is not strong evidence they're related.
        direct_identities = {(event.pid, event.container_id) for event in direct}
        user_identities = {(event.pid, event.container_id) for event in user}

        if direct_identities & user_identities:
            confidence = "high"
            reason = "same process/container seen in both physical-disk and user-share events"
        elif direct:
            confidence = "medium"
            reason = "matching physical-disk events only"
        elif user:
            confidence = "low"
            reason = "user-share events in the time window; disk mapping is inferred"
        else:
            confidence = "none"
            reason = "no matching filesystem events in the time window"

        return {
            "type": "spinup",
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S%z", time.localtime(spinup_epoch)
            ),
            "epoch": spinup_epoch,
            "disk": disk,
            "confidence": confidence,
            "reason": reason,
            "window_seconds_before": SECONDS_BEFORE,
            "window_seconds_after": SECONDS_AFTER,
            "direct_event_count": len(direct),
            "user_share_event_count": len(user),
            "direct_processes": direct_processes,
            "direct_paths": direct_paths,
            "indirect_processes": indirect_processes,
            "indirect_paths": indirect_paths,
            "operations": dict(operation_counts),
        }

    def rotate_events_file_if_needed(self) -> None:
        try:
            size = os.stat(EVENTS_FILE.name, dir_fd=self.data_dir_fd).st_size
        except FileNotFoundError:
            return
        if size < EVENTS_MAX_BYTES:
            return

        for index in range(EVENTS_BACKUP_COUNT - 1, 0, -1):
            src = f"{EVENTS_FILE.name}.{index}"
            dst = f"{EVENTS_FILE.name}.{index + 1}"
            try:
                os.replace(
                    src, dst, src_dir_fd=self.data_dir_fd, dst_dir_fd=self.data_dir_fd
                )
            except FileNotFoundError:
                pass

        if EVENTS_BACKUP_COUNT > 0:
            os.replace(
                EVENTS_FILE.name,
                f"{EVENTS_FILE.name}.1",
                src_dir_fd=self.data_dir_fd,
                dst_dir_fd=self.data_dir_fd,
            )
        else:
            os.remove(EVENTS_FILE.name, dir_fd=self.data_dir_fd)

        os.fsync(self.data_dir_fd)

    def append_event(self, report: dict[str, Any]) -> None:
        self.rotate_events_file_if_needed()
        line = (json.dumps(report, ensure_ascii=False) + "\n").encode("utf-8")
        fd = os.open(
            EVENTS_FILE.name,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644,
            dir_fd=self.data_dir_fd,
        )
        try:
            self.write_all(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def emit_report(self, report: dict[str, Any]) -> None:
        self.append_event(report)

        self.log(
            f"SPINUP {report['disk']} confidence={report['confidence']} "
            f"direct={report['direct_event_count']} "
            f"user_share={report['user_share_event_count']}"
        )

        if not report["direct_processes"] and not report["indirect_processes"]:
            self.log(f"  No matching process: {report['reason']}")
            return

        for item in report["direct_processes"]:
            container = (
                f" container={item['container']}" if item["container"] else ""
            )
            self.log(
                f"  direct process={item['process']} pid={item['pid']}"
                f"{container} events={item['events']}"
            )
        for item in report["direct_paths"]:
            self.log(f"  direct path={item['path']} events={item['events']}")

        for item in report["indirect_processes"]:
            container = (
                f" container={item['container']}" if item["container"] else ""
            )
            self.log(
                f"  possible (user-share) process={item['process']} pid={item['pid']}"
                f"{container} events={item['events']}"
            )
        for item in report["indirect_paths"]:
            self.log(
                f"  possible (user-share) path={item['path']} events={item['events']}"
            )

    def process_pending(self, now: float) -> None:
        ready = [item for item in self.pending if now >= item["report_after"]]
        self.pending = [item for item in self.pending if now < item["report_after"]]

        for item in ready:
            report = self.build_report(
                item["disk"],
                item["spinup_epoch"],
                item["spinup_monotonic"],
            )
            self.emit_report(report)

    def write_status(self) -> None:
        now_epoch = time.time()
        if now_epoch - self.last_status_write < 10:
            return

        status = {
            "status": "running",
            "updated_epoch": now_epoch,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "started_epoch": self.started_epoch,
            "pid": os.getpid(),
            "fanotify_fd": self.fd,
            "array_started": self.array_started(),
            "marked_paths": sorted(self.marked_paths),
            "buffered_events": len(self.events),
            "pending_reports": len(self.pending),
            "fanotify_overflows": self.overflow_count,
            "event_read_errors": self.event_read_errors,
            "last_event_read_error": self.last_event_read_error,
            "last_event_read_error_at": (
                time.strftime(
                    "%Y-%m-%dT%H:%M:%S%z",
                    time.localtime(self.last_event_read_error_epoch),
                )
                if self.last_event_read_error_epoch is not None
                else None
            ),
            "watch_disks": sorted(WATCH_DISKS) if WATCH_DISKS else "automatic",
        }

        payload = json.dumps(status, ensure_ascii=False, indent=2).encode("utf-8")
        tmp_name = f"{STATUS_FILE.name}.tmp"
        fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o644,
            dir_fd=self.data_dir_fd,
        )
        try:
            self.write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(
            tmp_name,
            STATUS_FILE.name,
            src_dir_fd=self.data_dir_fd,
            dst_dir_fd=self.data_dir_fd,
        )
        os.fsync(self.data_dir_fd)
        self.last_status_write = now_epoch

    def shutdown(self, *_args: Any) -> None:
        self.stop_requested = True

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

        syslog.openlog(
            ident="disk-access-monitor",
            logoption=syslog.LOG_PID,
            facility=syslog.LOG_DAEMON,
        )

        self.open_data_dir()
        self.enter_host_mount_namespace()
        self.init_fanotify()

        initial_states = self.read_disk_states()
        self.last_states.update(initial_states)
        self.refresh_marks(initial_states)

        self.log(
            "Disk Access Monitor started "
            f"(window=-{SECONDS_BEFORE}s/+{SECONDS_AFTER}s, "
            f"disks={','.join(sorted(WATCH_DISKS)) if WATCH_DISKS else 'automatic'})"
        )

        while not self.stop_requested:
            now = time.monotonic()

            readable, _, _ = select.select([self.fd], [], [], POLL_INTERVAL)
            if readable:
                self.consume_fanotify()

            if now - self.last_state_poll >= POLL_INTERVAL:
                if self.array_started():
                    self.detect_spinups(now)
                self.last_state_poll = now

            self.process_pending(now)
            self.write_status()

        self.log("Disk Access Monitor stopped")
        if self.fd >= 0:
            os.close(self.fd)
        if self.data_dir_fd >= 0:
            os.close(self.data_dir_fd)


def main() -> int:
    monitor = HostFanotifyMonitor()
    try:
        monitor.run()
        return 0
    except MonitorError as exc:
        print(f"FATAL: {exc}", file=sys.stderr, flush=True)
        return 1
    except ModuleNotFoundError as exc:
        print(
            f"FATAL unexpected error: {exc!r} - this is likely a stdlib "
            "module imported for the first time (e.g. via a stdlib "
            "function's own lazy import) after "
            "enter_host_mount_namespace()'s setns()+chroot(); Python then "
            "searches the *host* filesystem for it instead of this image's. "
            "Fix: add an eager `import <module>` near the top of "
            "monitor.py, alongside the existing `import heapq` note.",
            file=sys.stderr,
            flush=True,
        )
        return 1
    except Exception as exc:
        print(f"FATAL unexpected error: {exc!r}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
