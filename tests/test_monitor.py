"""Unit tests for the pure/stateless parts of monitor.py.

These only cover logic that does not require root, fanotify or an actual
Unraid host, so they can run in plain CI (GitHub Actions).
"""

import importlib.util
import json
import os
import pathlib
import sys

import pytest

MODULE_PATH = pathlib.Path(__file__).resolve().parent.parent / "monitor.py"
spec = importlib.util.spec_from_file_location("monitor", MODULE_PATH)
monitor = importlib.util.module_from_spec(spec)
# dataclass(slots=True) in monitor.py looks up cls.__module__ in
# sys.modules while rebuilding the class; without this the import raises
# AttributeError: 'NoneType' object has no attribute '__dict__'.
sys.modules[spec.name] = monitor
spec.loader.exec_module(monitor)


# -- env_bool / env_int / env_float -----------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [("1", True), ("true", True), ("YES", True), ("on", True),
     ("0", False), ("false", False), ("", False), ("nonsense", False)],
)
def test_env_bool(monkeypatch, value, expected):
    monkeypatch.setenv("X", value)
    assert monitor.env_bool("X", False) is expected


def test_env_bool_default_when_unset(monkeypatch):
    monkeypatch.delenv("X", raising=False)
    assert monitor.env_bool("X", True) is True
    assert monitor.env_bool("X", False) is False


def test_env_int_valid(monkeypatch):
    monkeypatch.setenv("X", "42")
    assert monitor.env_int("X", 0) == 42


def test_env_int_enforces_minimum(monkeypatch):
    monkeypatch.setenv("X", "-5")
    assert monitor.env_int("X", 0, minimum=1) == 1


def test_env_int_invalid_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("X", "not-an-int")
    assert monitor.env_int("X", 7) == 7


def test_env_float_invalid_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("X", "not-a-float")
    assert monitor.env_float("X", 2.5) == 2.5


# -- HostFanotifyMonitor static helpers --------------------------------------

def test_operation_from_mask_combines_flags():
    mask = monitor.FAN_OPEN | monitor.FAN_MODIFY
    assert monitor.HostFanotifyMonitor.operation_from_mask(mask) == "open+modify"


def test_operation_from_mask_unknown_flag():
    result = monitor.HostFanotifyMonitor.operation_from_mask(0x40000000)
    assert result.startswith("mask:0x")


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/mnt/user/media/movie.mkv", "user-share"),
        ("/mnt/disk3/media/movie.mkv", "physical-disk"),
        ("/mnt/cache/foo", "other"),
    ],
)
def test_classify_source(path, expected):
    assert monitor.HostFanotifyMonitor.classify_source(path) == expected


def test_extract_container_id_from_cgroup():
    container_id = "a" * 64
    cgroup = f"12:pids:/docker/{container_id}\n11:cpu:/docker/{container_id}"
    assert monitor.HostFanotifyMonitor.extract_container_id(cgroup) == container_id


def test_extract_container_id_no_match():
    assert monitor.HostFanotifyMonitor.extract_container_id("0::/") is None


def test_heapq_is_eagerly_imported():
    # Guards against someone "cleaning up" this apparently-unused import:
    # collections.Counter.most_common(n) imports heapq lazily on first use,
    # which crashes with ModuleNotFoundError once monitor.py has chroot'd
    # into the host root (confirmed in production) unless heapq is already
    # cached in sys.modules beforehand. See the comment in monitor.py.
    assert hasattr(monitor, "heapq")


def test_container_name_matches_by_short_id_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "CONTAINERS_ROOT", tmp_path)
    full_id = "b" * 64
    container_dir = tmp_path / full_id
    container_dir.mkdir()
    (container_dir / "config.v2.json").write_text('{"Name": "/plex"}')

    mon = monitor.HostFanotifyMonitor()
    short_id = full_id[:12]

    assert mon.container_name(short_id) == "plex"


def test_container_name_no_match_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "CONTAINERS_ROOT", tmp_path)
    mon = monitor.HostFanotifyMonitor()

    assert mon.container_name("deadbeef0000") is None


def test_parse_ini_sections(tmp_path):
    ini_file = tmp_path / "disks.ini"
    ini_file.write_text(
        '[disk1]\n'
        'spundown="0"\n'
        '[disk2]\n'
        'spundown="1"\n'
    )
    sections = monitor.HostFanotifyMonitor.parse_ini_sections(ini_file)
    assert sections == {"disk1": {"spundown": "0"}, "disk2": {"spundown": "1"}}


def test_parse_ini_sections_missing_file(tmp_path):
    assert monitor.HostFanotifyMonitor.parse_ini_sections(tmp_path / "missing.ini") == {}


def test_sanitize_path_truncates_user_share(monkeypatch):
    monkeypatch.setattr(monitor, "LOG_FULL_PATHS", False)
    result = monitor.HostFanotifyMonitor.sanitize_path("/mnt/user/media/movie.mkv")
    assert result == "/mnt/user/media/..."


def test_sanitize_path_truncates_disk(monkeypatch):
    monkeypatch.setattr(monitor, "LOG_FULL_PATHS", False)
    result = monitor.HostFanotifyMonitor.sanitize_path("/mnt/disk3/media/movie.mkv")
    assert result == "/mnt/disk3/media/..."


def test_sanitize_path_full_paths_disabled_truncation(monkeypatch):
    monkeypatch.setattr(monitor, "LOG_FULL_PATHS", True)
    path = "/mnt/user/media/movie.mkv"
    assert monitor.HostFanotifyMonitor.sanitize_path(path) == path


# -- build_report: direct vs. indirect (user-share) attribution -------------

def make_event(**overrides):
    defaults = dict(
        epoch=0.0,
        monotonic=95.0,
        pid=100,
        process="plex",
        command="plex",
        container_id=None,
        container_name=None,
        path="/mnt/disk1/media/movie.mkv",
        operation="open",
        source="physical-disk",
    )
    defaults.update(overrides)
    return monitor.FsEvent(**defaults)


def test_build_report_keeps_direct_and_indirect_processes_separate():
    mon = monitor.HostFanotifyMonitor()
    # Direct: plex reading disk1 directly.
    mon.events.append(
        make_event(process="plex", pid=100, path="/mnt/disk1/media/movie.mkv")
    )
    # Unrelated concurrent user-share activity from a different app/share -
    # must NOT be counted as evidence that immich touched disk1.
    mon.events.append(
        make_event(
            process="immich",
            pid=200,
            path="/mnt/user/photos/pic.jpg",
            source="user-share",
        )
    )

    report = mon.build_report("disk1", spinup_epoch=1000.0, spinup_monotonic=100.0)

    assert [p["process"] for p in report["direct_processes"]] == ["plex"]
    assert [p["process"] for p in report["indirect_processes"]] == ["immich"]
    # Two different processes just overlapping in time is not strong
    # evidence they're related - only a direct hit, so "medium".
    assert report["confidence"] == "medium"


def test_build_report_confidence_high_requires_matching_identity():
    mon = monitor.HostFanotifyMonitor()
    # Same process (same pid) shows up in both groups: it read the share
    # first (shfs), then the request landed on disk1 directly.
    mon.events.append(
        make_event(process="plex", pid=100, path="/mnt/user/media/movie.mkv", source="user-share")
    )
    mon.events.append(
        make_event(process="plex", pid=100, path="/mnt/disk1/media/movie.mkv")
    )

    report = mon.build_report("disk1", spinup_epoch=1000.0, spinup_monotonic=100.0)

    assert report["confidence"] == "high"


def test_build_report_no_events_in_window():
    mon = monitor.HostFanotifyMonitor()
    mon.events.append(make_event(monotonic=0.0))  # far outside the window

    report = mon.build_report("disk1", spinup_epoch=1000.0, spinup_monotonic=100.0)

    assert report["direct_processes"] == []
    assert report["indirect_processes"] == []
    assert report["confidence"] == "none"


# -- dir_fd based data writes (the pre-chroot fd from open_data_dir) --------

def open_dir_fd(path: pathlib.Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY)


def test_write_status_creates_status_file_via_dir_fd(tmp_path):
    mon = monitor.HostFanotifyMonitor()
    mon.data_dir_fd = open_dir_fd(tmp_path)
    try:
        mon.write_status()
    finally:
        os.close(mon.data_dir_fd)

    status_file = tmp_path / "status.json"
    assert status_file.exists()
    data = json.loads(status_file.read_text())
    assert data["status"] == "running"
    assert data["event_read_errors"] == 0
    assert data["last_event_read_error"] is None
    assert data["last_event_read_error_at"] is None
    assert not (tmp_path / "status.json.tmp").exists()


def test_write_status_reports_last_event_read_error(tmp_path):
    mon = monitor.HostFanotifyMonitor()
    mon.event_read_errors = 4
    mon.last_event_read_error = "EBADF"
    mon.last_event_read_error_epoch = 1700000000.0
    mon.data_dir_fd = open_dir_fd(tmp_path)
    try:
        mon.write_status()
    finally:
        os.close(mon.data_dir_fd)

    data = json.loads((tmp_path / "status.json").read_text())
    assert data["event_read_errors"] == 4
    assert data["last_event_read_error"] == "EBADF"
    assert data["last_event_read_error_at"] is not None


def test_append_event_rotates_when_over_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "EVENTS_MAX_BYTES", 100)
    monkeypatch.setattr(monitor, "EVENTS_BACKUP_COUNT", 2)

    mon = monitor.HostFanotifyMonitor()
    mon.data_dir_fd = open_dir_fd(tmp_path)
    try:
        for i in range(20):
            mon.append_event({"n": i, "pad": "x" * 20})
    finally:
        os.close(mon.data_dir_fd)

    assert (tmp_path / "events.jsonl").exists()
    assert (tmp_path / "events.jsonl.1").exists()
    # backup count is capped at 2 - no third generation should exist
    assert not (tmp_path / "events.jsonl.3").exists()
