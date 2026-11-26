"""Módulo de monitoreo del servidor host (CPU, RAM, I/O Disco, Almacenamiento y Procesos)."""
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

_lock = threading.Lock()
_prev_disk_snap: Optional[Tuple[float, Any]] = None
_prev_proc_snap: Dict[int, Tuple[float, float, int, int]] = {}


def _get_storage_mounts() -> List[Dict[str, Any]]:
    mounts: List[Dict[str, Any]] = []
    seen_devices = set()

    if os.path.ismount("/hostfs") or os.path.isdir("/hostfs/etc"):
        try:
            usage = psutil.disk_usage("/hostfs")
            mounts.append({
                "mountpoint": "/ (Host Root)",
                "device": "root",
                "fstype": "hostfs",
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "percent": round(usage.percent, 1),
            })
            seen_devices.add("/hostfs")
        except Exception:
            pass

    skip_fs = {"squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "devpts"}
    try:
        for part in psutil.disk_partitions(all=False):
            if part.fstype in skip_fs:
                continue
            if part.mountpoint.startswith("/snap") or part.mountpoint.startswith("/var/lib/docker/overlay2"):
                continue
            if part.device in seen_devices:
                continue
            if "/hostfs" in seen_devices and part.mountpoint == "/":
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                if usage.total == 0:
                    continue
                seen_devices.add(part.device)
                mounts.append({
                    "mountpoint": part.mountpoint,
                    "device": part.device,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent": round(usage.percent, 1),
                })
            except Exception:
                continue
    except Exception:
        pass

    if not mounts:
        try:
            usage = psutil.disk_usage("/")
            mounts.append({
                "mountpoint": "/",
                "device": "root",
                "fstype": "fs",
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "percent": round(usage.percent, 1),
            })
        except Exception:
            pass
    return mounts


def _sample_processes() -> Tuple[float, Dict[int, Dict[str, Any]]]:
    now = time.monotonic()
    samples: Dict[int, Dict[str, Any]] = {}
    attrs = ["pid", "name", "username", "status", "cpu_times", "memory_info", "memory_percent", "cmdline"]

    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info
            pid = info["pid"]
            ct = info.get("cpu_times")
            cpu_time = (ct.user + ct.system) if ct else 0.0
            mem_info = info.get("memory_info")
            mem_mb = round((mem_info.rss / (1024 ** 2)), 1) if mem_info else 0.0
            mem_pct = round(info.get("memory_percent") or 0.0, 2)

            read_bytes, write_bytes = 0, 0
            try:
                io = proc.io_counters()
                read_bytes, write_bytes = io.read_bytes, io.write_bytes
            except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError, AttributeError):
                pass

            raw_cmd = info.get("cmdline") or []
            cmdline = " ".join(raw_cmd) if raw_cmd else (info.get("name") or "")
            if len(cmdline) > 120:
                cmdline = cmdline[:117] + "..."

            samples[pid] = {
                "pid": pid,
                "name": info.get("name") or "?",
                "username": info.get("username") or "-",
                "status": info.get("status") or "-",
                "cpu_time": cpu_time,
                "memory_mb": mem_mb,
                "memory_percent": mem_pct,
                "read_bytes": read_bytes,
                "write_bytes": write_bytes,
                "cmdline": cmdline,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return now, samples


def get_system_metrics(sort_by: str = "cpu", order: str = "desc", limit: int = 60) -> Dict[str, Any]:
    global _prev_disk_snap, _prev_proc_snap

    with _lock:
        cpu_total = psutil.cpu_percent(interval=0.15)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_cores = psutil.cpu_count(logical=True) or 1
        try:
            load1, load5, load15 = os.getloadavg()
        except Exception:
            load1, load5, load15 = 0.0, 0.0, 0.0

        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()

        now_disk = time.monotonic()
        disk_counters = psutil.disk_io_counters()
        read_mb_s = write_mb_s = read_iops = write_iops = total_read_gb = total_write_gb = 0.0

        if disk_counters:
            total_read_gb = round(disk_counters.read_bytes / (1024 ** 3), 2)
            total_write_gb = round(disk_counters.write_bytes / (1024 ** 3), 2)
            if _prev_disk_snap is not None:
                prev_ts, prev_dc = _prev_disk_snap
                dt = max(now_disk - prev_ts, 0.1)
                d_read = max(0, disk_counters.read_bytes - prev_dc.read_bytes)
                d_write = max(0, disk_counters.write_bytes - prev_dc.write_bytes)
                d_rcnt = max(0, disk_counters.read_count - prev_dc.read_count)
                d_wcnt = max(0, disk_counters.write_count - prev_dc.write_count)
                read_mb_s = round((d_read / dt) / (1024 ** 2), 2)
                write_mb_s = round((d_write / dt) / (1024 ** 2), 2)
                read_iops = round(d_rcnt / dt, 1)
                write_iops = round(d_wcnt / dt, 1)
            _prev_disk_snap = (now_disk, disk_counters)

        if not _prev_proc_snap:
            t0, s0 = _sample_processes()
            _prev_proc_snap = {pid: (t0, d["cpu_time"], d["read_bytes"], d["write_bytes"]) for pid, d in s0.items()}
            time.sleep(0.25)

        now_p, curr_samples = _sample_processes()
        processes: List[Dict[str, Any]] = []
        new_proc_snap: Dict[int, Tuple[float, float, int, int]] = {}

        for pid, d in curr_samples.items():
            cpu_pct = io_read_kbps = io_write_kbps = 0.0
            if pid in _prev_proc_snap:
                prev_ts, prev_ct, prev_rb, prev_wb = _prev_proc_snap[pid]
                dt = max(now_p - prev_ts, 0.1)
                cpu_pct = round((max(0.0, d["cpu_time"] - prev_ct) / dt) * 100.0, 1)
                if cpu_pct > cpu_cores * 100.0:
                    cpu_pct = round(cpu_cores * 100.0, 1)
                io_read_kbps = round((max(0, d["read_bytes"] - prev_rb) / dt) / 1024.0, 1)
                io_write_kbps = round((max(0, d["write_bytes"] - prev_wb) / dt) / 1024.0, 1)

            new_proc_snap[pid] = (now_p, d["cpu_time"], d["read_bytes"], d["write_bytes"])
            io_total_kbps = round(io_read_kbps + io_write_kbps, 1)
            io_total_mb = round((d["read_bytes"] + d["write_bytes"]) / (1024 ** 2), 1)

            processes.append({
                "pid": pid,
                "name": d["name"],
                "username": d["username"],
                "status": d["status"],
                "cpu_percent": cpu_pct,
                "memory_mb": d["memory_mb"],
                "memory_percent": d["memory_percent"],
                "io_read_kbps": io_read_kbps,
                "io_write_kbps": io_write_kbps,
                "io_total_kbps": io_total_kbps,
                "io_total_mb": io_total_mb,
                "cmdline": d["cmdline"],
            })

        _prev_proc_snap = new_proc_snap

    reverse = order.lower() != "asc"
    if sort_by == "memory":
        key_fn = lambda p: (p["memory_mb"], p["cpu_percent"])
    elif sort_by == "io":
        key_fn = lambda p: (p["io_total_kbps"], p["io_total_mb"], p["cpu_percent"])
    else:
        key_fn = lambda p: (p["cpu_percent"], p["memory_mb"])

    processes.sort(key=key_fn, reverse=reverse)

    return {
        "timestamp": int(time.time()),
        "cpu": {
            "percent": round(cpu_total, 1),
            "cores": cpu_cores,
            "per_core": [round(x, 1) for x in cpu_per_core],
            "load_1m": round(load1, 2),
            "load_5m": round(load5, 2),
            "load_15m": round(load15, 2),
        },
        "memory": {
            "total_gb": round(vm.total / (1024 ** 3), 2),
            "used_gb": round(vm.used / (1024 ** 3), 2),
            "available_gb": round(vm.available / (1024 ** 3), 2),
            "percent": round(vm.percent, 1),
            "swap_total_gb": round(sm.total / (1024 ** 3), 2),
            "swap_used_gb": round(sm.used / (1024 ** 3), 2),
            "swap_percent": round(sm.percent, 1),
        },
        "disk_io": {
            "read_mb_s": read_mb_s,
            "write_mb_s": write_mb_s,
            "total_mb_s": round(read_mb_s + write_mb_s, 2),
            "read_iops": read_iops,
            "write_iops": write_iops,
            "total_read_gb": total_read_gb,
            "total_write_gb": total_write_gb,
        },
        "storage": _get_storage_mounts(),
        "processes": processes[:max(10, min(limit, 150))],
        "total_processes": len(processes),
    }
