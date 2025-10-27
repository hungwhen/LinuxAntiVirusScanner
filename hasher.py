#!/usr/bin/env python3
import os, sys, stat, time, hashlib, traceback
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Settings ---
CHUNK = 1 << 20
PROGRESS_EVERY = 200
SUBMIT_BATCH = 5000
HEARTBEAT_SEC = 5.0
DEBUG_LOG = "debug_output.log"
HASH_FILE = "hashes.txt"

# Filesystem types we’ll skip (pseudo/virtual or problematic for hashing)
SKIP_FS_TYPES = {
    "proc","sysfs","devtmpfs","devpts","tmpfs","hugetlbfs",
    "cgroup","cgroup2","configfs","fusectl","debugfs","securityfs",
    "pstore","bpf","tracefs","ramfs","autofs","sockfs","pipefs",
    "overlay",      # often Docker/containers
    "squashfs",     # snaps / app images (optional to skip)
    "nsfs","binfmt_misc","rpc_pipefs","mqueue","zramfs","zsmalloc"
}
# If a type starts with any of these prefixes, skip as well
SKIP_FS_PREFIXES = ("cgroup", "fuse.", "fusectl")

# ----------------

def load_mounts_to_skip():
    """
    Parse /proc/self/mountinfo (preferred) or /proc/mounts and
    return a list of mountpoints to skip, based on SKIP_FS_TYPES/ prefixes.
    """
    mounts = []
    path = "/proc/self/mountinfo" if os.path.exists("/proc/self/mountinfo") else "/proc/mounts"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # mountinfo format:
                # ID parent major:minor root mountpoint options - fstype source superopts
                # We split on " - " first to get fstype reliably.
                if path.endswith("mountinfo"):
                    try:
                        left, right = line.strip().split(" - ", 1)
                        parts_left = left.split()
                        mountpoint = parts_left[4]
                        fstype = right.split()[0]
                    except Exception:
                        continue
                else:
                    # /proc/mounts: <source> <mountpoint> <fstype> ...
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    mountpoint, fstype = parts[1], parts[2]

                if (fstype in SKIP_FS_TYPES) or any(fstype.startswith(pfx) for pfx in SKIP_FS_PREFIXES):
                    mounts.append(os.path.abspath(mountpoint))
    except Exception:
        pass

    # Sort longest-first so child mounts match before parents
    mounts = sorted(set(mounts), key=lambda p: (-len(p), p))
    return mounts

def path_on_skipped_mount(path, skip_mounts):
    # Quick check whether path is under any skipped mountpoint
    ap = os.path.abspath(path)
    for m in skip_mounts:
        if ap == m or ap.startswith(m + os.sep):
            return True
    return False

def teeprint(*args, **kw):
    msg = " ".join(str(a) for a in args)
    print(msg, flush=True, **kw)
    print(msg, file=logfile, flush=True, **kw)

def is_regular_file(path):
    try:
        st = os.lstat(path)
        return stat.S_ISREG(st.st_mode)
    except OSError:
        return False

def blake2b_file(path, size=64):
    pid = os.getpid()
    teeprint(f"[WORKER {pid}] OPENING: {path}")
    h = hashlib.blake2b(digest_size=size)
    bytes_read = 0
    try:
        with open(path, 'rb') as f:
            for b in iter(lambda: f.read(CHUNK), b''):
                h.update(b)
                bytes_read += len(b)
        teeprint(f"[WORKER {pid}] DONE: {path} read={bytes_read} bytes")
        return h.hexdigest()
    except Exception as e:
        teeprint(f"[WORKER {pid}] ERROR {path}: {e}")
        traceback.print_exc(file=logfile)
        return None

def hash_one(args):
    path, skip_mounts = args
    pid = os.getpid()
    teeprint(f"[WORKER {pid}] START {path}")

    if path_on_skipped_mount(path, skip_mounts):
        teeprint(f"[WORKER {pid}] SKIP (skipped fs mount): {path}")
        return (path, None)

    if not is_regular_file(path):
        teeprint(f"[WORKER {pid}] SKIP (not regular): {path}")
        return (path, None)

    digest = blake2b_file(path)
    return (path, digest)

def hash_all(root='/', out_file=HASH_FILE, workers=None):
    if workers is None:
        workers = max(4, (os.cpu_count() or 4))

    skip_mounts = load_mounts_to_skip()
    teeprint(f"[START] root={root} workers={workers}")
    if skip_mounts:
        teeprint("[SKIP] mountpoints:", *("  - " + m for m in skip_mounts), sep="\n")

    submitted = 0
    done = 0
    errors = 0
    futures = []
    last_heartbeat = time.monotonic()

    def heartbeat():
        nonlocal last_heartbeat
        now = time.monotonic()
        if now - last_heartbeat >= HEARTBEAT_SEC:
            inflight = len(futures)
            sample = [getattr(f, "_path", None) for f in futures[:5]]
            teeprint(f"[HEARTBEAT] done={done} errors={errors} submitted={submitted} inflight={inflight}")
            if sample:
                teeprint("[HEARTBEAT] sample in-flight:")
                for s in sample:
                    teeprint("   -", s)
            last_heartbeat = now

    def drain(n=None):
        nonlocal done, errors
        count = 0
        snapshot = list(futures) if n is None else futures[:n]
        for fut in as_completed(snapshot):
            try:
                futures.remove(fut)
            except ValueError:
                pass
            path, digest = fut.result()
            if digest:
                out.write(f"{digest} {path}\n")
            else:
                errors += 1
            done += 1
            if done % PROGRESS_EVERY == 0:
                out.flush()
                teeprint(f"[PROGRESS] {done} done ({errors} errors, {submitted} submitted)")
            count += 1
            if n is not None and count >= n:
                break

    with ProcessPoolExecutor(max_workers=workers) as pool, \
         open(out_file, 'a', encoding='utf-8') as out:

        for dirpath, _, filenames in os.walk(root, followlinks=False):
            teeprint(f"[SCAN] dir: {dirpath}")
            for name in filenames:
                fpath = os.path.join(dirpath, name)
                fut = pool.submit(hash_one, (fpath, skip_mounts))
                setattr(fut, "_path", fpath)
                futures.append(fut)
                submitted += 1

                if submitted % 500 == 0:
                    teeprint(f"[INFO] submitted {submitted} files; inflight={len(futures)}")

                if submitted % SUBMIT_BATCH == 0:
                    teeprint(f"[INFO] submitted {submitted}; draining half of batch…")
                    drain(n=SUBMIT_BATCH // 2)

                heartbeat()

        teeprint(f"[INFO] submission complete. draining remaining {len(futures)} futures…")
        drain()
        out.flush()

    teeprint(f"[DONE] submitted={submitted} ok={done - errors} errors={errors}")
    return 0

if __name__ == '__main__':
    with open(DEBUG_LOG, 'w', encoding='utf-8') as logfile:
        root = sys.argv[1] if len(sys.argv) > 1 else '/'
        outp = sys.argv[2] if len(sys.argv) > 2 else HASH_FILE
        hash_all(root, outp)
    print(f"All debug output saved to {DEBUG_LOG}")
    print(f"Hashes saved to {HASH_FILE}")

