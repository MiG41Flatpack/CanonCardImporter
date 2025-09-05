# CanonImporter_tk.py
# Tkinter GUI importer for Canon cards, date-folder routing, duplicate skip, logging
# Remembers last Source and Destination in %APPDATA%\CanonImporter\settings.json

import os
import sys
import time
import json
import queue
import threading
import hashlib
import datetime
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import exifread

DEFAULT_EXTS = "jpg jpeg cr2 cr3 mp4 mov avi mkv heic"
BUFFER_SIZE = 1024 * 1024  # 1 MB

# --------- settings persistence ----------
def _settings_path():
    base = os.environ.get("APPDATA") or str(Path.home())
    cfg_dir = Path(base) / "CanonImporter"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "settings.json"

def load_settings():
    try:
        p = _settings_path()
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_settings(data: dict):
    try:
        p = _settings_path()
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# --------- helpers ----------
def read_exif_datetime(path: Path):
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        raw = None
        for key in ("EXIF DateTimeOriginal", "EXIF DateTimeDigitized", "Image DateTime"):
            if key in tags and str(tags[key]).strip():
                raw = str(tags[key]).strip()
                break
        if not raw:
            return None
        if len(raw) >= 19 and raw[4] == ":" and raw[7] == ":" and raw[13] == ":" and raw[16] == ":":
            y = int(raw[0:4]); m = int(raw[5:7]); d = int(raw[8:10])
            H = int(raw[11:13]); M = int(raw[14:16]); S = int(raw[17:19])
            return datetime.datetime(y, m, d, H, M, S)
    except Exception:
        pass
    return None

def resolve_capture_datetime(p: Path):
    ext = p.suffix.lower()
    if ext in [".jpg", ".jpeg"]:
        dt = read_exif_datetime(p)
        if dt:
            return dt
    try:
        stat = p.stat()
        return datetime.datetime.fromtimestamp(stat.st_ctime)
    except Exception:
        return datetime.datetime.fromtimestamp(p.stat().st_mtime)

def next_available_with_suffix(dest_dir: Path, name: str):
    base = Path(name).stem
    ext = Path(name).suffix
    i = 1
    while True:
        candidate = dest_dir / f"{base}_{i}{ext}"
        if not candidate.exists():
            return candidate
        i += 1

def same_file_by_size(a: Path, b: Path):
    try:
        return a.stat().st_size == b.stat().st_size
    except Exception:
        return False

def md5sum(p: Path):
    h = hashlib.md5()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# --------- worker ----------
def importer_worker(params, emit):
    try:
        src = Path(params["src"])
        dest_root = Path(params["dest"])
        dry_run = params["dry_run"]
        use_hash = params["use_hash"]
        exts = set(x.strip().lower() for x in params["exts"].split() if x.strip())
        stop_flag = params["stop_flag"]

        if not src.exists():
            emit("ERROR", f"Source does not exist, {src}")
            return
        dest_root.mkdir(parents=True, exist_ok=True)

        files = []
        for p in src.rglob("*"):
            if p.is_file() and p.suffix.lower().lstrip(".") in exts:
                files.append(p)
        files.sort()

        total = len(files)
        copied = 0
        skipped = 0

        log_lines = []
        run_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_lines.append(f"==== Import run {run_stamp} ====")

        emit("TOTAL", total)

        for idx, f in enumerate(files, start=1):
            if stop_flag.is_set():
                log_lines.append("CANCEL, user stopped the import")
                break

            emit("STATUS", f"Planning {f.name} ({idx} of {total})")

            dt = resolve_capture_datetime(f)
            date_str = dt.strftime("%Y_%m_%d")
            dest_dir = dest_root / date_str
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_file = dest_dir / f.name

            if dest_file.exists():
                if same_file_by_size(f, dest_file):
                    if use_hash:
                        if md5sum(f) == md5sum(dest_file):
                            action = "SKIP"
                        else:
                            dest_file = next_available_with_suffix(dest_dir, f.name)
                            action = "COPY"
                    else:
                        action = "SKIP"
                else:
                    dest_file = next_available_with_suffix(dest_dir, f.name)
                    action = "COPY"
            else:
                action = "COPY"

            if dry_run:
                log_lines.append(f"{action}: {f} -> {dest_file}")
                if action == "COPY":
                    copied += 1
                else:
                    skipped += 1
                emit("PROGRESS", {"i": idx, "total": total, "copied": copied, "skipped": skipped, "current": f.name})
                continue

            if action == "COPY":
                size = f.stat().st_size
                done = 0
                with open(f, "rb") as r, open(dest_file, "wb") as w:
                    while True:
                        chunk = r.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        w.write(chunk)
                        done += len(chunk)
                        pct = int(done * 100 / size) if size else 100
                        emit("FILEPROG", {"name": f.name, "pct": pct})
                try:
                    os.utime(dest_file, (f.stat().st_atime, f.stat().st_mtime))
                except Exception:
                    pass
                copied += 1
                log_lines.append(f"COPY: {f} -> {dest_file}")
            else:
                skipped += 1
                log_lines.append(f"SKIP: {f} -> {dest_file}")

            emit("PROGRESS", {"i": idx, "total": total, "copied": copied, "skipped": skipped, "current": f.name})

        log_path = dest_root / "ImportLog.txt"
        with open(log_path, "a", encoding="utf-8") as logf:
            for line in log_lines:
                logf.write(line + "\n")

        emit("DONE", {"copied": copied, "skipped": skipped, "total": total, "log": str(log_path)})

    except Exception as e:
        emit("ERROR", f"{e}\n{traceback.format_exc()}")

# --------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Canon Card Importer")
        self.geometry("980x560")

        self.queue = queue.Queue()
        self.worker_thread = None
        self.stop_flag = threading.Event()

        # load saved settings
        self._saved = load_settings()
        last_src = self._saved.get("last_source", "")
        last_dest = self._saved.get("last_destination", "")
        last_exts = self._saved.get("last_extensions", DEFAULT_EXTS)
        last_hash = bool(self._saved.get("last_use_hash", False))

        self._build_ui(default_src=last_src, default_dest=last_dest,
                       default_exts=last_exts, default_hash=last_hash)

        # save on window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._poll_queue()

    def _build_ui(self, default_src="", default_dest="", default_exts=DEFAULT_EXTS, default_hash=False):
        pad = {"padx": 6, "pady": 6}

        frm_top = ttk.Frame(self)
        frm_top.pack(fill="x", **pad)

        ttk.Label(frm_top, text="Source folder").grid(row=0, column=0, sticky="w")
        self.var_src = tk.StringVar(value=default_src)
        ttk.Entry(frm_top, textvariable=self.var_src, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(frm_top, text="Browse", command=self.pick_src).grid(row=0, column=2, sticky="w")

        ttk.Label(frm_top, text="Destination").grid(row=1, column=0, sticky="w")
        self.var_dest = tk.StringVar(value=default_dest)
        ttk.Entry(frm_top, textvariable=self.var_dest, width=60).grid(row=1, column=1, sticky="we")
        ttk.Button(frm_top, text="Browse", command=self.pick_dest).grid(row=1, column=2, sticky="w")

        ttk.Label(frm_top, text="Extensions").grid(row=2, column=0, sticky="w")
        self.var_exts = tk.StringVar(value=default_exts)
        ttk.Entry(frm_top, textvariable=self.var_exts, width=60).grid(row=2, column=1, sticky="we")
        ttk.Label(frm_top, text="Space separated, e.g. jpg jpeg cr2 cr3 mp4 mov").grid(row=2, column=2, sticky="w")

        self.var_hash = tk.BooleanVar(value=default_hash)
        ttk.Checkbutton(frm_top, text="Use file hash to confirm duplicates, slower", variable=self.var_hash).grid(row=3, column=0, columnspan=3, sticky="w")

        frm_btns = ttk.Frame(self)
        frm_btns.pack(fill="x", **pad)
        ttk.Button(frm_btns, text="Dry Run", command=lambda: self.start_run(dry_run=True)).pack(side="left")
        ttk.Button(frm_btns, text="Start Import", command=lambda: self.start_run(dry_run=False)).pack(side="left")
        ttk.Button(frm_btns, text="Stop", command=self.stop_run).pack(side="left")
        ttk.Button(frm_btns, text="Exit", command=self._on_close).pack(side="right")

        frm_prog = ttk.Frame(self)
        frm_prog.pack(fill="x", **pad)

        ttk.Label(frm_prog, text="Overall").grid(row=0, column=0, sticky="w")
        self.pb_overall = ttk.Progressbar(frm_prog, maximum=100, length=600)
        self.pb_overall.grid(row=0, column=1, sticky="we")
        self.lbl_overall = ttk.Label(frm_prog, text="")
        self.lbl_overall.grid(row=0, column=2, sticky="w")

        ttk.Label(frm_prog, text="This file").grid(row=1, column=0, sticky="w")
        self.pb_file = ttk.Progressbar(frm_prog, maximum=100, length=600)
        self.pb_file.grid(row=1, column=1, sticky="we")
        self.lbl_file = ttk.Label(frm_prog, text="")
        self.lbl_file.grid(row=1, column=2, sticky="w")

        frm_cur = ttk.Frame(self)
        frm_cur.pack(fill="x", **pad)
        ttk.Label(frm_cur, text="Current file").pack(side="left")
        self.lbl_current = ttk.Label(frm_cur, text="", width=80)
        self.lbl_current.pack(side="left")

        frm_log = ttk.Frame(self)
        frm_log.pack(fill="both", expand=True, **pad)
        ttk.Label(frm_log, text="Log").pack(anchor="w")
        self.txt_log = tk.Text(frm_log, height=16, wrap="none")
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.configure(state="disabled")

        frm_status = ttk.Frame(self)
        frm_status.pack(fill="x")
        self.var_status = tk.StringVar(value="")
        ttk.Label(frm_status, textvariable=self.var_status, relief="sunken", anchor="w").pack(fill="x")

        for i in range(3):
            frm_top.grid_columnconfigure(i, weight=1)
        frm_prog.grid_columnconfigure(1, weight=1)

    # ---- UI callbacks ----
    def pick_src(self):
        path = filedialog.askdirectory(title="Select source folder")
        if path:
            self.var_src.set(path)
            self._save_now()  # persist change immediately

    def pick_dest(self):
        path = filedialog.askdirectory(title="Select destination folder")
        if path:
            self.var_dest.set(path)
            self._save_now()  # persist change immediately

    def start_run(self, dry_run: bool):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Busy", "An import is already running")
            return
        src = self.var_src.get().strip()
        dest = self.var_dest.get().strip()
        if not src or not dest:
            messagebox.showwarning("Missing", "Please pick both Source and Destination")
            return

        # save current selections so they come back next time
        self._save_now()

        self.stop_flag = threading.Event()
        self._set_overall(0, "")
        self._set_file(0, "")
        self.lbl_current.config(text="")
        self._log_clear()
        self.var_status.set("Starting...")

        params = {
            "src": src,
            "dest": dest,
            "exts": self.var_exts.get().strip() or DEFAULT_EXTS,
            "dry_run": dry_run,
            "use_hash": self.var_hash.get(),
            "stop_flag": self.stop_flag
        }

        def emit(name, payload):
            self.queue.put((name, payload))

        self.worker_thread = threading.Thread(target=importer_worker, args=(params, emit), daemon=True)
        self.worker_thread.start()

    def stop_run(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_flag.set()
            self.var_status.set("Stopping, please wait...")

    # ---- queue polling ----
    def _poll_queue(self):
        try:
            while True:
                name, payload = self.queue.get_nowait()
                self._handle_event(name, payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_event(self, name, payload):
        if name == "TOTAL":
            self._log(f"Found {payload} file(s)")
            self.var_status.set(f"Queued {payload} items")
            self.total_files = payload
        elif name == "STATUS":
            self.lbl_current.config(text=str(payload))
        elif name == "FILEPROG":
            pct = int(payload.get("pct", 0))
            self._set_file(pct, f"{pct}%")
        elif name == "PROGRESS":
            i = payload["i"]; total = payload["total"]
            copied = payload["copied"]; skipped = payload["skipped"]
            current = payload["current"]
            overall_pct = int((copied + skipped) * 100 / total) if total else 100
            self._set_overall(overall_pct, f"{copied + skipped} of {total}")
            self.lbl_current.config(text=current)
            self._log(f"[{i}/{total}] {current}  Copied={copied}  Skipped={skipped}")
        elif name == "DONE":
            msg = f"Done, copied {payload['copied']}, skipped {payload['skipped']}, total {payload['total']}\nLog, {payload['log']}"
            self.var_status.set(msg)
            self._log(msg)
            self._set_overall(100, "Done")
            self._set_file(100, "Done")
        elif name == "ERROR":
            self.var_status.set("Error, see log")
            self._log("ERROR:\n" + str(payload))

    # ---- small UI helpers ----
    def _set_overall(self, pct, text):
        self.pb_overall["value"] = pct
        self.lbl_overall.config(text=text)

    def _set_file(self, pct, text):
        self.pb_file["value"] = pct
        self.lbl_file.config(text=text)

    def _log(self, line: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", line + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _log_clear(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _save_now(self):
        save_settings({
            "last_source": self.var_src.get().strip(),
            "last_destination": self.var_dest.get().strip(),
            "last_extensions": self.var_exts.get().strip() or DEFAULT_EXTS,
            "last_use_hash": bool(self.var_hash.get())
        })

    def _on_close(self):
        self._save_now()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()