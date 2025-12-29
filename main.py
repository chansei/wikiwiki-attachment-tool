import os
import sys
import io
import json
import time
import base64
import threading
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

import ctypes
from ctypes import wintypes

import requests
from PIL import Image, ImageTk  # pillow

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from urllib.parse import quote


# =============================
# DPAPI
# =============================

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _dpapi_protect(data: bytes) -> bytes:
    """
    Windows DPAPI で暗号化する関数
    """
    if os.name != "nt":
        raise RuntimeError("DPAPI は Windows 専用です．")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_buf = ctypes.create_string_buffer(data)
    in_blob = _DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = _DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "WikiWikiAttachTool",
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise RuntimeError("暗号化に失敗しました．")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    """
    Windows DPAPI で復号化する関数
    """
    if os.name != "nt":
        raise RuntimeError("DPAPI は Windows 専用です．")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_buf = ctypes.create_string_buffer(data)
    in_blob = _DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = _DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise RuntimeError("復号に失敗しました．保存ファイルが壊れているか，別ユーザーで作成された可能性があります．")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _get_credentials_path() -> str:
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_dir, "credentials.bin")


# =============================
# API
# =============================

@dataclass
class AttachmentMeta:
    file: str
    type: str = ""
    size: int = 0
    size_str: str = ""
    time_str: str = ""
    md5hash: str = ""
    freeze: bool = False


class WikiWikiApiError(Exception):
    pass


class WikiWikiClient:
    def __init__(self, wiki_id: str, timeout_sec: int = 30):
        self.wiki_id = (wiki_id or "").strip()
        if not self.wiki_id:
            raise ValueError("wiki_id が空です．")
        self.base = f"https://api.wikiwiki.jp/{self.wiki_id}"
        self.timeout_sec = timeout_sec
        self.token: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    @staticmethod
    def _enc_page(page_name: str) -> str:
        parts = [quote(p, safe="") for p in (page_name or "").split("/")]
        return "/".join(parts)

    @staticmethod
    def _enc_file(file_name: str) -> str:
        return quote(file_name or "", safe="")

    def authenticate_with_api_key(self, api_key_id: str, secret: str) -> str:
        api_key_id = (api_key_id or "").strip()
        secret = (secret or "").strip()
        if not api_key_id or not secret:
            raise ValueError("API Key ID と Secret を入力してください．")

        payload = {"api_key_id": api_key_id, "secret": secret}
        url = f"{self.base}/auth"

        last_err = None

        try:
            r = requests.post(
                url,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                data=json.dumps(payload),
                timeout=self.timeout_sec,
            )
            if r.status_code == 404:
                last_err = f"{url} が見つかりません．"
                raise WikiWikiApiError(last_err)

            r.raise_for_status()
            data = r.json()
            if data.get("status") != "ok" or not data.get("token"):
                raise WikiWikiApiError(f"認証に失敗しました．response={data!r}")

            self.token = data["token"]
            return self.token

        except Exception as e:
            last_err = str(e)

        raise WikiWikiApiError(last_err or "不明なエラーです．")

    def list_attachments(self, page_name: str) -> List[AttachmentMeta]:
        page_name = (page_name or "").strip()
        if not page_name:
            raise ValueError("pagename が空です．")

        enc_page = self._enc_page(page_name)
        url = f"{self.base}/page/{enc_page}/attachments"
        r = requests.get(url, headers=self._headers(), timeout=self.timeout_sec)
        r.raise_for_status()
        data = r.json()

        attachments = data.get("attachments")
        if attachments is None:
            return []
        if isinstance(attachments, list):
            return []
        if not isinstance(attachments, dict):
            return []

        metas: List[AttachmentMeta] = []
        for fname, meta in attachments.items():
            if not isinstance(meta, dict):
                continue
            metas.append(
                AttachmentMeta(
                    file=fname,
                    type=str(meta.get("type") or ""),
                    size=int(meta.get("size") or 0),
                    size_str=str(meta.get("size_str") or ""),
                    time_str=str(meta.get("time_str") or ""),
                    md5hash=str(meta.get("md5hash") or ""),
                    freeze=bool(meta.get("freeze") or False),
                )
            )
        metas.sort(key=lambda x: x.file.lower())
        return metas

    def download_attachment_bytes(self, page_name: str, file_name: str, md5hash: Optional[str] = None) -> bytes:
        # direct=1 でバイナリとして取得
        page_name = (page_name or "").strip()
        file_name = (file_name or "").strip()
        if not page_name or not file_name:
            raise ValueError("page_name または file_name が空です．")

        enc_page = self._enc_page(page_name)
        enc_file = self._enc_file(file_name)

        params = {"direct": "1"}
        if md5hash:
            params["rev"] = md5hash

        url = f"{self.base}/page/{enc_page}/attachment/{enc_file}"
        r = requests.get(url, headers=self._headers(), params=params, timeout=self.timeout_sec)
        r.raise_for_status()
        return r.content

    def download_attachment_to_path(self, page_name: str, file_name: str, save_path: str, md5hash: Optional[str] = None) -> None:
        b = self.download_attachment_bytes(page_name, file_name, md5hash=md5hash)
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(b)

    def upload_attachment_from_file(self, page_name: str, file_path: str) -> Dict[str, Any]:
        """
        PUT /page/<page>/attachment
        body: {"filename": "...", "data": "<base64>"}
        """
        page_name = (page_name or "").strip()
        if not page_name:
            raise ValueError("pagename が空です．")
        if not os.path.isfile(file_path):
            raise ValueError(f"ファイルが見つかりません．{file_path}")

        enc_page = self._enc_page(page_name)

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            raw = f.read()

        b64 = base64.b64encode(raw).decode("ascii")
        payload = {"filename": filename, "data": b64}

        url = f"{self.base}/page/{enc_page}/attachment"
        r = requests.put(
            url,
            headers={**self._headers(), "Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=self.timeout_sec,
        )
        r.raise_for_status()
        return r.json()

    def delete_attachment(self, page_name: str, file_name: str) -> Dict[str, Any]:
        """
        DELETE /page/<page-name>/attachment/<file-name>
        """
        page_name = (page_name or "").strip()
        file_name = (file_name or "").strip()
        if not page_name or not file_name:
            raise ValueError("page_name または file_name が空です．")

        enc_page = self._enc_page(page_name)
        enc_file = self._enc_file(file_name)

        url = f"{self.base}/page/{enc_page}/attachment/{enc_file}"
        r = requests.delete(url, headers=self._headers(), timeout=self.timeout_sec)
        r.raise_for_status()
        return r.json()


# =============================
# GUI
# =============================

class ScrollableFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)

        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_inner_configure(self, _e):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, e):
        self.canvas.itemconfigure(self.inner_id, width=e.width)

    def _on_mousewheel(self, e):
        self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")


class AttachmentWindow(tk.Toplevel):
    def __init__(self, master, client: WikiWikiClient, page_name: str, default_dir: str):
        super().__init__(master)
        self.title("添付ファイル一覧")
        self.geometry("980x620")
        self.client = client
        self.page_name = page_name
        self.default_dir = default_dir

        self._thumb_refs: Dict[str, ImageTk.PhotoImage] = {}
        self._thumb_labels: Dict[str, tk.Label] = {}

        self._row_frames: Dict[str, ttk.Frame] = {}

        self._active_files: set[str] = set()

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(top, text="ページ名：").pack(side="left")
        ttk.Label(top, text=page_name).pack(side="left", padx=(0, 10))

        ttk.Label(top, text="保存先：").pack(side="left")
        self.var_save_dir = tk.StringVar(value=default_dir or "")
        ent = ttk.Entry(top, textvariable=self.var_save_dir, width=45)
        ent.pack(side="left", padx=(0, 6))
        ttk.Button(top, text="変更...", command=self._choose_save_dir).pack(side="left", padx=(0, 10))

        ttk.Button(top, text="一覧更新", command=self.refresh).pack(side="right")

        self.status = tk.StringVar(value="取得完了")
        ttk.Label(self, textvariable=self.status).pack(fill="x", padx=10, pady=(0, 6))

        footer = ttk.Frame(self)
        footer.pack(fill="x", padx=10, pady=(0, 8), side="bottom")

        self.var_no_refetch_after_delete = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            footer,
            text="削除後に自動更新しない",
            variable=self.var_no_refetch_after_delete,
        ).pack(side="left")

        self.sf = ScrollableFrame(self)
        self.sf.pack(fill="both", expand=True, padx=10, pady=10)

        self.refresh()

    def _choose_save_dir(self):
        d = filedialog.askdirectory(title="保存先フォルダを選択してください")
        if d:
            self.var_save_dir.set(d)

    def _clear_rows(self):
        for child in self.sf.inner.winfo_children():
            child.destroy()
        self._thumb_refs.clear()
        self._thumb_labels.clear()
        self._row_frames.clear()
        self._active_files.clear()

    def refresh(self):
        self._clear_rows()
        self.status.set("添付ファイル一覧を取得しています…")
        try:
            metas = self.client.list_attachments(self.page_name)
        except Exception as e:
            self.status.set("取得に失敗しました．")
            messagebox.showerror("エラー", f"添付ファイル一覧の取得に失敗しました．\n{e}")
            return

        if not metas:
            self.status.set("添付ファイルはありません．")
            return

        for i, meta in enumerate(metas):
            row = ttk.Frame(self.sf.inner)
            row.grid(row=i, column=0, sticky="ew", pady=4)
            row.columnconfigure(2, weight=1)

            self._row_frames[meta.file] = row
            self._active_files.add(meta.file)

            thumb = tk.Label(row, width=96, height=96, bd=1, relief="solid")
            thumb.grid(row=0, column=0, rowspan=2, padx=(0, 10))
            thumb.configure(text="画像\n取得中…", justify="center")
            self._thumb_labels[meta.file] = thumb

            ttk.Label(row, text=meta.file).grid(row=0, column=1, sticky="w")

            info = f"{meta.type or 'unknown'} / {meta.size_str or meta.size} / {meta.time_str or ''}"
            if meta.freeze:
                info += " / freeze=true"
            ttk.Label(row, text=info).grid(row=1, column=1, sticky="w")

            btns = ttk.Frame(row)
            btns.grid(row=0, column=3, rowspan=2, padx=(10, 0), sticky="e")

            ttk.Button(btns, text="ダウンロード",
                       command=lambda m=meta: self._download_one(m)).pack(side="top", fill="x")

            ttk.Button(btns, text="削除",
                       command=lambda m=meta: self._delete_one(m)).pack(side="top", fill="x", pady=(6, 0))

        self.status.set(f"{len(metas)} 件の添付ファイルを取得しました．サムネイルを作成しています…")
        t = threading.Thread(target=self._load_thumbnails_thread, args=(metas,), daemon=True)
        t.start()

    def _download_one(self, meta: AttachmentMeta):
        save_dir = (self.var_save_dir.get() or "").strip()
        path = filedialog.asksaveasfilename(
            title="保存先を選択してください",
            initialfile=meta.file,
            initialdir=save_dir or None,
            defaultextension="",
        )
        if not path:
            return
        try:
            self.status.set(f"{meta.file} をダウンロードしています…")
            self.client.download_attachment_to_path(self.page_name, meta.file, path, md5hash=meta.md5hash or None)
            self.status.set(f"{meta.file} を保存しました．")
            messagebox.showinfo("完了", f"保存しました．\n{path}")
        except Exception as e:
            self.status.set("ダウンロードに失敗しました．")
            messagebox.showerror("エラー", f"ダウンロードに失敗しました．\n{e}")

    def _remove_file_from_view(self, file_name: str):
        if file_name in self._active_files:
            self._active_files.remove(file_name)

        self._thumb_refs.pop(file_name, None)
        self._thumb_labels.pop(file_name, None)

        row = self._row_frames.pop(file_name, None)
        if row is not None:
            row.destroy()

        if not self._row_frames:
            self.status.set("添付ファイルはありません．")

    def _delete_one(self, meta: AttachmentMeta):
        warn = ""
        if meta.freeze:
            warn = "\n\nこのファイルは freeze=true です．削除が拒否される可能性があります．"
        ok = messagebox.askyesno(
            "確認",
            f"次の添付ファイルを削除しますか？\n\n{meta.file}{warn}",
        )
        if not ok:
            return

        try:
            self.status.set(f"{meta.file} を削除しています…")
            resp = self.client.delete_attachment(self.page_name, meta.file)
            if resp.get("status") == "ok":
                self.status.set(f"{meta.file} を削除しました．")
                messagebox.showinfo("完了", f"削除しました．\n{meta.file}")

                if self.var_no_refetch_after_delete.get():
                    self._remove_file_from_view(meta.file)
                else:
                    self.refresh()

            else:
                self.status.set("削除に失敗しました．")
                messagebox.showerror("エラー", f"削除に失敗しました．\nresponse={resp!r}")
        except Exception as e:
            self.status.set("削除に失敗しました．")
            messagebox.showerror("エラー", f"削除に失敗しました．\n{e}")

    def _load_thumbnails_thread(self, metas: List[AttachmentMeta]):
        for meta in metas:
            if meta.file not in self._active_files:
                continue

            is_image = (meta.type or "").startswith("image/")
            ext = os.path.splitext(meta.file.lower())[1]
            if not is_image and ext not in [".png", ".jpg", ".jpeg"]:
                self.after(0, self._set_non_image_placeholder, meta.file)
                continue

            try:
                b = self.client.download_attachment_bytes(self.page_name, meta.file, md5hash=meta.md5hash or None)
                img = Image.open(io.BytesIO(b))
                img.thumbnail((96, 96))
                photo = ImageTk.PhotoImage(img)
                self.after(0, self._apply_thumbnail, meta.file, photo)
            except Exception:
                self.after(0, self._set_thumbnail_failed, meta.file)

        self.after(0, lambda: self.status.set("サムネイルの準備ができました．"))

    def _apply_thumbnail(self, file_name: str, photo: ImageTk.PhotoImage):
        if file_name not in self._active_files:
            return
        self._thumb_refs[file_name] = photo
        lbl = self._thumb_labels.get(file_name)
        if lbl:
            lbl.configure(image=photo, text="")

    def _set_non_image_placeholder(self, file_name: str):
        if file_name not in self._active_files:
            return
        lbl = self._thumb_labels.get(file_name)
        if lbl:
            lbl.configure(text="（画像では\nありません）", image="", justify="center")

    def _set_thumbnail_failed(self, file_name: str):
        if file_name not in self._active_files:
            return
        lbl = self._thumb_labels.get(file_name)
        if lbl:
            lbl.configure(text="画像の\n取得に失敗\nしました", image="", justify="center")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WIKIWIKI用添付ファイル管理ツール")
        self.geometry("860x640")

        try:
            iconfile = "icon.ico"
            if getattr(sys, "frozen", False):
                iconfile = os.path.join(sys._MEIPASS, iconfile)
            if os.path.isfile(iconfile):
                self.iconbitmap(default=iconfile)
        except Exception:
            pass

        self.client: Optional[WikiWikiClient] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        grid = ttk.Frame(frm)
        grid.pack(fill="x")

        self.var_wiki_id = tk.StringVar()
        self.var_api_key_id = tk.StringVar()
        self.var_api_secret = tk.StringVar()
        self.var_page = tk.StringVar()
        self.var_dir = tk.StringVar()
        self.var_recursive = tk.BooleanVar(value=False)

        r = 0
        ttk.Label(grid, text="Wiki ID（wikiwiki ID）").grid(row=r, column=0, sticky="w")
        ttk.Entry(grid, textvariable=self.var_wiki_id, width=45).grid(row=r, column=1, sticky="we", padx=8)
        r += 1

        ttk.Label(grid, text="API Key").grid(row=r, column=0, sticky="w")
        ttk.Entry(grid, textvariable=self.var_api_key_id, width=45).grid(row=r, column=1, sticky="we", padx=8)
        r += 1

        ttk.Label(grid, text="API Secret").grid(row=r, column=0, sticky="w")
        ttk.Entry(grid, textvariable=self.var_api_secret, width=45, show="*").grid(row=r, column=1, sticky="we", padx=8)
        r += 1

        ttk.Label(grid, text="ページ名（pagename）").grid(row=r, column=0, sticky="w")
        ttk.Entry(grid, textvariable=self.var_page, width=45).grid(row=r, column=1, sticky="we", padx=8)
        r += 1

        ttk.Label(grid, text="ディレクトリ").grid(row=r, column=0, sticky="w")
        dir_row = ttk.Frame(grid)
        dir_row.grid(row=r, column=1, sticky="we", padx=8)
        dir_row.columnconfigure(0, weight=1)
        ttk.Entry(dir_row, textvariable=self.var_dir).grid(row=0, column=0, sticky="we")
        ttk.Button(dir_row, text="参照…", command=self._browse_dir).grid(row=0, column=1, padx=(6, 0))
        r += 1

        ttk.Checkbutton(grid, text="サブフォルダを含める", variable=self.var_recursive)\
            .grid(row=r, column=1, sticky="w", padx=8, pady=(4, 0))
        r += 1

        grid.columnconfigure(1, weight=1)

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(12, 8))

        ttk.Button(btns, text="認証", command=self.on_auth).pack(side="left")
        ttk.Button(btns, text="画像アップロード", command=self.on_upload_dir).pack(side="left", padx=8)
        ttk.Button(btns, text="添付ファイル取得", command=self.on_open_attachments).pack(side="left")

        prog = ttk.Frame(frm)
        prog.pack(fill="x", pady=(0, 8))
        self.var_status = tk.StringVar(value="準備できました．")
        ttk.Label(prog, textvariable=self.var_status).pack(side="left")
        self.pb = ttk.Progressbar(prog, length=240, mode="determinate")
        self.pb.pack(side="right")

        ttk.Label(frm, text="ログ").pack(anchor="w")
        self.txt = tk.Text(frm, height=18, wrap="word")
        self.txt.pack(fill="both", expand=True)
        self._log("必要情報を入力して「認証」を押してください．")

        # 起動時に認証情報があれば読み込む
        self._load_credentials_if_exists()

    def _log(self, s: str):
        ts = time.strftime("%H:%M:%S")
        self.txt.insert("end", f"[{ts}] {s}\n")
        self.txt.see("end")

    def _browse_dir(self):
        d = filedialog.askdirectory(title="アップロード対象のフォルダを選択してください")
        if d:
            self.var_dir.set(d)

    def _require_client(self) -> WikiWikiClient:
        if not self.client or not self.client.token:
            raise WikiWikiApiError("未認証です．先に認証してください．")
        return self.client

    def _load_credentials_if_exists(self):
        path = _get_credentials_path()
        if not os.path.isfile(path):
            self._log(f"保存済み認証情報は見つかりませんでした．({path})")
            return

        try:
            with open(path, "rb") as f:
                enc = f.read()
            raw = _dpapi_unprotect(enc)
            data = json.loads(raw.decode("utf-8"))

            wiki_id = str(data.get("wiki_id") or "")
            api_key_id = str(data.get("api_key_id") or "")
            secret = str(data.get("secret") or "")

            self.var_wiki_id.set(wiki_id)
            self.var_api_key_id.set(api_key_id)
            self.var_api_secret.set(secret)

            self._log(f"保存済みの認証情報を読み込みました．({path})")
        except Exception as e:
            self._log(f"保存済み認証情報の読み込みに失敗しました．({path}) {e}")

    def _save_credentials(self, wiki_id: str, api_key_id: str, secret: str):
        path = _get_credentials_path()
        payload = {
            "wiki_id": (wiki_id or "").strip(),
            "api_key_id": (api_key_id or "").strip(),
            "secret": (secret or "").strip(),
        }
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        enc = _dpapi_protect(raw)

        try:
            with open(path, "wb") as f:
                f.write(enc)
            self._log(f"認証情報を保存しました．({path})")
        except Exception as e:
            self._log(f"認証情報の保存に失敗しました．({path}) {e}")
            messagebox.showerror(
                "保存エラー",
                "認証情報の保存に失敗しました．\n"
                f"保存先：{path}\n"
                f"詳細：{e}",
            )

    def on_auth(self):
        wiki_id = (self.var_wiki_id.get() or "").strip()
        key_id = (self.var_api_key_id.get() or "").strip()
        secret = (self.var_api_secret.get() or "").strip()

        if not wiki_id:
            messagebox.showwarning("エラー", "Wiki ID を入力してください．")
            return

        try:
            self.client = WikiWikiClient(wiki_id=wiki_id)
            self.var_status.set("認証しています…")
            self._log("認証を開始します．")
            self.client.authenticate_with_api_key(key_id, secret)

            # 認証成功後に暗号化して保存する
            self._save_credentials(wiki_id, key_id, secret)

            self._log("認証できました．トークンを取得しました．")
            self.var_status.set("認証できました．")

        except Exception as e:
            prefix = "認証に失敗しました．"
            msg = str(e).strip()

            while msg.startswith(prefix):
                msg = msg[len(prefix):].lstrip()
            msg = prefix + (msg if msg else "")

            self._log(msg)
            self.var_status.set("認証に失敗しました．")
            messagebox.showerror("入力エラー", msg)

    def on_upload_dir(self):
        try:
            client = self._require_client()
        except Exception as e:
            messagebox.showwarning("未認証", str(e))
            return

        page = (self.var_page.get() or "").strip()
        d = (self.var_dir.get() or "").strip()
        recursive = bool(self.var_recursive.get())

        if not page:
            messagebox.showwarning("入力エラー", "ページ名（pagename）を入力してください．")
            return
        if not d or not os.path.isdir(d):
            messagebox.showwarning("入力エラー", "有効なディレクトリを指定してください．")
            return

        files: List[str] = []
        if recursive:
            for root, _dirs, fnames in os.walk(d):
                for fn in fnames:
                    files.append(os.path.join(root, fn))
        else:
            for fn in os.listdir(d):
                p = os.path.join(d, fn)
                if os.path.isfile(p):
                    files.append(p)

        if not files:
            messagebox.showinfo("情報", "アップロード対象ファイルが見つかりませんでした．")
            return

        t = threading.Thread(target=self._upload_thread, args=(client, page, files), daemon=True)
        t.start()

    def _upload_thread(self, client: WikiWikiClient, page: str, files: List[str]):
        self.after(0, lambda: self.pb.configure(maximum=len(files), value=0))
        self.after(0, lambda: self.var_status.set("アップロードしています…"))

        ok = 0
        ng = 0
        for i, fp in enumerate(files, start=1):
            name = os.path.basename(fp)
            self.after(0, lambda n=name, idx=i: self._log(f"{idx}/{len(files)} {n} をアップロードします…"))
            try:
                resp = client.upload_attachment_from_file(page, fp)
                if resp.get("status") == "ok":
                    ok += 1
                    self.after(0, lambda n=name: self._log(f"{n} をアップロードしました．"))
                else:
                    ng += 1
                    self.after(0, lambda n=name, rr=resp: self._log(f"{n} は失敗しました．response={rr!r}"))
            except Exception as e:
                ng += 1
                self.after(0, lambda n=name, ee=str(e): self._log(f"{n} は失敗しました．{ee}"))

            self.after(0, lambda v=i: self.pb.configure(value=v))

        self.after(0, lambda: self.var_status.set(f"完了しました．成功={ok} 失敗={ng}"))
        self.after(0, lambda: messagebox.showinfo("完了", f"アップロードが完了しました．\n成功={ok}\n失敗={ng}"))

    def on_open_attachments(self):
        try:
            client = self._require_client()
        except Exception as e:
            messagebox.showwarning("未認証", str(e))
            return

        page = (self.var_page.get() or "").strip()
        if not page:
            messagebox.showwarning("入力エラー", "ページ名（pagename）を入力してください．")
            return

        default_dir = (self.var_dir.get() or "").strip()
        AttachmentWindow(self, client=client, page_name=page, default_dir=default_dir)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
