"""剪贴板历史小工具：自动记下最近复制的 8 条文字，可以搜索，也能一键复制回去。

在 Windows 上它会一直在后台运行：开机自动启动，关掉窗口也照样记录；
在任何地方按 Ctrl+Shift+V 就能叫出来，选好后自动粘贴。

运行方法：python clipboard_history.py
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from tkinter import font as tkfont
from tkinter import messagebox, ttk

if sys.platform == "win32":
    import winreg
    from ctypes import wintypes

MAX_ITEMS = 8  # 最多保留几条，再多就把最旧的删掉
POLL_INTERVAL_MS = 500  # 每隔多久看一次剪贴板
HOTKEY_POLL_MS = 50  # 每隔多久看一次快捷键有没有被按下
PASTE_DELAY_MS = 150  # 切回原来的窗口后稍等一下再粘贴，给它时间拿到焦点
PREVIEW_LIMIT = 20_000  # 预览区最多显示的字数（复制回去时仍然是完整内容）
DATA_FILE = Path.home() / ".clipboard_history.json"
HOTKEY_NAME = "Ctrl+Shift+V"
TIP = "双击或回车：复制回剪贴板    Delete：删除    Esc：清空搜索"
TIP_BACKGROUND = f"{HOTKEY_NAME}：随时呼出    回车：用这条    Esc：收起"


@dataclass
class Entry:
    text: str
    copied_at: float = field(default_factory=time.time)


class ClipboardHistory:
    """最近复制过的内容，新的在前面，最多 max_items 条。"""

    def __init__(self, max_items: int = MAX_ITEMS, path: Path | None = None) -> None:
        self.max_items = max_items
        self.path = path
        self.items: list[Entry] = []
        self.settings: dict = {}  # 顺便记几个小设置，比如要不要开机自启

    def add(self, text: str) -> bool:
        """记下一条新复制的内容，返回列表有没有变化。

        已经存在的内容会挪到最前面，不会重复保存；超过上限时删掉最旧的。
        """
        if not text.strip() or (self.items and self.items[0].text == text):
            return False
        self.items = [entry for entry in self.items if entry.text != text]
        self.items.insert(0, Entry(text))
        del self.items[self.max_items :]
        return True

    def search(self, query: str) -> list[Entry]:
        """不区分大小写；多个关键词用空格隔开，要全部包含才算匹配。"""
        keywords = query.casefold().split()
        return [
            entry
            for entry in self.items
            if all(keyword in entry.text.casefold() for keyword in keywords)
        ]

    def remove(self, entry: Entry) -> None:
        self.items.remove(entry)

    def clear(self) -> None:
        self.items.clear()

    def load(self) -> None:
        """从文件读回历史；文件不存在或者坏掉了，就从空列表开始。"""
        if self.path is None:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            items = [Entry(str(item["text"]), float(item["copied_at"])) for item in data["items"]]
            settings = data.get("settings", {})
        except (OSError, ValueError, KeyError, TypeError):
            return
        self.items = items[: self.max_items]
        self.settings = settings if isinstance(settings, dict) else {}

    def save(self) -> None:
        """先写临时文件再替换，写到一半断电也不会把历史弄坏。"""
        if self.path is None:
            return
        tmp = self.path.with_name(self.path.name + ".tmp")
        data = {"items": [asdict(entry) for entry in self.items], "settings": self.settings}
        # 剪贴板里可能有密码之类的内容，文件只给自己读写
        with open(tmp, "w", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as file:
            json.dump(data, file, indent=2)
        os.replace(tmp, self.path)


def one_line(text: str, limit: int = 120) -> str:
    """列表里每条只占一行：换行和连续空白合并成一个空格。"""
    return " ".join(text[:limit].split())


def format_time(timestamp: float) -> str:
    moment = datetime.fromtimestamp(timestamp)
    if moment.date() == date.today():
        return moment.strftime("%H:%M:%S")
    return moment.strftime("%m-%d %H:%M")


def windowless_python() -> Path:
    """Windows 上不带黑色命令行窗口的 Python（pythonw.exe），找不到就用当前这个。"""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return pythonw if pythonw.exists() else Path(sys.executable)


class WindowsDesktop:
    """只在 Windows 上用：全局快捷键、切回原来的窗口自动粘贴、开机自启、只运行一份。"""

    MOD_CONTROL, MOD_SHIFT, MOD_NOREPEAT = 0x0002, 0x0004, 0x4000
    VK_CONTROL, VK_SHIFT, VK_V = 0x11, 0x10, 0x56
    WM_HOTKEY, KEYEVENTF_KEYUP, ERROR_ALREADY_EXISTS = 0x0312, 0x0002, 183
    RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    AUTOSTART_NAME = "ClipboardHistory"

    def __init__(self) -> None:
        self.hotkey_pressed = threading.Event()
        self.hotkey_ok = False
        self._mutex = None
        user32 = self.user32 = ctypes.WinDLL("user32")
        user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
        user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT
        ]
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.keybd_event.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, wintypes.DWORD, ctypes.c_size_t]

    def claim_single_instance(self) -> bool:
        """占住一个名字；已经有一份在运行时返回 False。"""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self._mutex = kernel32.CreateMutexW(None, False, "ClipboardHistory.SingleInstance")
        return ctypes.get_last_error() != self.ERROR_ALREADY_EXISTS

    def start_hotkey(self) -> None:
        registered = threading.Event()
        threading.Thread(target=self._listen, args=(registered,), daemon=True).start()
        registered.wait(2)

    def _listen(self, registered: threading.Event) -> None:
        # 快捷键在哪个线程注册，按下时的消息就发给哪个线程，所以注册和收消息都在这个后台线程里
        modifiers = self.MOD_CONTROL | self.MOD_SHIFT | self.MOD_NOREPEAT
        self.hotkey_ok = bool(self.user32.RegisterHotKey(None, 1, modifiers, self.VK_V))
        registered.set()
        if not self.hotkey_ok:
            return
        msg = wintypes.MSG()
        while self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            if msg.message == self.WM_HOTKEY:
                self.hotkey_pressed.set()

    def foreground(self) -> int:
        return self.user32.GetForegroundWindow() or 0

    def is_ours(self, hwnd: int) -> bool:
        """这个窗口是不是本程序的（主窗口、确认框都算）。"""
        pid = wintypes.DWORD()
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value == os.getpid()

    def activate(self, hwnd: int) -> None:
        self.user32.SetForegroundWindow(hwnd)

    def paste(self) -> None:
        """替用户按一下 Ctrl+V。"""
        self._press(self.VK_CONTROL, self.VK_V)

    def press_hotkey(self) -> None:
        """替用户按一下 Ctrl+Shift+V，用来叫出已经在运行的那一份。"""
        self._press(self.VK_CONTROL, self.VK_SHIFT, self.VK_V)

    def _press(self, *keys: int) -> None:
        for key in keys:
            self.user32.keybd_event(key, 0, 0, 0)
        for key in reversed(keys):
            self.user32.keybd_event(key, 0, self.KEYEVENTF_KEYUP, 0)

    @property
    def autostart(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY) as key:
                winreg.QueryValueEx(key, self.AUTOSTART_NAME)
        except OSError:
            return False
        return True

    def set_autostart(self, enabled: bool) -> None:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                # 开机时用 pythonw 在后台启动，不弹窗口
                command = f'"{windowless_python()}" "{Path(__file__).resolve()}" --hidden'
                winreg.SetValueEx(key, self.AUTOSTART_NAME, 0, winreg.REG_SZ, command)
            elif self.autostart:
                winreg.DeleteValue(key, self.AUTOSTART_NAME)


class ClipboardHistoryApp:
    def __init__(
        self, root: tk.Tk, history: ClipboardHistory, desktop: WindowsDesktop | None = None
    ) -> None:
        self.root = root
        self.history = history
        self.desktop = desktop  # 只有 Windows 上才有：快捷键、后台运行、开机自启
        self._visible: list[Entry] = []  # 列表里正在显示的记录（搜索过滤之后）
        self._status_job: str | None = None
        self._paste_target: int | None = None  # 按快捷键之前正在用的窗口，选好后粘贴回去
        self._picker_seen = False  # 呼出之后，窗口是不是已经到最前面了
        self._build_ui()
        self._bind_keys()
        # 打开之前就在剪贴板里的内容不算新复制的，免得删掉的记录重启后又冒出来
        self._last_seen = self._read_clipboard()
        self._refresh()
        self.search_box.focus_set()
        self.root.after(POLL_INTERVAL_MS, self._poll_clipboard)
        if desktop is not None:
            self._apply_autostart_setting()
            # 点 × 只是藏到后台：关掉窗口也照样记录，快捷键也照样能用
            root.protocol("WM_DELETE_WINDOW", self._on_close)
            self.root.after(HOTKEY_POLL_MS, self._poll_hotkey)

    @property
    def _tip(self) -> str:
        if self.desktop is None:
            return TIP
        if self.desktop.hotkey_ok:
            return TIP_BACKGROUND
        return f"{HOTKEY_NAME} 被别的程序占用了，快捷键暂时用不了"

    def _build_ui(self) -> None:
        root = self.root
        root.title("剪贴板历史")

        style = ttk.Style(root)
        if style.theme_use() == "default" and "clam" in style.theme_names():
            style.theme_use("clam")  # Linux 上的默认主题太朴素了
        body_font = tkfont.nametofont("TkDefaultFont")
        # 尺寸都按字体来算，高分屏上才不会挤成一团
        style.configure("Treeview", rowheight=body_font.metrics("linespace") + 8)

        frame = ttk.Frame(root, padding=12)
        frame.pack(fill="both", expand=True)

        # 底部的状态栏和按钮先摆上，窗口变小时优先压缩预览区
        self.status = ttk.Label(frame, text=self._tip, foreground="gray")
        self.status.pack(side="bottom", fill="x", pady=(8, 0))

        buttons = ttk.Frame(frame)
        buttons.pack(side="bottom", fill="x", pady=(10, 0))
        ttk.Button(buttons, text="复制", width=6, command=self.copy_selected).pack(side="left")
        ttk.Button(buttons, text="删除", width=6, command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(buttons, text="清空", width=6, command=self.clear_all).pack(side="left")
        if self.desktop is not None:
            ttk.Button(buttons, text="退出", width=6, command=root.destroy).pack(side="left", padx=6)
            self.autostart = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                buttons, text="开机自启", variable=self.autostart, command=self._toggle_autostart
            ).pack(side="right", padx=(10, 0))
        self.topmost = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            buttons,
            text="窗口置顶",
            variable=self.topmost,
            command=lambda: root.attributes("-topmost", self.topmost.get()),
        ).pack(side="right")

        search_bar = ttk.Frame(frame)
        search_bar.pack(fill="x")
        ttk.Label(search_bar, text="搜索").pack(side="left")
        self.query = tk.StringVar()
        self.query.trace_add("write", lambda *_: self._refresh())
        self.search_box = ttk.Entry(search_bar, textvariable=self.query)
        self.search_box.pack(side="left", fill="x", expand=True, padx=8)
        self.counter = ttk.Label(search_bar, foreground="gray")
        self.counter.pack(side="left")

        self.tree = ttk.Treeview(
            frame,
            columns=("time", "text"),
            show="headings",
            selectmode="browse",
            height=self.history.max_items,
        )
        self.tree.heading("time", text="时间")
        self.tree.heading("text", text="内容", anchor="w")
        self.tree.column(
            "time", width=body_font.measure("00-00 00:00") + 24, stretch=False, anchor="center"
        )
        self.tree.column("text", width=body_font.measure("0") * 30, stretch=True)
        self.tree.pack(fill="x", pady=(10, 0))

        ttk.Label(frame, text="完整内容").pack(anchor="w", pady=(12, 4))
        preview_box = ttk.Frame(frame)
        preview_box.pack(fill="both", expand=True)
        self.preview = tk.Text(
            preview_box,
            width=64,
            height=9,
            wrap="word",
            font="TkTextFont",
            padx=8,
            pady=6,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#c8c8c8",
            highlightcolor="#c8c8c8",
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(preview_box, command=self.preview.yview)
        self.preview.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.preview.pack(side="left", fill="both", expand=True)
        self.preview.tag_configure("match", background="#ffe066", foreground="black")
        self.preview.tag_configure("hint", foreground="gray")

    def _bind_keys(self) -> None:
        is_mac = self.root.tk.call("tk", "windowingsystem") == "aqua"
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_preview())
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Return>", lambda _e: self.copy_selected())
        self.tree.bind("<Delete>", lambda _e: self.delete_selected())
        if is_mac:
            self.tree.bind("<BackSpace>", lambda _e: self.delete_selected())  # Mac 键盘上的删除键
        # 在搜索框里就能用上下键挑选、回车复制，不用碰鼠标
        self.search_box.bind("<Return>", lambda _e: self.copy_selected())
        self.search_box.bind("<Down>", lambda _e: self._move_selection(1))
        self.search_box.bind("<Up>", lambda _e: self._move_selection(-1))
        # 点一下预览区让它拿到焦点，这样可以选中一部分文字再 Ctrl+C
        self.preview.bind("<Button-1>", lambda _e: self.preview.focus_set())
        self.root.bind("<Escape>", lambda _e: self._on_escape())
        self.root.bind("<Command-f>" if is_mac else "<Control-f>", lambda _e: self.search_box.focus_set())

    # ---- 剪贴板 ----

    def _read_clipboard(self) -> str | None:
        try:
            return self.root.clipboard_get()
        except tk.TclError:  # 剪贴板是空的，或者里面是图片、文件
            return None

    def _poll_clipboard(self) -> None:
        try:
            self.check_clipboard()
        finally:
            self.root.after(POLL_INTERVAL_MS, self._poll_clipboard)

    def check_clipboard(self) -> None:
        """看看剪贴板里有没有新内容，有就记下来。"""
        text = self._read_clipboard()
        if text is None or text == self._last_seen:
            return
        self._last_seen = text
        if self.history.add(text):
            self._save()
            self._refresh(select=text)

    # ---- 后台运行和快捷键（Windows） ----

    def _poll_hotkey(self) -> None:
        try:
            self.check_hotkey()
        finally:
            self.root.after(HOTKEY_POLL_MS, self._poll_hotkey)

    def check_hotkey(self) -> None:
        """处理快捷键；呼出后如果用户点去了别的窗口，就像 Win+V 一样自动收起。"""
        front = self.desktop.foreground()
        ours = self.desktop.is_ours(front)
        if self.desktop.hotkey_pressed.is_set():
            self.desktop.hotkey_pressed.clear()
            if ours and self.root.state() in ("normal", "zoomed"):
                self.hide()  # 窗口已经在最前面了，再按一次就收起
            else:
                self.summon(None if ours else front)
        elif self._paste_target is not None:
            if ours:
                self._picker_seen = True
            elif self._picker_seen:
                self._paste_target = None
                self.root.withdraw()

    def summon(self, target: int | None) -> None:
        """快捷键呼出：记住刚才在用的窗口，选好后自动粘贴回去。"""
        self._paste_target = target
        self._picker_seen = False
        self.query.set("")
        self.root.deiconify()
        self.root.update_idletasks()  # 开机后第一次呼出时窗口还没画出来，先画好再抢焦点
        self.root.lift()
        self.root.focus_force()
        self.search_box.focus_set()
        if self._visible:
            self.tree.selection_set("0")
            self.tree.see("0")

    def hide(self, paste: bool = False) -> None:
        """藏到后台继续记录，并把焦点还给呼出前的窗口；paste=True 时顺手按一下 Ctrl+V。"""
        target, self._paste_target = self._paste_target, None
        if target:
            self.desktop.activate(target)  # 先还焦点再藏窗口，Windows 才肯切过去
        self.root.withdraw()
        if target and paste:
            self.root.after(PASTE_DELAY_MS, self.desktop.paste)

    def _on_close(self) -> None:
        if not self.history.settings.get("close_hint_shown"):
            messagebox.showinfo(
                "还在后台运行哦",
                "关掉窗口后，剪贴板历史会在后台继续记录。\n\n"
                f"随时按 {HOTKEY_NAME} 就能把它叫出来；想彻底退出，点窗口里的「退出」。",
                parent=self.root,
            )
            self.history.settings["close_hint_shown"] = True
            self._save()
        self.hide()

    def _apply_autostart_setting(self) -> None:
        # 第一次运行默认开启：开机后自动在后台记录，不用每次手动打开
        if "autostart" not in self.history.settings:
            self.history.settings["autostart"] = True
            self._save()
        try:
            # 每次启动都按设置写一遍，程序文件夹挪了位置也能跟着更新
            self.desktop.set_autostart(self.history.settings["autostart"])
        except OSError:
            pass
        self.autostart.set(self.desktop.autostart)

    def _toggle_autostart(self) -> None:
        enabled = self.autostart.get()
        try:
            self.desktop.set_autostart(enabled)
        except OSError as error:
            self.autostart.set(not enabled)
            self._flash(f"设置失败：{error}")
            return
        self.history.settings["autostart"] = enabled
        self._save()
        self._flash("开机后会自动在后台运行 ✓" if enabled else "已取消开机自启")

    # ---- 按钮和快捷键 ----

    def copy_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(entry.text)
        self._last_seen = entry.text
        if self.history.add(entry.text):  # 用过的挪到最前面
            self._save()
        self._refresh(select=entry.text)
        self._flash("已复制到剪贴板 ✓")
        if self._paste_target is not None:
            self.hide(paste=True)

    def delete_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        self.history.remove(entry)
        self._save()
        self._refresh()
        self._flash("已删除 1 条记录")

    def clear_all(self) -> None:
        if not self.history.items:
            return
        if messagebox.askyesno("清空历史", "确定要清空全部记录吗？", parent=self.root):
            self.history.clear()
            self._save()
            self._refresh()
            self._flash("已清空")

    def _on_double_click(self, event: tk.Event) -> None:
        if self.tree.identify_region(event.x, event.y) == "cell":
            self.copy_selected()

    def _move_selection(self, step: int) -> str:
        if self._visible:
            index = (self._selected_index() or 0) + step
            index = max(0, min(index, len(self._visible) - 1))
            self.tree.selection_set(str(index))
            self.tree.see(str(index))
        return "break"

    def _on_escape(self) -> None:
        """Esc：搜索框有字就先清空；已经是空的，就把窗口收起来（Windows）。"""
        if not self.query.get() and self.desktop is not None:
            self.hide()
            return
        self.query.set("")
        self.search_box.focus_set()

    # ---- 界面刷新 ----

    def _selected_index(self) -> int | None:
        selection = self.tree.selection()
        return int(selection[0]) if selection else None

    def _selected_entry(self) -> Entry | None:
        index = self._selected_index()
        return None if index is None else self._visible[index]

    def _refresh(self, select: str | None = None) -> None:
        """按搜索词重建列表，尽量让原来选中的那条继续选中。"""
        old_index = self._selected_index()
        if select is None and old_index is not None:
            select = self._visible[old_index].text
        self._visible = self.history.search(self.query.get())

        self.tree.delete(*self.tree.get_children())
        for index, entry in enumerate(self._visible):
            values = (format_time(entry.copied_at), one_line(entry.text))
            self.tree.insert("", "end", iid=str(index), values=values)
        self.counter.configure(text=f"{len(self.history.items)} / {self.history.max_items}")

        if self._visible:
            texts = [entry.text for entry in self._visible]
            # 原来那条不见了（被删掉或被搜索过滤掉），就选同一个位置上的
            index = texts.index(select) if select in texts else min(old_index or 0, len(texts) - 1)
            self.tree.selection_set(str(index))
            self.tree.see(str(index))
        self._update_preview()

    def _update_preview(self) -> None:
        entry = self._selected_entry()
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        if entry is not None:
            self.preview.insert("1.0", entry.text[:PREVIEW_LIMIT])
            if len(entry.text) > PREVIEW_LIMIT:
                notice = f"\n\n…… 内容太长，只预览前 {PREVIEW_LIMIT} 个字，复制时是完整的"
                self.preview.insert("end", notice, "hint")
            self._highlight(self.query.get().split())
        elif self.history.items:
            self.preview.insert("1.0", f"没有找到包含「{self.query.get().strip()}」的记录", "hint")
        else:
            self.preview.insert("1.0", "还没有记录～去任何地方复制一段文字，它就会出现在这里。", "hint")
        self.preview.configure(state="disabled")

    def _highlight(self, keywords: list[str]) -> None:
        """把预览里的搜索关键词标成黄色。"""
        length = tk.IntVar()
        for keyword in keywords:
            start = "1.0"
            while True:
                start = self.preview.search(
                    keyword, start, stopindex="end", nocase=True, count=length
                )
                if not start or not length.get():
                    break
                end = f"{start}+{length.get()}c"
                self.preview.tag_add("match", start, end)
                start = end

    def _save(self) -> None:
        try:
            self.history.save()
        except OSError as error:
            self._flash(f"保存失败：{error}")

    def _flash(self, message: str) -> None:
        """在状态栏显示几秒提示，然后换回操作说明。"""
        self.status.configure(text=message)
        if self._status_job is not None:
            self.root.after_cancel(self._status_job)
        self._status_job = self.root.after(3000, lambda: self.status.configure(text=self._tip))


def main() -> None:
    desktop = None
    if sys.platform == "win32":
        python = windowless_python()
        if python != Path(sys.executable):
            # 双击 .py 会多出一个黑色命令行窗口，关掉它程序也跟着退出；换成 pythonw 重新启动
            subprocess.Popen([str(python), str(Path(__file__).resolve()), *sys.argv[1:]])
            return
        # 告诉 Windows 缩放由我们自己处理，高分屏上字才不会发虚
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
        desktop = WindowsDesktop()
        if not desktop.claim_single_instance():
            desktop.press_hotkey()  # 已经有一份在后台运行了，把它叫出来就行
            return
        desktop.start_hotkey()
    history = ClipboardHistory(path=DATA_FILE)
    history.load()
    root = tk.Tk()
    ClipboardHistoryApp(root, history, desktop)
    if "--hidden" in sys.argv[1:]:
        root.withdraw()  # 开机自启时不弹窗口，直接在后台待命
    root.mainloop()


if __name__ == "__main__":
    main()
