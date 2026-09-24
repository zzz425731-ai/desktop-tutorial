"""垃圾软件检查：找出电脑里常见的捆绑软件、弹窗软件，还有早就停止更新的老软件。

它会看两个地方：已经安装的软件，和开机自动启动的程序。
只在 Windows 上能用。运行方法：python junk_checker.py
"""

from __future__ import annotations

import ctypes
import itertools
import os
import subprocess
import sys
import tkinter as tk
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from tkinter import font as tkfont
from tkinter import messagebox, ttk

if sys.platform == "win32":
    import winreg

JUNK = "建议卸载"
OPTIONAL = "按需保留"
JUNK_COLOR = "#c62828"
OPTIONAL_COLOR = "#b26a00"
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
DISCLAIMER = "只认识清单里的常见捆绑软件；没被标出来不代表一定安全，怀疑中毒请用杀毒软件全盘扫描。"


@dataclass(frozen=True)
class Rule:
    level: str  # JUNK 或 OPTIONAL
    label: str
    keywords: tuple  # 名称、发布者或启动命令里出现其中任何一个（不分大小写）就算
    reason: str


BUNDLED = "常被捆绑安装"
ONE_IS_ENOUGH = "电脑里留一个安全软件就够了，Windows 自带的 Microsoft Defender 已经够用"
DRIVERS = "驱动用 Windows 更新或电脑品牌官网的就行"

# 想加新的规则？照着格式往下加一行就行。越具体的规则要放得越靠前。
RULES = [
    # ---- 建议卸载：捆绑安装、弹广告、改主页，或者早就停止更新 ----
    Rule(JUNK, "Flash 中心", ("flash中心", "flashcenter", "flash helper", "flashhelper", "重庆重橙", "zhongcheng"),
         "国内版 Flash 附带的广告弹窗服务；Flash 早就停用了，可以放心卸载"),
    Rule(JUNK, "Flash Player", ("flash player",), "Adobe 已在 2020 年底停止支持 Flash，留着只有安全风险"),
    Rule(JUNK, "2345 全家桶", ("2345", "二三四五", "好压", "haozip"), f"{BUNDLED}，会锁定浏览器主页、弹广告"),
    Rule(JUNK, "鲁大师", ("鲁大师", "ludashi"), f"{BUNDLED}，弹窗广告多"),
    Rule(JUNK, "驱动精灵", ("驱动精灵", "drivergenius", "driver genius"), f"{BUNDLED}，还会顺带推荐装别的软件；{DRIVERS}"),
    Rule(JUNK, "驱动人生", ("驱动人生", "drivethelife"), f"{BUNDLED}，还会顺带推荐装别的软件；{DRIVERS}"),
    Rule(JUNK, "快压", ("快压", "kuaizip"), "被多家杀毒软件列为潜在有害程序，弹窗广告多；解压用 7-Zip 或 Windows 自带的功能就行"),
    Rule(JUNK, "hao123", ("hao123",), "常被用来锁定浏览器主页"),
    Rule(JUNK, "百度全家桶", ("百度卫士", "百度杀毒", "百度浏览器", "百度影音", "baidu antivirus", "baidu browser"),
         f"{BUNDLED}，而且早就停止更新了"),
    Rule(JUNK, "猎豹全家桶", ("猎豹浏览器", "猎豹清理", "猎豹免费wifi", "liebao", "猎豹移动", "cheetah mobile"), f"{BUNDLED}，弹窗广告多"),
    Rule(JUNK, "桌面弹窗软件", ("小鸟壁纸", "火萤"), f"{BUNDLED}，会在桌面上弹资讯和广告"),
    Rule(JUNK, "浏览器工具条", ("ask toolbar", "babylon toolbar", "conduit ltd", "search protect", "mindspark", "mywebsearch"),
         "会偷偷改掉浏览器的主页和默认搜索引擎"),
    Rule(JUNK, "流氓浏览器", ("wave browser", "wavesor", "onelaunch"), f"被 Microsoft Defender 等列为潜在有害程序，{BUNDLED}"),
    Rule(JUNK, "假杀毒 / 假优化", ("segurazo", "santivirus", "bytefence", "reimage repair", "restoro"),
         f"{BUNDLED}，会夸大电脑的问题、诱导付费"),
    Rule(JUNK, "Silverlight", ("silverlight",), "微软已在 2021 年停止支持，现在几乎没有网站在用"),
    Rule(JUNK, "QuickTime", ("quicktime",), "苹果早就不再更新 Windows 版，有没修复的安全漏洞"),
    # ---- 按需保留：本身没问题，但推广、弹窗比较多 ----
    Rule(OPTIONAL, "360 全家桶", ("360安全", "360杀毒", "360浏览器", "360极速浏览器", "360压缩", "360驱动", "360软件管家",
                                "360桌面", "360 total security", "奇虎", "qihoo", "360.cn"),
         f"弹窗和推广较多，还会互相推荐安装；{ONE_IS_ENOUGH}"),
    Rule(OPTIONAL, "腾讯电脑管家", ("腾讯电脑管家", "tencent pc manager"), f"弹窗和推广较多；{ONE_IS_ENOUGH}"),
    Rule(OPTIONAL, "金山毒霸", ("毒霸", "kingsoft antivirus"), f"弹窗和推广较多；{ONE_IS_ENOUGH}"),
    Rule(OPTIONAL, "McAfee WebAdvisor", ("webadvisor",), "经常在装别的软件（比如 Adobe Reader）时被顺带装上，不需要就可以卸载"),
]


def find_rule(*texts: str) -> Rule | None:
    """看看这些文字（名称、发布者、启动命令）有没有命中清单里的规则。"""
    text = "\n".join(texts).casefold()
    for rule in RULES:
        if any(keyword.casefold() in text for keyword in rule.keywords):
            return rule
    return None


@dataclass
class Program:
    name: str
    publisher: str = ""
    version: str = ""
    install_date: str = ""
    size_kb: int = 0
    location: str = ""
    uninstall: str = ""
    machine_wide: bool = False  # 装给所有用户的，卸载时要管理员权限

    @cached_property
    def rule(self) -> Rule | None:
        return find_rule(self.name, self.publisher)


@dataclass
class StartupItem:
    name: str
    command: str
    source: str  # 登记在哪儿：注册表还是启动文件夹

    @cached_property
    def rule(self) -> Rule | None:
        return find_rule(self.name, self.command)


def format_size(kb: int) -> str:
    if kb <= 0:
        return ""
    if kb < 1024:
        return f"{kb} KB"
    if kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    return f"{kb / 1024 / 1024:.1f} GB"


def format_date(raw: str) -> str:
    """注册表里的安装日期一般是 20240115 这样的格式。"""
    if len(raw) == 8 and raw.isdigit():
        return f"{raw[:4]}-{raw[4:6]}-{raw[6:]}"
    return raw


def split_command(command: str) -> tuple[str, str]:
    """把命令拆成“程序”和“参数”，比如 "C:\\x\\uninst.exe" /S → (C:\\x\\uninst.exe, /S)。"""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            return command[1:end], command[end + 1 :].strip()
    end = command.lower().find(".exe")
    if end >= 0:  # 没加引号的路径里可能有空格，就以第一个 .exe 为界
        end += len(".exe")
        return command[:end], command[end:].strip()
    program, _, args = command.partition(" ")
    return program, args.strip()


def verdict(item: Program | StartupItem) -> str:
    return item.rule.level if item.rule else ""


def sort_key(item: Program | StartupItem) -> tuple:
    """可疑的排在前面：建议卸载 → 按需保留 → 其他，同一类里按名字排。"""
    rank = {JUNK: 0, OPTIONAL: 1}[item.rule.level] if item.rule else 2
    return rank, item.name.casefold()


def unique(items: list, key) -> list:
    """去掉重复的（同一个软件可能在 64 位和 32 位两个地方都登记了）。"""
    seen = set()
    result = []
    for item in items:
        if key(item) not in seen:
            seen.add(key(item))
            result.append(item)
    return result


def program_from_values(values: dict, machine_wide: bool = False) -> Program | None:
    """把注册表里的一条卸载登记变成 Program；系统组件、更新补丁这些不算，返回 None。"""
    name = str(values.get("DisplayName") or "").strip()
    if (
        not name
        or values.get("SystemComponent") == 1
        or values.get("ParentKeyName")
        or values.get("ReleaseType") in ("Update", "Hotfix", "Security Update")
    ):
        return None
    size = values.get("EstimatedSize")
    return Program(
        name=name,
        publisher=str(values.get("Publisher") or "").strip(),
        version=str(values.get("DisplayVersion") or "").strip(),
        install_date=str(values.get("InstallDate") or "").strip(),
        size_kb=size if isinstance(size, int) else 0,
        location=str(values.get("InstallLocation") or "").strip().strip('"'),
        uninstall=str(values.get("UninstallString") or "").strip(),
        machine_wide=machine_wide,
    )


def summarize(programs: list[Program], startup: list[StartupItem]) -> str:
    junk = sum(1 for program in programs if verdict(program) == JUNK)
    optional = sum(1 for program in programs if verdict(program) == OPTIONAL)
    boot = sum(1 for item in startup if item.rule)
    if not (junk or optional or boot):
        return f"没发现清单里的垃圾软件，电脑挺干净的！（共 {len(programs)} 个软件）"
    parts = [f"{junk} 个建议卸载"] if junk else []
    if optional:
        parts.append(f"{optional} 个按需保留")
    if boot:
        parts.append(f"{boot} 个可疑的开机启动项")
    return f"发现 {'、'.join(parts)}（共 {len(programs)} 个软件）"


def describe_program(program: Program) -> str:
    facts = [
        f"版本 {program.version}" if program.version else "",
        f"安装于 {format_date(program.install_date)}" if program.install_date else "",
        format_size(program.size_kb),
    ]
    lines = [
        program.name,
        f"发布者：{program.publisher}" if program.publisher else "",
        "  ·  ".join(fact for fact in facts if fact),
        f"安装位置：{program.location}" if program.location else "",
    ]
    return "\n".join(line for line in lines if line)


def describe_startup(item: StartupItem) -> str:
    return f"{item.name}\n来源：{item.source}\n启动命令：{item.command}"


# ---- 读取电脑里的信息（只在 Windows 上） ----


def registry_views() -> list:
    """(根键, 视图, 是否装给所有用户)。64 位和 32 位程序登记在不同的地方，两边都要看。"""
    return [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, True),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, True),
        (winreg.HKEY_CURRENT_USER, 0, False),
    ]


def read_values(key) -> dict:
    """读出一个注册表项下面所有的值。"""
    values = {}
    for index in itertools.count():
        try:
            name, value, _ = winreg.EnumValue(key, index)
        except OSError:
            return values
        values[name] = value


def scan_programs() -> list[Program]:
    """已经安装的软件，和 Windows 设置里“已安装的应用”看的是同一份登记。"""
    programs = []
    for hive, view, machine_wide in registry_views():
        try:
            root = winreg.OpenKey(hive, UNINSTALL_KEY, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with root:
            for index in itertools.count():
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                try:
                    with winreg.OpenKey(root, name, 0, winreg.KEY_READ | view) as key:
                        program = program_from_values(read_values(key), machine_wide)
                except OSError:
                    continue
                if program:
                    programs.append(program)
    return unique(programs, key=lambda p: (p.name.casefold(), p.version, p.publisher.casefold()))


def scan_startup_items() -> list[StartupItem]:
    """开机自动启动的程序：注册表里的 Run，加上“启动”文件夹。"""
    items = []
    for hive, view, machine_wide in registry_views():
        where = "所有用户" if machine_wide else "当前用户"
        try:
            key = winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with key:
            for name, command in read_values(key).items():
                items.append(StartupItem(name, str(command), f"注册表（{where}）"))
    startup = Path("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    for variable, where in (("APPDATA", "当前用户"), ("PROGRAMDATA", "所有用户")):
        folder = Path(os.environ.get(variable, "")) / startup
        if os.environ.get(variable) and folder.is_dir():
            for path in sorted(folder.iterdir()):
                if path.name.lower() != "desktop.ini":
                    items.append(StartupItem(path.stem, f'"{path}"', f"启动文件夹（{where}）"))
    return unique(items, key=lambda item: (item.name, item.command))


def scan_computer() -> tuple[list[Program], list[StartupItem]]:
    return scan_programs(), scan_startup_items()


class WindowsSystem:
    """真正动手的部分：打开卸载程序、打开文件夹、打开系统设置。"""

    def uninstall(self, program: Program) -> bool:
        exe, args = split_command(program.uninstall)
        shell32 = ctypes.WinDLL("shell32")
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        shell32.ShellExecuteW.argtypes = [ctypes.c_void_p] + [ctypes.c_wchar_p] * 4 + [ctypes.c_int]
        # 装给所有用户的软件，卸载要管理员权限；用 runas 打开会弹出授权确认
        verb = "runas" if program.machine_wide else "open"
        result = shell32.ShellExecuteW(None, verb, os.path.expandvars(exe), args or None, None, 1)
        return (result or 0) > 32  # 大于 32 表示打开成功

    def show(self, path: str) -> bool:
        path = os.path.expandvars(path)
        if os.path.isfile(path):
            subprocess.Popen(f'explorer /select,"{path}"')
        elif os.path.isdir(path):
            os.startfile(path)
        else:
            return False
        return True

    def open_settings(self, page: str) -> None:
        os.startfile(page)


# ---- 界面 ----


class ResultTab:
    """一个标签页：搜索框、“只看可疑的”、列表和详情。"""

    def __init__(self, notebook: ttk.Notebook, title: str, columns: list, describe) -> None:
        self.notebook = notebook
        self.title = title
        self.columns = columns  # [(列名, 按这段示例文字定宽度, 取值函数, 窗口变宽时要不要跟着变宽), ...]
        self.describe = describe  # 选中一行时，详情区显示什么
        self.items: list = []
        self.visible: list = []

        self.frame = ttk.Frame(notebook, padding=10)
        notebook.add(self.frame, text=title)
        body_font = tkfont.nametofont("TkDefaultFont")

        bar = ttk.Frame(self.frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="搜索").pack(side="left")
        self.query = tk.StringVar()
        self.query.trace_add("write", lambda *_: self.refresh())
        ttk.Entry(bar, textvariable=self.query).pack(side="left", fill="x", expand=True, padx=8)
        self.only_flagged = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="只看可疑的", variable=self.only_flagged, command=self.refresh).pack(side="left")

        # 底部的按钮和详情先摆上，窗口变小时优先压缩列表
        self.buttons = ttk.Frame(self.frame)
        self.buttons.pack(side="bottom", fill="x", pady=(10, 0))
        self.details = tk.Text(
            self.frame,
            height=8,
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
        self.details.pack(side="bottom", fill="x", pady=(10, 0))
        self.details.tag_configure(JUNK, foreground=JUNK_COLOR)
        self.details.tag_configure(OPTIONAL, foreground=OPTIONAL_COLOR)
        self.details.tag_configure("hint", foreground="gray")

        names = [str(index) for index in range(len(columns))]
        self.tree = ttk.Treeview(self.frame, columns=names, show="headings", selectmode="browse", height=10)
        for name, (heading, sample, _, stretch) in zip(names, columns):
            self.tree.heading(name, text=heading, anchor="w")
            self.tree.column(name, width=body_font.measure(sample) + 16, anchor="w", stretch=stretch)
        self.tree.tag_configure(JUNK, foreground=JUNK_COLOR)
        self.tree.tag_configure(OPTIONAL, foreground=OPTIONAL_COLOR)
        scrollbar = ttk.Scrollbar(self.frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y", pady=(10, 0))
        self.tree.pack(fill="both", expand=True, pady=(10, 0))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_details())

    def set_items(self, items: list) -> None:
        self.items = sorted(items, key=sort_key)
        self.notebook.tab(self.frame, text=f"{self.title}（{len(self.items)}）")
        self.refresh()

    def refresh(self) -> None:
        words = self.query.get().casefold().split()
        self.tree.delete(*self.tree.get_children())
        self.visible = []
        for item in self.items:
            values = [value(item) for _, _, value, _ in self.columns]
            text = "\n".join(values).casefold()
            if (item.rule or not self.only_flagged.get()) and all(word in text for word in words):
                tags = (item.rule.level,) if item.rule else ()
                self.tree.insert("", "end", iid=str(len(self.visible)), values=values, tags=tags)
                self.visible.append(item)
        if self.visible:
            self.tree.selection_set("0")
        self.show_details()

    def selected(self):
        selection = self.tree.selection()
        return self.visible[int(selection[0])] if selection else None

    def show_details(self) -> None:
        item = self.selected()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if item is not None:
            if item.rule:
                self.details.insert("end", f"{item.rule.level} · {item.rule.label}\n", item.rule.level)
                self.details.insert("end", f"{item.rule.reason}\n\n")
            self.details.insert("end", self.describe(item))
        elif self.only_flagged.get() and not any(entry.rule for entry in self.items):
            self.details.insert("end", "这里没发现可疑的，挺干净！取消勾选「只看可疑的」可以看全部。", "hint")
        else:
            self.details.insert("end", "没有找到符合条件的。", "hint")
        self.details.configure(state="disabled")


class JunkCheckerApp:
    def __init__(self, root: tk.Tk, scan, system) -> None:
        self.root = root
        self.scan = scan  # 扫描函数：返回（已安装的软件, 开机启动项）
        self.system = system  # 真正动手的部分：卸载、打开文件夹、打开系统设置
        root.title("垃圾软件检查")

        style = ttk.Style(root)
        if style.theme_use() == "default" and "clam" in style.theme_names():
            style.theme_use("clam")  # Linux 上的默认主题太朴素了
        body_font = tkfont.nametofont("TkDefaultFont")
        # 尺寸都按字体来算，高分屏上才不会挤成一团
        style.configure("Treeview", rowheight=body_font.metrics("linespace") + 8)
        bold = body_font.copy()
        bold.configure(weight="bold")

        frame = ttk.Frame(root, padding=12)
        frame.pack(fill="both", expand=True)
        header = ttk.Frame(frame)
        header.pack(fill="x")
        self.summary = ttk.Label(header, font=bold)
        self.summary.pack(side="left")
        ttk.Button(header, text="重新扫描", command=self.rescan).pack(side="right")

        self.status = ttk.Label(frame, text=DISCLAIMER, foreground="gray")
        self.status.pack(side="bottom", fill="x", pady=(8, 0))

        notebook = ttk.Notebook(frame)
        notebook.pack(fill="both", expand=True, pady=(10, 0))
        self.programs_tab = ResultTab(
            notebook,
            "已安装的软件",
            [
                ("判断", "建议卸载", verdict, False),
                ("名称", "中" * 16, lambda program: program.name, True),
                ("发布者", "中" * 12, lambda program: program.publisher, True),
                ("安装日期", "2024-01-15", lambda program: format_date(program.install_date), False),
                ("大小", "999.9 MB", lambda program: format_size(program.size_kb), False),
            ],
            describe_program,
        )
        self.startup_tab = ResultTab(
            notebook,
            "开机启动项",
            [
                ("判断", "建议卸载", verdict, False),
                ("名称", "中" * 10, lambda item: item.name, True),
                ("来源", "注册表（所有用户）", lambda item: item.source, False),
                ("启动命令", "中" * 20, lambda item: item.command, True),
            ],
            describe_startup,
        )
        for text, command in [
            ("卸载…", self.uninstall_selected),
            ("打开安装位置", self.show_program_location),
            ("去系统设置卸载", lambda: self.system.open_settings("ms-settings:appsfeatures")),
        ]:
            ttk.Button(self.programs_tab.buttons, text=text, command=command).pack(side="left", padx=(0, 6))
        for text, command in [
            ("打开所在位置", self.show_startup_location),
            ("去系统设置关掉开机启动", lambda: self.system.open_settings("ms-settings:startupapps")),
        ]:
            ttk.Button(self.startup_tab.buttons, text=text, command=command).pack(side="left", padx=(0, 6))

        self.rescan()

    def rescan(self) -> None:
        self.summary.configure(text="正在扫描…")
        self.root.update_idletasks()
        programs, startup = self.scan()
        self.programs_tab.set_items(programs)
        self.startup_tab.set_items(startup)
        self.summary.configure(text=summarize(programs, startup))

    def uninstall_selected(self) -> None:
        program = self.programs_tab.selected()
        if program is None:
            return
        if not program.uninstall:
            messagebox.showinfo(
                "没法直接卸载", "这个软件没有登记卸载程序，可以点「去系统设置卸载」试试。", parent=self.root
            )
            return
        question = (
            f"要打开「{program.name}」自己的卸载程序吗？\n\n"
            "卸载时留意一下：有些软件会用“再想想”“保留”之类的按钮挽留你，别点错啦。"
        )
        if not messagebox.askyesno("卸载", question, parent=self.root):
            return
        if self.system.uninstall(program):
            self.status.configure(text=f"已经打开「{program.name}」的卸载程序，卸载完点「重新扫描」看看结果。")
        else:
            messagebox.showwarning(
                "没打开",
                "卸载程序没能打开（可能是取消了管理员授权）。也可以点「去系统设置卸载」。",
                parent=self.root,
            )

    def show_program_location(self) -> None:
        program = self.programs_tab.selected()
        if program is not None:
            self._show(program.location or split_command(program.uninstall)[0])

    def show_startup_location(self) -> None:
        item = self.startup_tab.selected()
        if item is not None:
            self._show(split_command(item.command)[0])

    def _show(self, path: str) -> None:
        if not (path and self.system.show(path)):
            messagebox.showinfo("找不到", "找不到这个位置，可能已经被删掉了。", parent=self.root)


def main() -> None:
    if sys.platform != "win32":
        print("这个小工具只能在 Windows 上用～")
        return
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    if python.name.lower() != "pythonw.exe" and pythonw.exists():
        # 双击 .py 会多出一个黑色命令行窗口；换成 pythonw 重新启动，窗口就没了
        subprocess.Popen([str(pythonw), str(Path(__file__).resolve())])
        return
    # 告诉 Windows 缩放由我们自己处理，高分屏上字才不会发虚
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    JunkCheckerApp(root, scan_computer, WindowsSystem())
    root.mainloop()


if __name__ == "__main__":
    main()
