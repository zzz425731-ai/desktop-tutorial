"""垃圾软件检查：找出电脑里常见的捆绑软件、弹窗软件，还有早就停止更新的老软件，
还能直接关掉烦人的开机自启、帮你卸载。

它会看两个地方：已经安装的软件，和开机自动启动的程序。
只在 Windows 上能用。运行方法：双击 junk_checker.py
"""

from __future__ import annotations

import ctypes
import itertools
import os
import re
import subprocess
import sys
import time
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
# 任务管理器和系统设置里的“开机启动”开关，就记在这里
APPROVED_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
UNINSTALL_POLL_MS = 1500  # 卸载开始后，每隔多久看一眼卸载完没有
UNINSTALL_WATCH_SECONDS = 15 * 60  # 最多盯这么久
DISCLAIMER = "只认识清单里的常见捆绑软件；没被标出来不代表一定安全，怀疑中毒请用杀毒软件全盘扫描。"
NO_ADMIN = "没有管理员权限：给所有用户设置的开机启动项改不了。关掉本工具重新打开，在授权窗口点“是”就行。"


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
    quiet_uninstall: str = ""  # 有的软件登记了“静默卸载”命令，用它就不用一路点下一步
    machine_wide: bool = False  # 装给所有用户的，卸载时要管理员权限
    registry_key: tuple = ()  # 登记在注册表的哪里，用来判断卸载完没有

    @cached_property
    def rule(self) -> Rule | None:
        return find_rule(self.name, self.publisher)


@dataclass
class StartupItem:
    name: str
    command: str
    source: str  # 登记在哪儿：注册表还是启动文件夹
    enabled: bool = True
    approval: tuple = ()  # 开关记在哪：(根键, StartupApproved 下面的子键, 值的名字)
    machine_wide: bool = False  # 给所有用户设置的，改开关要管理员权限

    @cached_property
    def rule(self) -> Rule | None:
        return find_rule(self.name, self.command)

    @cached_property
    def is_system(self) -> bool:
        """放在 Windows 文件夹里的，一般是系统或者驱动自带的（比如声卡、安全中心）。"""
        windows = os.environ.get("SystemRoot", r"C:\Windows").casefold().rstrip("\\") + "\\"
        return os.path.expandvars(split_command(self.command)[0]).casefold().startswith(windows)


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


def read_start(path: str, size: int = 4 * 1024 * 1024) -> bytes:
    """读卸载程序文件的开头，用来认出它是用什么工具做的。"""
    try:
        with open(os.path.expandvars(path), "rb") as file:
            return file.read(size)
    except OSError:
        return b""


def uninstall_command(program: Program, read=read_start) -> tuple[str, str, bool]:
    """返回 (程序, 参数, 是否静默)。能静默卸载就不弹窗口，省得一路点下一步、还要躲挽留按钮。"""
    if program.quiet_uninstall:
        return (*split_command(program.quiet_uninstall), True)
    exe, args = split_command(program.uninstall)
    guid = re.search(r"\{[0-9A-Fa-f-]{36}\}", args)
    if Path(exe).name.lower() == "msiexec.exe" and guid:
        # MSI 安装包：/x 是卸载，/qb 只显示进度条、不问问题
        return "msiexec.exe", f"/x {guid.group()} /qb /norestart", True
    start = read(exe)
    if b"Nullsoft.NSIS.exehead" in start:  # NSIS 做的卸载程序，国内软件最常见
        return exe, f"{args} /S".strip(), True
    if b"JR.Inno.Setup" in start:  # Inno Setup 做的卸载程序
        return exe, f"{args} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART".strip(), True
    return exe, args, False


def startup_enabled(data) -> bool:
    """开关的第一个字节是单数就表示被关掉了；没有记录就是开着。"""
    return not (isinstance(data, bytes) and data and data[0] % 2 == 1)


def approval_data(enabled: bool, now: float | None = None) -> bytes:
    """写进 StartupApproved 的 12 个字节，和任务管理器写的一样。"""
    if enabled:
        return bytes([2]) + bytes(11)
    # 关掉时还会记下是什么时候关的（Windows 的时间格式：从 1601 年起的 100 纳秒数）
    filetime = int(((time.time() if now is None else now) + 11_644_473_600) * 10_000_000)
    return bytes([3, 0, 0, 0]) + filetime.to_bytes(8, "little")


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


def program_from_values(values: dict, machine_wide: bool = False, registry_key: tuple = ()) -> Program | None:
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
        quiet_uninstall=str(values.get("QuietUninstallString") or "").strip(),
        machine_wide=machine_wide,
        registry_key=registry_key,
    )


def summarize(programs: list[Program], startup: list[StartupItem]) -> str:
    junk = sum(1 for program in programs if verdict(program) == JUNK)
    optional = sum(1 for program in programs if verdict(program) == OPTIONAL)
    found = [f"{junk} 个建议卸载"] if junk else []
    if optional:
        found.append(f"{optional} 个按需保留")
    first = f"发现 {'、'.join(found)}的软件" if found else "没发现清单里的垃圾软件"
    running = [item for item in startup if item.enabled]
    suspicious = sum(1 for item in running if item.rule)
    second = f"开机会自动打开 {len(running)} 个程序" + (f"（{suspicious} 个可疑）" if suspicious else "")
    return f"{first}；{second}"


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
    lines = [
        f"{item.name}（{'开机会自动打开' if item.enabled else '已关掉，开机不会自动打开'}）",
        f"来源：{item.source}",
        f"启动命令：{item.command}",
    ]
    if item.is_system:
        lines.append("这是 Windows 或驱动自带的（比如声卡、安全中心），一般建议保留。")
    return "\n".join(lines)


# ---- 读取和修改电脑里的设置（只在 Windows 上） ----


def registry_views() -> list:
    """(根键, 视图, 是否给所有用户, StartupApproved 里对应的子键)。
    64 位和 32 位程序登记在不同的地方，两边都要看。"""
    return [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, True, "Run"),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, True, "Run32"),
        (winreg.HKEY_CURRENT_USER, 0, False, "Run"),
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


def read_approvals(hive, subkey: str) -> dict:
    """读出某一类开机启动项的开关记录。"""
    view = winreg.KEY_WOW64_64KEY if hive == winreg.HKEY_LOCAL_MACHINE else 0
    try:
        with winreg.OpenKey(hive, f"{APPROVED_KEY}\\{subkey}", 0, winreg.KEY_READ | view) as key:
            return read_values(key)
    except OSError:
        return {}


def scan_programs() -> list[Program]:
    """已经安装的软件，和控制面板「程序和功能」看的是同一份登记。"""
    programs = []
    for hive, view, machine_wide, _ in registry_views():
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
                        values = read_values(key)
                except OSError:
                    continue
                program = program_from_values(values, machine_wide, (hive, view, name))
                if program:
                    programs.append(program)
    return unique(programs, key=lambda p: (p.name.casefold(), p.version, p.publisher.casefold()))


def scan_startup_items() -> list[StartupItem]:
    """开机自动启动的程序：注册表里的 Run，加上“启动”文件夹。"""
    items = []
    for hive, view, machine_wide, approved in registry_views():
        where = "所有用户" if machine_wide else "当前用户"
        switches = read_approvals(hive, approved)
        try:
            key = winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with key:
            for name, command in read_values(key).items():
                items.append(
                    StartupItem(
                        name,
                        str(command),
                        f"注册表（{where}）",
                        startup_enabled(switches.get(name)),
                        (hive, approved, name),
                        machine_wide,
                    )
                )
    startup = Path("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    folders = [
        ("APPDATA", "当前用户", winreg.HKEY_CURRENT_USER, False),
        ("PROGRAMDATA", "所有用户", winreg.HKEY_LOCAL_MACHINE, True),
    ]
    for variable, where, hive, machine_wide in folders:
        folder = Path(os.environ.get(variable, "")) / startup
        if not (os.environ.get(variable) and folder.is_dir()):
            continue
        switches = read_approvals(hive, "StartupFolder")
        for path in sorted(folder.iterdir()):
            if path.name.lower() != "desktop.ini":
                items.append(
                    StartupItem(
                        path.stem,
                        f'"{path}"',
                        f"启动文件夹（{where}）",
                        startup_enabled(switches.get(path.name)),
                        (hive, "StartupFolder", path.name),
                        machine_wide,
                    )
                )
    return unique(items, key=lambda item: (item.name, item.command))


def scan_computer() -> tuple[list[Program], list[StartupItem]]:
    return scan_programs(), scan_startup_items()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def shell_execute(verb: str, file: str, params: str) -> bool:
    """用 Windows 的方式打开一个程序；verb 是 runas 时会弹出管理员授权。"""
    shell32 = ctypes.WinDLL("shell32")
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    shell32.ShellExecuteW.argtypes = [ctypes.c_void_p] + [ctypes.c_wchar_p] * 4 + [ctypes.c_int]
    return (shell32.ShellExecuteW(None, verb, file, params or None, None, 1) or 0) > 32  # 大于 32 表示成功


def windowless_python() -> Path:
    """不带黑色命令行窗口的 Python（pythonw.exe），找不到就用当前这个。"""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return pythonw if pythonw.exists() else Path(sys.executable)


class WindowsSystem:
    """真正动手的部分：卸载、改开机启动开关、打开文件夹和系统设置。"""

    read_start = staticmethod(read_start)
    is_admin = staticmethod(is_admin)

    def run(self, exe: str, args: str, as_admin: bool) -> bool:
        return shell_execute("runas" if as_admin else "open", os.path.expandvars(exe), args)

    def is_installed(self, program: Program) -> bool:
        if not program.registry_key:
            return False
        hive, view, name = program.registry_key
        try:
            winreg.OpenKey(hive, f"{UNINSTALL_KEY}\\{name}", 0, winreg.KEY_READ | view).Close()
        except OSError:
            return False
        return True

    def set_startup_enabled(self, item: StartupItem, enabled: bool) -> None:
        """和任务管理器里点“禁用/启用”一样：只改开关，不删东西，随时能改回来。"""
        hive, subkey, name = item.approval
        view = winreg.KEY_WOW64_64KEY if hive == winreg.HKEY_LOCAL_MACHINE else 0
        with winreg.CreateKeyEx(hive, f"{APPROVED_KEY}\\{subkey}", 0, winreg.KEY_SET_VALUE | view) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_BINARY, approval_data(enabled))

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

    def __init__(
        self,
        notebook: ttk.Notebook,
        title: str,
        columns: list,
        describe,
        multiple: bool = False,
        only_flagged: bool = True,
    ) -> None:
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
        self.only_flagged = tk.BooleanVar(value=only_flagged)
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
        self.tree = ttk.Treeview(
            self.frame,
            columns=names,
            show="headings",
            selectmode="extended" if multiple else "browse",
            height=10,
        )
        for name, (heading, sample, _, stretch) in zip(names, columns):
            self.tree.heading(name, text=heading, anchor="w")
            self.tree.column(name, width=body_font.measure(sample) + 16, anchor="w", stretch=stretch)
        self.tree.tag_configure(JUNK, foreground=JUNK_COLOR)
        self.tree.tag_configure(OPTIONAL, foreground=OPTIONAL_COLOR)
        self.tree.tag_configure("off", foreground="gray")  # 后配置的优先：已关掉的一律灰色
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
                tags = [item.rule.level] if item.rule else []
                if getattr(item, "enabled", True) is False:
                    tags.append("off")
                self.tree.insert("", "end", iid=str(len(self.visible)), values=values, tags=tags)
                self.visible.append(item)
        if self.visible:
            self.tree.selection_set("0")
        self.show_details()

    def selected_items(self) -> list:
        return [self.visible[int(iid)] for iid in self.tree.selection()]

    def selected(self):
        items = self.selected_items()
        return items[0] if items else None

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
        self.system = system  # 真正动手的部分：卸载、改开机启动、打开文件夹和系统设置
        self._watching: list = []  # 正在卸载、等着它从列表里消失的软件
        self._default_status = DISCLAIMER if system.is_admin() else NO_ADMIN
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

        self.status = ttk.Label(frame, text=self._default_status, foreground="gray")
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
        # 开机启动项一般不多，默认全部列出来：不可疑但烦人的也能顺手关掉
        self.startup_tab = ResultTab(
            notebook,
            "开机启动项",
            [
                ("状态", "已关掉", lambda item: "开启" if item.enabled else "已关掉", False),
                ("判断", "建议卸载", verdict, False),
                ("名称", "中" * 10, lambda item: item.name, True),
                ("来源", "注册表（所有用户）", lambda item: item.source, False),
                ("启动命令", "中" * 14, lambda item: item.command, True),
            ],
            describe_startup,
            multiple=True,
            only_flagged=False,
        )
        for text, command in [
            ("卸载", self.uninstall_selected),
            ("打开安装位置", self.show_program_location),
            ("去系统设置卸载", lambda: self.system.open_settings("ms-settings:appsfeatures")),
        ]:
            ttk.Button(self.programs_tab.buttons, text=text, command=command).pack(side="left", padx=(0, 6))
        for text, command in [
            ("关掉开机启动", lambda: self.set_startup(self.startup_tab.selected_items(), False)),
            ("重新打开", lambda: self.set_startup(self.startup_tab.selected_items(), True)),
            ("关掉全部可疑的", self.turn_off_suspicious),
            ("打开所在位置", self.show_startup_location),
            ("去系统设置", lambda: self.system.open_settings("ms-settings:startupapps")),
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

    # ---- 卸载 ----

    def uninstall_selected(self) -> None:
        program = self.programs_tab.selected()
        if program is None:
            return
        if not (program.uninstall or program.quiet_uninstall):
            messagebox.showinfo(
                "没法直接卸载", "这个软件没有登记卸载程序，可以点「去系统设置卸载」试试。", parent=self.root
            )
            return
        exe, args, silent = uninstall_command(program, self.system.read_start)
        how = (
            "它支持静默卸载，会直接在后台卸掉，不用你点。"
            if silent
            else "会打开它自己的卸载窗口，按提示点下去就行。\n留意“再想想”“保留”之类的挽留按钮，别点错啦。"
        )
        if not messagebox.askyesno("卸载", f"要卸载「{program.name}」吗？\n\n{how}", parent=self.root):
            return
        if not self.system.run(exe, args, as_admin=program.machine_wide and not self.system.is_admin()):
            messagebox.showwarning(
                "没打开", "卸载程序没能打开（可能是取消了管理员授权）。也可以点「去系统设置卸载」。", parent=self.root
            )
            return
        self.status.configure(text=f"正在卸载「{program.name}」…卸载完会自动刷新列表。")
        self._watching.append((program, time.monotonic()))
        if len(self._watching) == 1:
            self.root.after(UNINSTALL_POLL_MS, self._check_uninstalled)

    def _check_uninstalled(self) -> None:
        """卸载程序在另一个进程里跑，这里定时看看软件从登记里消失了没有。"""
        now = time.monotonic()
        finished = [program for program, _ in self._watching if not self.system.is_installed(program)]
        self._watching = [
            (program, started)
            for program, started in self._watching
            if program not in finished and now - started < UNINSTALL_WATCH_SECONDS
        ]
        if finished:
            self.rescan()
            names = "、".join(f"「{program.name}」" for program in finished)
            self.status.configure(text=f"{names}已经卸载 ✓")
        if self._watching:
            self.root.after(UNINSTALL_POLL_MS, self._check_uninstalled)

    # ---- 开机启动 ----

    def set_startup(self, items: list, enabled: bool) -> None:
        items = [item for item in items if item.enabled != enabled]
        if not items:
            return
        system_items = [item.name for item in items if item.is_system]
        if not enabled and system_items:
            question = (
                f"{'、'.join(system_items)} 是 Windows 或驱动自带的，关掉可能影响声音、显卡、安全中心之类的功能。\n\n"
                "确定要关掉吗？（随时可以点「重新打开」改回来）"
            )
            if not messagebox.askyesno("确定吗？", question, parent=self.root):
                return
        denied = []
        for item in items:
            try:
                self.system.set_startup_enabled(item, enabled)
            except OSError:
                denied.append(item.name)
        self.rescan()
        changed = len(items) - len(denied)
        if changed:
            done = "关掉" if not enabled else "重新打开"
            later = "，下次开机它们就不会自己跳出来了" if not enabled else ""
            self.status.configure(text=f"已{done} {changed} 个开机启动项 ✓{later}")
        if denied:
            messagebox.showwarning(
                "需要管理员权限",
                f"{'、'.join(denied)} 是给所有用户设置的，要管理员权限才能改。\n\n"
                "关掉本工具再重新打开，在弹出的授权窗口里点“是”就行。",
                parent=self.root,
            )

    def turn_off_suspicious(self) -> None:
        items = [item for item in self.startup_tab.items if item.rule and item.enabled]
        if items:
            self.set_startup(items, False)
        else:
            self.status.configure(text="没有需要关掉的可疑开机启动项 ✓")

    # ---- 打开位置 ----

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
    script = str(Path(__file__).resolve())
    python = windowless_python()
    if not is_admin() and "--no-admin" not in sys.argv:
        # 先要一次管理员权限：之后关开机启动、卸载软件，都不用再一个个授权
        if shell_execute("runas", str(python), subprocess.list2cmdline([script])):
            return
        # 用户点了“否”，就用普通权限打开（给所有用户设置的开机启动项改不了）
    if python != Path(sys.executable):
        # 双击 .py 会多出一个黑色命令行窗口；换成 pythonw 重新启动，窗口就没了
        subprocess.Popen([str(python), script, "--no-admin"])
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
