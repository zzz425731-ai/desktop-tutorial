import sys
import time
import tkinter as tk
import unittest
from dataclasses import replace
from unittest import mock

import junk_checker
from junk_checker import (
    JUNK,
    OPTIONAL,
    UNINSTALL_POLL_MS,
    JunkCheckerApp,
    Program,
    StartupItem,
    WindowsSystem,
    approval_data,
    find_rule,
    format_date,
    format_size,
    program_from_values,
    scan_computer,
    split_command,
    startup_enabled,
    uninstall_command,
    unique,
)

if sys.platform == "win32":
    import winreg

PROGRAMS = [
    Program("微信", "腾讯科技(深圳)有限公司", "3.9", "20240301", 512000),
    Program(
        "2345看图王",
        "上海二三四五网络科技有限公司",
        "10.9",
        "20240115",
        36000,
        r"C:\Program Files (x86)\2345Soft\2345Pic",
        r'"C:\Program Files (x86)\2345Soft\2345Pic\uninst.exe"',
        machine_wide=True,
    ),
    Program("Google Chrome", "Google LLC", "128.0", "20240820", 900000, uninstall="chrome_uninstall.exe"),
    Program("360安全卫士", "360安全中心", "13.0", "20231105", 300000, uninstall=r"C:\360\uninst.exe"),
]
STARTUP = [
    StartupItem("百度网盘", r'"C:\Users\me\AppData\Roaming\baidu\BaiduNetdisk\baidunetdisk.exe" --autostart', "注册表（当前用户）"),
    StartupItem("2345PicHelper", r"C:\Program Files (x86)\2345Soft\2345Pic\helper.exe /start", "注册表（所有用户）", machine_wide=True),
    StartupItem("SecurityHealth", r"C:\Windows\System32\SecurityHealthSystray.exe", "注册表（所有用户）", machine_wide=True),
    StartupItem("OneDrive", r'"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', "注册表（当前用户）", enabled=False),
]


class RuleTest(unittest.TestCase):
    def test_known_junk_is_flagged(self):
        cases = {
            ("2345看图王", ""): "2345 全家桶",
            ("某某软件", "上海二三四五网络科技有限公司"): "2345 全家桶",
            ("鲁大师", ""): "鲁大师",
            ("KuaiZip", ""): "快压",
            ("Flash Helper Service", ""): "Flash 中心",
            ("Adobe Flash Player 32 PPAPI", "Adobe"): "Flash Player",
            ("Microsoft Silverlight", "Microsoft Corporation"): "Silverlight",
        }
        for (name, publisher), label in cases.items():
            with self.subTest(name=name):
                rule = find_rule(name, publisher)
                self.assertIsNotNone(rule)
                self.assertEqual((rule.level, rule.label), (JUNK, label))

    def test_security_suites_are_only_optional(self):
        for name in ["360安全卫士", "腾讯电脑管家", "金山毒霸"]:
            with self.subTest(name=name):
                self.assertEqual(find_rule(name, "").level, OPTIONAL)

    def test_normal_software_is_not_flagged(self):
        normal = [
            ("Google Chrome", "Google LLC"),
            ("WPS Office", "Kingsoft Corp."),
            ("微信", "腾讯科技(深圳)有限公司"),
            ("百度网盘", "北京度友科技有限公司"),
            ("Insta360 Studio", "Arashi Vision Inc."),
            ("Xbox 360 Controller", "Microsoft"),
            ("火绒安全软件", "北京火绒网络科技有限公司"),
            ("Microsoft 365 - zh-cn", "Microsoft Corporation"),
            ("NVIDIA 图形驱动程序", "NVIDIA Corporation"),
            ("联想电脑管家", "Lenovo"),
            ("7-Zip 23.01 (x64)", "Igor Pavlov"),
            ("Adobe Acrobat (64-bit)", "Adobe"),
        ]
        for name, publisher in normal:
            with self.subTest(name=name):
                self.assertIsNone(find_rule(name, publisher))

    def test_startup_command_path_is_checked_too(self):
        self.assertEqual(STARTUP[1].rule.label, "2345 全家桶")
        self.assertIsNone(STARTUP[0].rule)

    def test_windows_own_startup_items_are_recognised(self):
        self.assertTrue(STARTUP[2].is_system)
        self.assertFalse(STARTUP[1].is_system)


class HelperTest(unittest.TestCase):
    def test_split_command(self):
        cases = {
            r'"C:\Program Files (x86)\2345Soft\uninst.exe"': (r"C:\Program Files (x86)\2345Soft\uninst.exe", ""),
            r'"C:\Program Files\Foo\unins000.exe" /SILENT': (r"C:\Program Files\Foo\unins000.exe", "/SILENT"),
            "MsiExec.exe /X{12345678-ABCD}": ("MsiExec.exe", "/X{12345678-ABCD}"),
            r"C:\Program Files\Foo Bar\uninstall.exe --remove": (r"C:\Program Files\Foo Bar\uninstall.exe", "--remove"),
            "rundll32.exe dfshim.dll,ShArpMaintain app": ("rundll32.exe", "dfshim.dll,ShArpMaintain app"),
            "": ("", ""),
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(split_command(command), expected)

    def test_format_size_and_date(self):
        self.assertEqual(format_size(0), "")
        self.assertEqual(format_size(512), "512 KB")
        self.assertEqual(format_size(2048), "2.0 MB")
        self.assertEqual(format_size(3 * 1024 * 1024), "3.0 GB")
        self.assertEqual(format_date("20240115"), "2024-01-15")
        self.assertEqual(format_date("1/15/2024"), "1/15/2024")

    def test_program_from_registry_values(self):
        program = program_from_values(
            {
                "DisplayName": " 2345看图王 ",
                "Publisher": "上海二三四五网络科技有限公司",
                "DisplayVersion": "10.9",
                "InstallDate": "20240115",
                "EstimatedSize": 36000,
                "InstallLocation": r'"C:\2345Soft\2345Pic"',
                "UninstallString": r'"C:\2345Soft\2345Pic\uninst.exe"',
                "QuietUninstallString": r'"C:\2345Soft\2345Pic\uninst.exe" /S',
            },
            machine_wide=True,
        )
        self.assertEqual(program.name, "2345看图王")
        self.assertEqual(program.size_kb, 36000)
        self.assertEqual(program.location, r"C:\2345Soft\2345Pic")
        self.assertEqual(program.quiet_uninstall, r'"C:\2345Soft\2345Pic\uninst.exe" /S')
        self.assertTrue(program.machine_wide)
        self.assertEqual(program.rule.level, JUNK)

    def test_system_parts_and_updates_are_skipped(self):
        for values in [
            {},
            {"DisplayName": "Windows 驱动组件", "SystemComponent": 1},
            {"DisplayName": "Office 安全更新", "ParentKeyName": "Office16"},
            {"DisplayName": "KB5000001", "ReleaseType": "Update"},
        ]:
            with self.subTest(values=values):
                self.assertIsNone(program_from_values(values))

    def test_same_program_registered_twice_is_listed_once(self):
        programs = [Program("7-Zip", "Igor Pavlov", "23"), Program("7-zip", "igor pavlov", "23"), Program("7-Zip", "Igor Pavlov", "24")]
        result = unique(programs, key=lambda p: (p.name.casefold(), p.version, p.publisher.casefold()))
        self.assertEqual([p.version for p in result], ["23", "24"])

    def test_uninstall_runs_silently_when_it_can(self):
        def reader(content):
            return lambda path: content

        guid = "{12345678-1234-1234-1234-123456789ABC}"
        cases = [
            (Program("a", quiet_uninstall=r'"C:\a\uninst.exe" /quiet', uninstall="x"), b"", (r"C:\a\uninst.exe", "/quiet", True)),
            (Program("b", uninstall=f"MsiExec.exe /I{guid}"), b"", ("msiexec.exe", f"/x {guid} /qb /norestart", True)),
            (Program("c", uninstall=r'"C:\c\uninst.exe"'), b"..Nullsoft.NSIS.exehead..", (r"C:\c\uninst.exe", "/S", True)),
            (Program("d", uninstall=r'"C:\d\unins000.exe"'), b"..JR.Inno.Setup..",
             (r"C:\d\unins000.exe", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART", True)),
            (Program("e", uninstall=r'"C:\e\remove.exe" --all'), b"MZ other", (r"C:\e\remove.exe", "--all", False)),
        ]
        for program, content, expected in cases:
            with self.subTest(program=program.name):
                self.assertEqual(uninstall_command(program, reader(content)), expected)

    def test_startup_switch_matches_task_manager(self):
        self.assertTrue(startup_enabled(None))
        self.assertTrue(startup_enabled(bytes([2]) + bytes(11)))
        self.assertTrue(startup_enabled(bytes([6]) + bytes(11)))
        self.assertFalse(startup_enabled(bytes([3]) + bytes(11)))
        self.assertEqual(approval_data(True), bytes([2]) + bytes(11))
        off = approval_data(False, now=0)  # 1970-01-01 在 Windows 的时间格式里是 116444736000000000
        self.assertEqual(off, bytes([3, 0, 0, 0]) + (116444736000000000).to_bytes(8, "little"))
        self.assertFalse(startup_enabled(off))


class FakeSystem:
    """假装是 Windows：只记下程序想做什么，不会真的去卸载或改设置。"""

    def __init__(self, scans, admin=True):
        self.scans = scans  # 和 App 共用：改了开关、卸载了软件，下次扫描就能看到
        self.admin = admin
        self.runs = []
        self.shown = []
        self.settings = []

    def is_admin(self):
        return self.admin

    def read_start(self, path):
        return b"Nullsoft.NSIS.exehead" if "2345" in path else b""

    def run(self, exe, args, as_admin):
        self.runs.append((exe, args, as_admin))
        return True

    def is_installed(self, program):
        return program.name in [p.name for p in self.scans[-1][0]]

    def set_startup_enabled(self, item, enabled):
        if item.machine_wide and not self.admin:
            raise PermissionError("拒绝访问")
        programs, startup = self.scans[-1]
        changed = [replace(s, enabled=enabled) if s.name == item.name else s for s in startup]
        self.scans.append((programs, changed))

    def show(self, path):
        self.shown.append(path)
        return True

    def open_settings(self, page):
        self.settings.append(page)


def make_root(test):
    """建一个隐藏的 Tk 窗口给测试用，测试结束时自动关掉。"""
    try:
        root = tk.Tk()
    except tk.TclError:
        test.skipTest("没有图形界面，跳过界面测试")
    root.withdraw()
    test.addCleanup(root.destroy)

    def cancel_timers():
        for job in root.tk.splitlist(root.tk.call("after", "info")):
            root.after_cancel(job)

    test.addCleanup(cancel_timers)  # addCleanup 倒着执行：先取消定时任务，再关窗口
    return root


def names(tab):
    rows = tab.tree.get_children()
    assert len(rows) == len(tab.visible)
    return [item.name for item in tab.visible]


class AppTest(unittest.TestCase):
    def setUp(self):
        self.scans = [(PROGRAMS, STARTUP)]
        self.system = FakeSystem(self.scans)
        self.root = make_root(self)
        self.app = JunkCheckerApp(self.root, lambda: self.scans[-1], self.system)

    def details(self, tab):
        return tab.details.get("1.0", "end-1c")

    def test_summary_counts_what_was_found(self):
        self.assertEqual(
            self.app.summary.cget("text"), "发现 1 个建议卸载、1 个按需保留的软件；开机会自动打开 3 个程序（1 个可疑）"
        )

    def test_only_suspicious_programs_are_listed_by_default(self):
        self.assertEqual(names(self.app.programs_tab), ["2345看图王", "360安全卫士"])

    def test_unticking_shows_everything_with_suspicious_first(self):
        self.app.programs_tab.only_flagged.set(False)
        self.app.programs_tab.refresh()
        self.assertEqual(names(self.app.programs_tab), ["2345看图王", "360安全卫士", "Google Chrome", "微信"])

    def test_search(self):
        tab = self.app.programs_tab
        tab.only_flagged.set(False)
        tab.query.set("google")
        self.assertEqual(names(tab), ["Google Chrome"])
        tab.query.set("没有这个软件")
        self.assertEqual(names(tab), [])
        self.assertEqual(self.details(tab), "没有找到符合条件的。")

    def test_details_explain_why(self):
        text = self.details(self.app.programs_tab)
        self.assertIn("建议卸载 · 2345 全家桶", text)
        self.assertIn("会锁定浏览器主页", text)
        self.assertIn("发布者：上海二三四五网络科技有限公司", text)
        self.assertIn("版本 10.9  ·  安装于 2024-01-15  ·  35.2 MB", text)
        self.assertIn(r"安装位置：C:\Program Files (x86)\2345Soft\2345Pic", text)

    def test_uninstall_asks_first_and_runs_silently(self):
        with mock.patch("junk_checker.messagebox.askyesno", return_value=False):
            self.app.uninstall_selected()
        self.assertEqual(self.system.runs, [])
        with mock.patch("junk_checker.messagebox.askyesno", return_value=True) as ask:
            self.app.uninstall_selected()
        self.assertIn("静默卸载", ask.call_args[0][1])
        self.assertEqual(self.system.runs, [(r"C:\Program Files (x86)\2345Soft\2345Pic\uninst.exe", "/S", False)])
        self.assertIn("正在卸载「2345看图王」", self.app.status.cget("text"))

    def test_list_refreshes_by_itself_once_uninstalled(self):
        with mock.patch("junk_checker.messagebox.askyesno", return_value=True):
            self.app.uninstall_selected()
        self.app._check_uninstalled()
        self.assertEqual(names(self.app.programs_tab), ["2345看图王", "360安全卫士"])  # 还没卸完
        self.scans.append(([p for p in PROGRAMS if p.name != "2345看图王"], STARTUP))  # 卸载程序跑完了
        self.app._check_uninstalled()
        self.assertEqual(names(self.app.programs_tab), ["360安全卫士"])
        self.assertEqual(self.app.status.cget("text"), "「2345看图王」已经卸载 ✓")
        self.assertEqual(self.app._watching, [])

    def test_program_without_uninstaller_is_not_uninstalled(self):
        self.scans.append(([Program("鲁大师")], []))
        self.app.rescan()
        with mock.patch("junk_checker.messagebox.showinfo") as showinfo:
            self.app.uninstall_selected()
        showinfo.assert_called_once()
        self.assertEqual(self.system.runs, [])

    def test_open_locations(self):
        self.app.show_program_location()
        self.app.startup_tab.tree.selection_set("0")  # 2345PicHelper
        self.app.show_startup_location()
        self.assertEqual(
            self.system.shown,
            [r"C:\Program Files (x86)\2345Soft\2345Pic", r"C:\Program Files (x86)\2345Soft\2345Pic\helper.exe"],
        )

    def test_startup_tab_lists_everything_suspicious_first(self):
        self.assertEqual(names(self.app.startup_tab), ["2345PicHelper", "OneDrive", "SecurityHealth", "百度网盘"])
        row = self.app.startup_tab.tree.item("1")  # OneDrive 已经关掉了
        self.assertEqual(row["values"][0], "已关掉")
        self.assertIn("off", row["tags"])

    def test_turning_off_selected_startup_items(self):
        tab = self.app.startup_tab
        tab.tree.selection_set(("0", "3"))  # 2345PicHelper 和 百度网盘
        self.app.set_startup(tab.selected_items(), False)
        states = {item.name: item.enabled for item in tab.items}
        self.assertEqual(states, {"2345PicHelper": False, "OneDrive": False, "SecurityHealth": True, "百度网盘": False})
        self.assertIn("已关掉 2 个开机启动项", self.app.status.cget("text"))
        self.assertIn("开机会自动打开 1 个程序", self.app.summary.cget("text"))

    def test_turning_one_back_on(self):
        tab = self.app.startup_tab
        tab.tree.selection_set("1")  # OneDrive
        self.app.set_startup(tab.selected_items(), True)
        self.assertTrue(next(item for item in tab.items if item.name == "OneDrive").enabled)
        self.assertIn("已重新打开 1 个开机启动项", self.app.status.cget("text"))

    def test_turn_off_all_suspicious(self):
        self.app.turn_off_suspicious()
        states = {item.name: item.enabled for item in self.app.startup_tab.items}
        self.assertFalse(states["2345PicHelper"])
        self.assertTrue(states["百度网盘"])
        self.app.turn_off_suspicious()
        self.assertEqual(self.app.status.cget("text"), "没有需要关掉的可疑开机启动项 ✓")

    def test_windows_own_items_need_confirmation(self):
        tab = self.app.startup_tab
        tab.tree.selection_set("2")  # SecurityHealth
        with mock.patch("junk_checker.messagebox.askyesno", return_value=False) as ask:
            self.app.set_startup(tab.selected_items(), False)
        self.assertIn("Windows 或驱动自带", ask.call_args[0][1])
        self.assertTrue(next(item for item in tab.items if item.name == "SecurityHealth").enabled)

    def test_without_admin_all_user_items_cannot_be_changed(self):
        self.system.admin = False
        tab = self.app.startup_tab
        tab.tree.selection_set(("0", "3"))
        with mock.patch("junk_checker.messagebox.showwarning") as warn:
            self.app.set_startup(tab.selected_items(), False)
        self.assertIn("2345PicHelper", warn.call_args[0][1])
        states = {item.name: item.enabled for item in tab.items}
        self.assertTrue(states["2345PicHelper"])
        self.assertFalse(states["百度网盘"])

    def test_rescan_shows_the_new_result(self):
        self.scans.append(([p for p in PROGRAMS if "2345" not in p.name], [STARTUP[0]]))
        self.app.rescan()
        self.assertEqual(names(self.app.programs_tab), ["360安全卫士"])
        self.assertEqual(names(self.app.startup_tab), ["百度网盘"])

    def test_clean_computer(self):
        self.scans.append(([PROGRAMS[0], PROGRAMS[2]], [STARTUP[0]]))
        self.app.rescan()
        self.assertEqual(self.app.summary.cget("text"), "没发现清单里的垃圾软件；开机会自动打开 1 个程序")
        self.assertIn("没发现可疑的", self.details(self.app.programs_tab))


@unittest.skipUnless(sys.platform == "win32", "只在 Windows 上测")
class WindowsTest(unittest.TestCase):
    """真的去读写 Windows 注册表。测试用的登记都写在当前用户下面，测完就删掉。"""

    def add_uninstall_entry(self, key_name, **values):
        path = junk_checker.UNINSTALL_KEY + "\\" + key_name
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            for name, value in values.items():
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(key, name, 0, kind, value)

        def remove():
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass  # 已经被卸载测试删掉了

        self.addCleanup(remove)

    def add_run_entry(self, name, command):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, junk_checker.RUN_KEY) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)

        def remove():
            for subkey in (junk_checker.RUN_KEY, junk_checker.APPROVED_KEY + r"\Run"):
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, name)
                except OSError:
                    pass

        self.addCleanup(remove)

    def startup_items(self):
        return {item.name: item for item in junk_checker.scan_startup_items()}

    def test_finds_junk_registered_in_the_registry(self):
        self.add_uninstall_entry(
            "JunkCheckerTest",
            DisplayName="2345测试看图（测试用）",
            Publisher="上海二三四五网络科技有限公司",
            UninstallString=r'"C:\JunkCheckerTest\uninst.exe"',
        )
        self.add_uninstall_entry("JunkCheckerTestHidden", DisplayName="隐藏的系统组件（测试用）", SystemComponent=1)
        programs = {program.name: program for program in junk_checker.scan_programs()}
        self.assertEqual(programs["2345测试看图（测试用）"].rule.level, JUNK)
        self.assertFalse(programs["2345测试看图（测试用）"].machine_wide)
        self.assertNotIn("隐藏的系统组件（测试用）", programs)

    def test_startup_items_can_be_turned_off_and_on(self):
        self.add_run_entry("JunkCheckerTest", r'"C:\Program Files (x86)\2345Soft\t.exe" /auto')
        item = self.startup_items()["JunkCheckerTest"]
        self.assertEqual(item.rule.label, "2345 全家桶")
        self.assertTrue(item.enabled)

        WindowsSystem().set_startup_enabled(item, False)
        self.assertFalse(self.startup_items()["JunkCheckerTest"].enabled)
        WindowsSystem().set_startup_enabled(item, True)
        self.assertTrue(self.startup_items()["JunkCheckerTest"].enabled)

    def test_silent_uninstall_end_to_end(self):
        # “卸载命令”是删掉这条登记本身，就像真的卸载程序跑完了一样
        key_path = "HKCU\\" + junk_checker.UNINSTALL_KEY + "\\JunkCheckerUninstallTest"
        self.add_uninstall_entry(
            "JunkCheckerUninstallTest",
            DisplayName="2345卸载测试（测试用）",
            UninstallString=r'"C:\JunkCheckerTest\uninst.exe"',
            QuietUninstallString=f'reg.exe delete "{key_path}" /f',
        )
        root = make_root(self)
        app = JunkCheckerApp(root, scan_computer, WindowsSystem())
        app.programs_tab.query.set("2345卸载测试")
        self.assertEqual(names(app.programs_tab), ["2345卸载测试（测试用）"])
        with mock.patch("junk_checker.messagebox.askyesno", return_value=True):
            app.uninstall_selected()
        deadline = time.time() + 20
        while app._watching and time.time() < deadline:
            root.update()
            time.sleep(UNINSTALL_POLL_MS / 1000 / 5)
        self.assertEqual(app.status.cget("text"), "「2345卸载测试（测试用）」已经卸载 ✓")
        self.assertEqual(names(app.programs_tab), [])

    def test_app_shows_a_real_scan(self):
        programs, _ = scan_computer()
        self.assertGreater(len(programs), 0)
        self.assertTrue(all(program.name for program in programs))
        app = JunkCheckerApp(make_root(self), scan_computer, WindowsSystem())
        self.assertTrue(app.summary.cget("text"))


if __name__ == "__main__":
    unittest.main()
