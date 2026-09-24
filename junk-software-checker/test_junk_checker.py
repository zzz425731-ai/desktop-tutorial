import sys
import tkinter as tk
import unittest
from unittest import mock

import junk_checker
from junk_checker import (
    JUNK,
    OPTIONAL,
    JunkCheckerApp,
    Program,
    StartupItem,
    find_rule,
    format_date,
    format_size,
    program_from_values,
    scan_computer,
    split_command,
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
    StartupItem("OneDrive", r'"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', "注册表（当前用户）"),
    StartupItem("2345PicHelper", r"C:\Program Files (x86)\2345Soft\2345Pic\helper.exe /start", "注册表（所有用户）"),
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
            },
            machine_wide=True,
        )
        self.assertEqual(program.name, "2345看图王")
        self.assertEqual(program.size_kb, 36000)
        self.assertEqual(program.location, r"C:\2345Soft\2345Pic")
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


class FakeSystem:
    """假装是 Windows：只记下程序想做什么，不会真的去卸载。"""

    def __init__(self):
        self.uninstalled = []
        self.shown = []
        self.settings = []

    def uninstall(self, program):
        self.uninstalled.append(program.name)
        return True

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
    return root


class AppTest(unittest.TestCase):
    def setUp(self):
        self.scans = [(PROGRAMS, STARTUP)]
        self.system = FakeSystem()
        self.app = JunkCheckerApp(make_root(self), lambda: self.scans[-1], self.system)

    def rows(self, tab):
        return [tab.tree.set(iid, "1") for iid in tab.tree.get_children()]  # 第 2 列是名称

    def details(self, tab):
        return tab.details.get("1.0", "end-1c")

    def test_summary_counts_what_was_found(self):
        self.assertEqual(
            self.app.summary.cget("text"), "发现 1 个建议卸载、1 个按需保留、1 个可疑的开机启动项（共 4 个软件）"
        )

    def test_only_suspicious_programs_are_listed_by_default(self):
        self.assertEqual(self.rows(self.app.programs_tab), ["2345看图王", "360安全卫士"])

    def test_unticking_shows_everything_with_suspicious_first(self):
        self.app.programs_tab.only_flagged.set(False)
        self.app.programs_tab.refresh()
        self.assertEqual(self.rows(self.app.programs_tab), ["2345看图王", "360安全卫士", "Google Chrome", "微信"])

    def test_search(self):
        tab = self.app.programs_tab
        tab.only_flagged.set(False)
        tab.query.set("google")
        self.assertEqual(self.rows(tab), ["Google Chrome"])
        tab.query.set("没有这个软件")
        self.assertEqual(self.rows(tab), [])
        self.assertEqual(self.details(tab), "没有找到符合条件的。")

    def test_details_explain_why(self):
        text = self.details(self.app.programs_tab)
        self.assertIn("建议卸载 · 2345 全家桶", text)
        self.assertIn("会锁定浏览器主页", text)
        self.assertIn("发布者：上海二三四五网络科技有限公司", text)
        self.assertIn("版本 10.9  ·  安装于 2024-01-15  ·  35.2 MB", text)
        self.assertIn(r"安装位置：C:\Program Files (x86)\2345Soft\2345Pic", text)

    def test_uninstall_asks_first(self):
        with mock.patch("junk_checker.messagebox.askyesno", return_value=False):
            self.app.uninstall_selected()
        self.assertEqual(self.system.uninstalled, [])
        with mock.patch("junk_checker.messagebox.askyesno", return_value=True):
            self.app.uninstall_selected()
        self.assertEqual(self.system.uninstalled, ["2345看图王"])

    def test_program_without_uninstaller_is_not_uninstalled(self):
        self.scans.append(([Program("鲁大师")], []))
        self.app.rescan()
        with mock.patch("junk_checker.messagebox.showinfo") as showinfo:
            self.app.uninstall_selected()
        showinfo.assert_called_once()
        self.assertEqual(self.system.uninstalled, [])

    def test_open_locations(self):
        self.app.show_program_location()
        self.app.show_startup_location()
        self.assertEqual(
            self.system.shown,
            [r"C:\Program Files (x86)\2345Soft\2345Pic", r"C:\Program Files (x86)\2345Soft\2345Pic\helper.exe"],
        )

    def test_startup_tab_lists_suspicious_startup_items(self):
        self.assertEqual(self.rows(self.app.startup_tab), ["2345PicHelper"])

    def test_rescan_shows_the_new_result(self):
        self.scans.append(([p for p in PROGRAMS if "2345" not in p.name], [STARTUP[0]]))
        self.app.rescan()
        self.assertEqual(self.rows(self.app.programs_tab), ["360安全卫士"])
        self.assertEqual(self.rows(self.app.startup_tab), [])
        self.assertIn("没发现可疑的", self.details(self.app.startup_tab))

    def test_clean_computer(self):
        self.scans.append(([PROGRAMS[0], PROGRAMS[2]], [STARTUP[0]]))
        self.app.rescan()
        self.assertEqual(self.app.summary.cget("text"), "没发现清单里的垃圾软件，电脑挺干净的！（共 2 个软件）")


@unittest.skipUnless(sys.platform == "win32", "只在 Windows 上测")
class WindowsScanTest(unittest.TestCase):
    """真的去读 Windows 注册表。测试用的登记都写在当前用户下面，测完就删掉。"""

    def add_uninstall_entry(self, key_name, **values):
        path = junk_checker.UNINSTALL_KEY + "\\" + key_name
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            for name, value in values.items():
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(key, name, 0, kind, value)
        self.addCleanup(winreg.DeleteKey, winreg.HKEY_CURRENT_USER, path)

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

    def test_finds_junk_in_startup(self):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, junk_checker.RUN_KEY) as key:
            winreg.SetValueEx(key, "JunkCheckerTest", 0, winreg.REG_SZ, r'"C:\Program Files (x86)\2345Soft\t.exe" /auto')

        def remove():
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, junk_checker.RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "JunkCheckerTest")

        self.addCleanup(remove)
        items = {item.name: item for item in junk_checker.scan_startup_items()}
        self.assertEqual(items["JunkCheckerTest"].rule.label, "2345 全家桶")

    def test_app_shows_a_real_scan(self):
        programs, _ = scan_computer()
        self.assertGreater(len(programs), 0)
        self.assertTrue(all(program.name for program in programs))
        app = JunkCheckerApp(make_root(self), scan_computer, FakeSystem())
        self.assertIn(f"共 {len(programs)} 个软件", app.summary.cget("text"))


if __name__ == "__main__":
    unittest.main()
