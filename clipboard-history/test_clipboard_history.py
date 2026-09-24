import json
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path

from clipboard_history import (
    HOTKEY_NAME,
    MAX_ITEMS,
    PASTE_DELAY_MS,
    ClipboardHistory,
    ClipboardHistoryApp,
    WindowsDesktop,
)

if sys.platform == "win32":
    import winreg


def texts(entries):
    return [entry.text for entry in entries]


class FakeDesktop:
    """假装是 Windows：只记下程序想做什么，不真的去按键盘、改注册表。"""

    OURS = -1  # 代表本程序自己的窗口

    def __init__(self):
        self.hotkey_pressed = threading.Event()
        self.hotkey_ok = True
        self.front = 100  # 当前最前面的窗口
        self.activated = []
        self.pastes = 0
        self.autostart = False

    def foreground(self):
        return self.front

    def is_ours(self, hwnd):
        return hwnd == self.OURS

    def activate(self, hwnd):
        self.activated.append(hwnd)

    def paste(self):
        self.pastes += 1

    def set_autostart(self, enabled):
        self.autostart = enabled


def make_root(test):
    """建一个隐藏的 Tk 窗口给测试用，测试结束时自动关掉。"""
    try:
        root = tk.Tk()
    except tk.TclError:
        test.skipTest("没有图形界面，跳过界面测试")
    root.withdraw()
    # 上一个测试留在剪贴板里的内容会被当成“打开前就有的”而跳过，先清掉
    root.clipboard_clear()
    test.addCleanup(root.destroy)

    def cancel_timers():
        # 先取消还没跑的定时任务，不然后面的测试刷新界面时，它们会在已关掉的窗口上报错
        for job in root.tk.splitlist(root.tk.call("after", "info")):
            root.after_cancel(job)

    test.addCleanup(cancel_timers)  # addCleanup 倒着执行：先取消定时任务，再关窗口
    return root


class ClipboardHistoryTest(unittest.TestCase):
    def test_newest_comes_first(self):
        history = ClipboardHistory()
        history.add("第一条")
        history.add("第二条")
        self.assertEqual(texts(history.items), ["第二条", "第一条"])

    def test_keeps_only_the_latest_eight(self):
        history = ClipboardHistory()
        for i in range(1, 11):
            history.add(f"第 {i} 次复制")
        self.assertEqual(MAX_ITEMS, 8)
        self.assertEqual(len(history.items), 8)
        self.assertEqual(history.items[0].text, "第 10 次复制")
        self.assertEqual(history.items[-1].text, "第 3 次复制")  # 第 1、2 次被自动删掉了

    def test_copying_again_moves_to_front_without_duplicate(self):
        history = ClipboardHistory()
        for text in ["a", "b", "c"]:
            history.add(text)
        self.assertTrue(history.add("a"))
        self.assertEqual(texts(history.items), ["a", "c", "b"])

    def test_same_as_newest_changes_nothing(self):
        history = ClipboardHistory()
        history.add("a")
        self.assertFalse(history.add("a"))
        self.assertEqual(texts(history.items), ["a"])

    def test_blank_text_is_ignored(self):
        history = ClipboardHistory()
        self.assertFalse(history.add(""))
        self.assertFalse(history.add("  \n\t"))
        self.assertEqual(history.items, [])

    def test_search_ignores_case(self):
        history = ClipboardHistory()
        history.add("Hello World")
        history.add("你好 GitHub")
        self.assertEqual(texts(history.search("hello")), ["Hello World"])
        self.assertEqual(texts(history.search("GITHUB")), ["你好 GitHub"])

    def test_search_needs_every_keyword(self):
        history = ClipboardHistory()
        history.add("git commit -m 修复登录")
        history.add("git push")
        self.assertEqual(texts(history.search("git 修复")), ["git commit -m 修复登录"])
        self.assertEqual(len(history.search("git")), 2)
        self.assertEqual(history.search("svn"), [])

    def test_empty_search_returns_everything(self):
        history = ClipboardHistory()
        history.add("a")
        history.add("b")
        self.assertEqual(history.search("   "), history.items)

    def test_remove_and_clear(self):
        history = ClipboardHistory()
        for text in ["a", "b", "c"]:
            history.add(text)
        history.remove(history.items[1])
        self.assertEqual(texts(history.items), ["c", "a"])
        history.clear()
        self.assertEqual(history.items, [])


class PersistenceTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "history.json"

    def test_save_then_load(self):
        history = ClipboardHistory(path=self.path)
        history.add("多行\n内容")
        history.add('特殊字符 {} [] "引号" \\ $HOME 😀')
        history.save()

        loaded = ClipboardHistory(path=self.path)
        loaded.load()
        self.assertEqual(loaded.items, history.items)

    def test_missing_file_starts_empty(self):
        history = ClipboardHistory(path=self.path)
        history.load()
        self.assertEqual(history.items, [])

    def test_broken_file_starts_empty(self):
        for content in ["不是 JSON", "[]", '{"items": [{"text": "缺了时间"}]}']:
            self.path.write_text(content, encoding="utf-8")
            history = ClipboardHistory(path=self.path)
            history.load()
            self.assertEqual(history.items, [], content)

    def test_load_keeps_at_most_eight(self):
        items = [{"text": f"item {i}", "copied_at": i} for i in range(20)]
        self.path.write_text(json.dumps({"items": items}), encoding="utf-8")
        history = ClipboardHistory(path=self.path)
        history.load()
        self.assertEqual(len(history.items), MAX_ITEMS)

    def test_settings_are_saved_with_the_history(self):
        history = ClipboardHistory(path=self.path)
        history.settings["autostart"] = False
        history.save()

        loaded = ClipboardHistory(path=self.path)
        loaded.load()
        self.assertEqual(loaded.settings, {"autostart": False})


class AppTest(unittest.TestCase):
    def setUp(self):
        self.root = make_root(self)
        self.app = ClipboardHistoryApp(self.root, ClipboardHistory())

    def copy(self, text):
        """模拟在别的程序里复制了一段文字。"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.app.check_clipboard()

    def rows(self):
        return [self.app.tree.set(iid, "text") for iid in self.app.tree.get_children()]

    def test_new_copy_shows_on_top(self):
        self.copy("hello")
        self.copy("world")
        self.assertEqual(self.rows(), ["world", "hello"])

    def test_list_never_goes_over_eight(self):
        for i in range(12):
            self.copy(f"item {i}")
        self.assertEqual(len(self.rows()), MAX_ITEMS)
        self.assertEqual(self.rows()[0], "item 11")

    def test_search_filters_the_list(self):
        for text in ["apple pie", "banana", "Apple juice"]:
            self.copy(text)
        self.app.query.set("apple")
        self.assertEqual(self.rows(), ["Apple juice", "apple pie"])
        self.app.query.set("")
        self.assertEqual(len(self.rows()), 3)

    def test_copy_back_puts_text_on_clipboard_and_moves_it_to_top(self):
        for text in ["one", "two", "three"]:
            self.copy(text)
        self.app.tree.selection_set("2")  # "one"
        self.app.copy_selected()
        self.assertEqual(self.root.clipboard_get(), "one")
        self.assertEqual(self.rows(), ["one", "three", "two"])

    def test_delete_selects_the_next_row(self):
        for text in ["one", "two", "three"]:
            self.copy(text)
        self.app.tree.selection_set("1")  # "two"
        self.app.delete_selected()
        self.assertEqual(self.rows(), ["three", "one"])
        self.assertEqual(self.app.tree.selection(), ("1",))

    def test_deleted_text_is_not_recorded_again_while_still_on_clipboard(self):
        self.copy("secret")
        self.app.delete_selected()
        self.app.check_clipboard()
        self.assertEqual(self.rows(), [])

    def test_special_characters_show_correctly(self):
        text = '路径 C:\\Users\\{name} "引号" $HOME [x] 😀'
        self.copy(text)
        self.assertEqual(self.rows(), [text])
        self.assertEqual(self.app.preview.get("1.0", "end-1c"), text)

    def test_multiline_text_is_one_row_but_full_in_preview(self):
        self.copy("第一行\n  第二行")
        self.assertEqual(self.rows(), ["第一行 第二行"])
        self.assertEqual(self.app.preview.get("1.0", "end-1c"), "第一行\n  第二行")

    def test_search_keywords_are_highlighted(self):
        self.copy("Git is great, I love git")
        self.app.query.set("git")
        ranges = self.app.preview.tag_ranges("match")
        self.assertEqual([str(index) for index in ranges], ["1.0", "1.3", "1.21", "1.24"])


class BackgroundModeTest(unittest.TestCase):
    """Windows 上的后台运行和快捷键，用 FakeDesktop 在任何系统上都能测。"""

    def setUp(self):
        self.root = make_root(self)
        self.desktop = FakeDesktop()
        self.history = ClipboardHistory()
        self.history.settings["close_hint_shown"] = True  # 别弹“还在后台运行”的提示框
        self.app = ClipboardHistoryApp(self.root, self.history, self.desktop)
        for text in ["one", "two", "three"]:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.app.check_clipboard()

    def press_hotkey(self):
        self.desktop.hotkey_pressed.set()
        self.app.check_hotkey()
        self.root.update()

    def test_first_run_turns_on_autostart(self):
        self.assertTrue(self.desktop.autostart)
        self.assertTrue(self.app.autostart.get())

    def test_turning_autostart_off_is_remembered(self):
        self.app.autostart.set(False)
        self.app._toggle_autostart()
        self.assertFalse(self.desktop.autostart)

        desktop = FakeDesktop()
        desktop.autostart = True
        ClipboardHistoryApp(make_root(self), self.history, desktop)  # 模拟下次启动
        self.assertFalse(desktop.autostart)

    def test_hotkey_shows_window_and_remembers_where_you_were(self):
        self.press_hotkey()
        self.assertEqual(self.root.state(), "normal")
        self.assertEqual(self.app._paste_target, 100)
        self.assertEqual(self.app.tree.selection(), ("0",))

    def test_choosing_an_item_pastes_into_the_previous_window(self):
        self.press_hotkey()
        self.app.tree.selection_set("1")  # "two"
        self.app.copy_selected()
        self.assertEqual(self.root.clipboard_get(), "two")
        self.assertEqual(self.desktop.activated, [100])
        self.assertEqual(self.root.state(), "withdrawn")
        time.sleep(PASTE_DELAY_MS / 1000 + 0.1)
        self.root.update()
        self.assertEqual(self.desktop.pastes, 1)

    def test_pressing_hotkey_again_hides_without_pasting(self):
        self.press_hotkey()
        self.desktop.front = FakeDesktop.OURS
        self.press_hotkey()
        self.assertEqual(self.root.state(), "withdrawn")
        self.assertEqual(self.desktop.activated, [100])
        self.assertEqual(self.desktop.pastes, 0)

    def test_escape_clears_search_first_then_hides(self):
        self.press_hotkey()
        self.app.query.set("tw")
        self.app._on_escape()
        self.assertEqual(self.app.query.get(), "")
        self.assertEqual(self.root.state(), "normal")
        self.app._on_escape()
        self.assertEqual(self.root.state(), "withdrawn")

    def test_clicking_another_window_hides_the_popup(self):
        self.press_hotkey()
        self.desktop.front = FakeDesktop.OURS
        self.app.check_hotkey()
        self.desktop.front = 200
        self.app.check_hotkey()
        self.assertEqual(self.root.state(), "withdrawn")
        self.assertIsNone(self.app._paste_target)

    def test_copy_without_hotkey_does_not_paste(self):
        self.root.deiconify()
        self.app.tree.selection_set("1")
        self.app.copy_selected()
        self.assertEqual(self.root.clipboard_get(), "two")
        self.assertEqual(self.desktop.activated, [])
        self.assertEqual(self.root.state(), "normal")

    def test_close_button_keeps_recording_in_background(self):
        self.root.deiconify()
        self.root.tk.call(self.root.protocol("WM_DELETE_WINDOW"))  # 点右上角的 ×
        self.assertEqual(self.root.state(), "withdrawn")
        self.root.clipboard_clear()
        self.root.clipboard_append("关着也能记")
        self.app.check_clipboard()
        self.assertEqual(self.history.items[0].text, "关着也能记")


@unittest.skipUnless(sys.platform == "win32", "只在 Windows 上测")
class WindowsDesktopTest(unittest.TestCase):
    """真的调用 Windows 接口：快捷键、开机自启、只运行一份、自动粘贴。"""

    def desktop(self):
        desktop = WindowsDesktop()
        desktop.AUTOSTART_NAME = "ClipboardHistoryTest"  # 别动真正的开机自启设置
        self.addCleanup(desktop.set_autostart, False)
        return desktop

    def test_hotkey_press_is_received(self):
        desktop = self.desktop()
        desktop.start_hotkey()
        if not desktop.hotkey_ok:
            self.skipTest(f"{HOTKEY_NAME} 被别的程序占用了")
        desktop.press_hotkey()
        self.assertTrue(desktop.hotkey_pressed.wait(3))

    def test_autostart_can_be_switched_on_and_off(self):
        desktop = self.desktop()
        desktop.set_autostart(True)
        self.assertTrue(desktop.autostart)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, desktop.RUN_KEY) as key:
            command = winreg.QueryValueEx(key, desktop.AUTOSTART_NAME)[0]
        self.assertIn("clipboard_history.py", command)
        self.assertTrue(command.endswith("--hidden"))
        desktop.set_autostart(False)
        self.assertFalse(desktop.autostart)

    def test_only_one_copy_runs_at_a_time(self):
        first = self.desktop()
        if not first.claim_single_instance():
            self.skipTest("剪贴板历史正在这台电脑上运行")
        self.assertFalse(self.desktop().claim_single_instance())

    def test_choosing_an_item_pastes_into_the_previous_window(self):
        root = make_root(self)
        history = ClipboardHistory()
        history.settings["close_hint_shown"] = True
        app = ClipboardHistoryApp(root, history, self.desktop())
        root.clipboard_append("粘贴测试")
        app.check_clipboard()

        # 另开一个带输入框的窗口，当作“刚才正在用的程序”
        target = tk.Toplevel(root)
        editor = tk.Text(target, width=30, height=3)
        editor.pack()
        target.update()
        target.focus_force()
        editor.focus_set()
        root.update()
        target_hwnd = int(target.wm_frame(), 16)
        if app.desktop.foreground() != target_hwnd:
            self.skipTest("这台机器上切换不了窗口焦点")

        app._paste_target = target_hwnd
        app.tree.selection_set("0")
        app.copy_selected()
        deadline = time.time() + 3
        while not editor.get("1.0", "end-1c") and time.time() < deadline:
            root.update()
            time.sleep(0.02)
        self.assertEqual(editor.get("1.0", "end-1c"), "粘贴测试")


if __name__ == "__main__":
    unittest.main()
