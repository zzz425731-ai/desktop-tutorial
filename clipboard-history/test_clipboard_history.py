import json
import tempfile
import tkinter as tk
import unittest
from pathlib import Path

from clipboard_history import MAX_ITEMS, ClipboardHistory, ClipboardHistoryApp


def texts(entries):
    return [entry.text for entry in entries]


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


class AppTest(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("没有图形界面，跳过界面测试")
        self.addCleanup(self.root.destroy)
        self.root.withdraw()
        # 上一个测试留在剪贴板里的内容会被当成“打开前就有的”而跳过，先清掉
        self.root.clipboard_clear()
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


if __name__ == "__main__":
    unittest.main()
