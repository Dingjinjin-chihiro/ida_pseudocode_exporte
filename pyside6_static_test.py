from pathlib import Path
import ast
root = Path(__file__).resolve().parent
plugin = (root / "ida_pseudocode_exporter.py").read_text(encoding="utf-8")
core = (root / "ida_pseudocode_export_core.py").read_text(encoding="utf-8")
ast.parse(plugin)
ast.parse(core)
assert "PluginForm" in plugin
assert "QSplitter" in plugin
assert plugin.count("QScrollArea") >= 1
assert "CollapsibleCard" in plugin
assert "QListWidget" in plugin
assert "THEME_STYLES" in plugin
assert "完整路径最大长度" not in plugin
assert "文件名可读部分最大长度" not in plugin
assert "类目录单段最大长度" not in plugin
assert "路径长度无需手工设置" in plugin
assert "auto_path_shortening" in core
assert "get_auto_path_budget" in core
assert "get_compact_storage_root" in core
assert "resolve_function_root" in core
assert "ida_kernwin.Form(" not in plugin
assert "from PySide6 import QtCore, QtWidgets" in plugin
assert "PyQt5" not in plugin
assert "TWidgetToQtPythonWidget" in plugin
assert "ask_dir" not in plugin
assert "ask_directory" not in plugin
assert "导出全部函数名称" in plugin
assert "export_all_function_names" in core
assert "collect_all_function_name_records" in core
assert "ACTION_EXPORT_NAMES" in plugin
print("PySide6 dashboard static test: OK")
