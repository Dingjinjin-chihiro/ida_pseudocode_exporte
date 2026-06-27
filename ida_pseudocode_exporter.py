# -*- coding: utf-8 -*-
"""
通用函数伪代码导出器 V3.5.0 IDA 9.3 / PySide6 中文版
=======================================

适用于 IDA Pro 9.3 / IDAPython / Hex-Rays Decompiler。

界面特性：
- IDA 9.3 / Qt6 / PySide6 PluginForm 单窗口。
- 双栏卡片式布局，可拖动、可缩放，左右区域分别滚动。
- 设置分组可折叠，底部操作区固定。
- 字符串筛选规则使用列表编辑器。
- 路径长度完全自动优化，不要求普通用户填写长度限制。
- 支持按批次、类名称和段名称分类输出。
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Dict, List

import ida_auto
import ida_diskio
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader

PLUGIN_DIR = Path(__file__).resolve().parent
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))

import ida_pseudocode_export_core as core

PLUGIN_NAME = "通用函数伪代码导出器"
PLUGIN_VERSION = "3.5.1-ida93-pyside6-zh"
BUNDLED_CONFIG_PATH = PLUGIN_DIR / "ida_pseudocode_exporter_config.json"
try:
    IDA_USER_DIR = Path(ida_diskio.get_user_idadir())
except Exception:
    IDA_USER_DIR = Path.home()
USER_CONFIG_PATH = IDA_USER_DIR / "ida_pseudocode_exporter_v3_5_0_ida93_config.json"

RULE_SECTIONS = (
    ("include_contains", "包含子字符串"),
    ("include_prefixes", "包含前缀"),
    ("include_exact_names", "包含精确名称"),
    ("include_globs", "包含通配符"),
    ("exclude_contains", "排除子字符串"),
    ("exclude_prefixes", "排除前缀"),
    ("exclude_exact_names", "排除精确名称"),
    ("exclude_globs", "排除通配符"),
    ("force_include_prefixes", "强制保留前缀"),
    ("include_segments", "仅包含段名称模式"),
    ("exclude_segments", "排除段名称模式"),
)

from PySide6 import QtCore, QtWidgets

ACTIVE_FORM = None
ACTIONS_REGISTERED = False
ACTION_SHOW_PANEL = "ida_pseudocode_exporter:show_panel"
ACTION_EXPORT_NAMES = "ida_pseudocode_exporter:export_all_function_names"


def log(message: str) -> None:
    core.default_logger(message)


def load_config() -> dict:
    cfg = dict(core.DEFAULT_CONFIG)
    try:
        cfg = core.deep_merge_config(cfg, core.load_json(BUNDLED_CONFIG_PATH))
    except Exception as exc:
        log(f"警告：读取插件默认配置失败：{exc}")
    try:
        cfg = core.deep_merge_config(cfg, core.load_json(USER_CONFIG_PATH))
    except Exception as exc:
        log(f"警告：读取用户配置失败：{exc}")
    return core.normalize_config(cfg)


def save_user_config(cfg: dict) -> None:
    USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    core.atomic_write_json(USER_CONFIG_PATH, core.normalize_config(cfg))
    log(f"已保存用户配置：{USER_CONFIG_PATH}")


def option_index(options, key: str) -> int:
    return next((index for index, (item_key, _) in enumerate(options) if item_key == key), 0)


def get_hexrays_plugin_candidates() -> List[str]:
    """
    根据当前处理器模块生成 Hex-Rays 插件候选名称。

    init_hexrays_plugin() 只检查反编译器是否已经存在且兼容，
    不负责加载对应架构的反编译器插件。因此需要在检查失败时
    使用 ida_loader.load_plugin() 尝试延迟加载。
    """
    try:
        processor = str(ida_idp.get_idp_name() or "").lower()
    except Exception:
        processor = ""

    try:
        is_64bit = bool(ida_ida.inf_is_64bit())
    except Exception:
        is_64bit = False

    candidates: List[str] = []

    # IBM PC / x86 / x64
    if any(token in processor for token in ("pc", "metapc", "x86", "386")):
        candidates.extend(["hexx64", "hexrays"] if is_64bit else ["hexrays", "hexx64"])

    # ARM / AArch64
    elif "arm" in processor:
        candidates.extend(["hexarm64", "hexarm"] if is_64bit else ["hexarm", "hexarm64"])

    # Other commonly installed Hex-Rays decompiler modules.
    elif "mips" in processor:
        candidates.append("hexmips")
    elif any(token in processor for token in ("ppc", "powerpc")):
        candidates.append("hexppc")
    elif "riscv" in processor:
        candidates.append("hexriscv")

    # Generic fallback order. Missing plugins are harmless: load_plugin()
    # simply returns no plugin object or raises, and diagnostics are logged.
    candidates.extend(
        [
            "hexx64",
            "hexrays",
            "hexarm64",
            "hexarm",
            "hexmips",
            "hexppc",
            "hexriscv",
        ]
    )

    deduplicated: List[str] = []
    for name in candidates:
        if name not in deduplicated:
            deduplicated.append(name)
    return deduplicated


def ensure_hexrays_available() -> tuple[bool, List[str]]:
    """
    Ensure that a compatible Hex-Rays decompiler plugin is available.

    Returns:
        (available, diagnostic_lines)
    """
    diagnostics: List[str] = []

    try:
        if ida_hexrays.init_hexrays_plugin():
            diagnostics.append("Hex-Rays 已经加载并且兼容当前数据库。")
            return True, diagnostics
    except Exception as exc:
        diagnostics.append(f"初始兼容性检查异常：{type(exc).__name__}: {exc}")

    try:
        processor = str(ida_idp.get_idp_name() or "<unknown>")
    except Exception:
        processor = "<unknown>"

    try:
        bitness = "64-bit" if ida_ida.inf_is_64bit() else "32-bit"
    except Exception:
        bitness = "<unknown-bitness>"

    diagnostics.append(f"当前处理器模块：{processor}，位数：{bitness}")
    diagnostics.append("Hex-Rays 尚未可用，开始尝试延迟加载架构对应插件。")

    for plugin_name in get_hexrays_plugin_candidates():
        try:
            plugin_object = ida_loader.load_plugin(plugin_name)
            if plugin_object is None:
                diagnostics.append(f"- {plugin_name}: 未找到、无法加载或不适用于当前安装。")
            else:
                diagnostics.append(f"- {plugin_name}: 已请求加载。")

            try:
                if ida_hexrays.init_hexrays_plugin():
                    diagnostics.append(f"Hex-Rays 自动加载成功：{plugin_name}")
                    return True, diagnostics
            except Exception as exc:
                diagnostics.append(
                    f"- {plugin_name}: 加载后兼容性检查异常：{type(exc).__name__}: {exc}"
                )
        except Exception as exc:
            diagnostics.append(f"- {plugin_name}: 加载异常：{type(exc).__name__}: {exc}")

    diagnostics.append(
        "自动加载失败。请在任意函数内手工按 F5："
        "如果 F5 也失败，通常是对应架构反编译器未安装、许可证不可用，"
        "或当前 IDA 安装缺少匹配的 Hex-Rays 插件。"
    )
    return False, diagnostics


THEME_OPTIONS = (
    ("soft_dark", "柔和深色（推荐）"),
    ("follow_ida", "跟随 IDA 主题"),
    ("soft_gray", "柔和灰色"),
)

COMMON_STYLE = """
QWidget { font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif; font-size: 12px; }
QLabel#PageTitle { font-size: 19px; font-weight: 600; }
QLabel#PageSubtitle, QLabel#MutedTip, QLabel#VersionLabel { padding-bottom: 4px; }
QFrame#Card { border-radius: 9px; }
QToolButton#CardHeader { border: none; padding: 11px 12px; text-align: left; font-weight: 600; }
QLineEdit, QComboBox, QSpinBox, QListWidget {
    min-height: 29px; padding: 4px 7px; border-radius: 6px;
}
QListWidget { padding: 6px; }
QPushButton { min-height: 30px; padding: 5px 13px; border-radius: 6px; }
QPushButton#PrimaryButton { font-weight: 600; }
QPushButton#DangerButton { font-weight: 500; }
QCheckBox { spacing: 7px; min-height: 23px; }
QScrollArea { border: none; background: transparent; }
QProgressBar { min-height: 17px; border-radius: 5px; text-align: center; }
QProgressBar::chunk { border-radius: 4px; }
QSplitter::handle { width: 6px; }
QFrame#ActionBar { border-radius: 9px; }
QLabel#InfoTip { border-radius: 6px; padding: 8px; }
QLabel#StatusLabel { padding: 3px 5px; }
"""

FOLLOW_IDA_STYLE = COMMON_STYLE + """
QWidget#RootPanel { background: palette(window); color: palette(window-text); }
QLabel#PageSubtitle, QLabel#MutedTip, QLabel#VersionLabel, QLabel#StatusLabel { color: palette(mid); }
QFrame#Card, QFrame#ActionBar { background: palette(alternate-base); border: 1px solid palette(midlight); }
QToolButton#CardHeader { color: palette(window-text); }
QToolButton#CardHeader:hover { background: palette(base); }
QLineEdit, QComboBox, QSpinBox, QListWidget {
    color: palette(text); background: palette(base); border: 1px solid palette(mid);
    selection-background-color: palette(highlight); selection-color: palette(highlighted-text);
}
QPushButton { color: palette(button-text); background: palette(button); border: 1px solid palette(mid); }
QPushButton:hover { background: palette(midlight); }
QPushButton#PrimaryButton { color: palette(highlighted-text); background: palette(highlight); border-color: palette(highlight); }
QPushButton#DangerButton { color: #c86f6f; }
QProgressBar { color: palette(text); background: palette(base); border: 1px solid palette(mid); }
QProgressBar::chunk { background: palette(highlight); }
QSplitter::handle { background: palette(midlight); }
QLabel#InfoTip { color: palette(text); background: palette(alternate-base); border: 1px solid palette(midlight); }
"""

SOFT_DARK_STYLE = COMMON_STYLE + """
QWidget#RootPanel { background: #20242b; color: #d7dde7; }
QLabel#PageTitle { color: #e1e6ee; }
QLabel#PageSubtitle, QLabel#MutedTip, QLabel#VersionLabel, QLabel#StatusLabel { color: #9aa7b5; }
QFrame#Card, QFrame#ActionBar { background: #2a3038; border: 1px solid #3d4652; }
QToolButton#CardHeader { color: #dce3ec; }
QToolButton#CardHeader:hover { background: #343b46; }
QLineEdit, QComboBox, QSpinBox, QListWidget {
    color: #d7dde7; background: #242a31; border: 1px solid #46515e;
    selection-background-color: #3f5f7f; selection-color: #f0f4f8;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QListWidget:focus { border: 1px solid #6f8fae; }
QPushButton { color: #d7dde7; background: #303741; border: 1px solid #4a5563; }
QPushButton:hover { background: #3a4450; }
QPushButton#PrimaryButton { color: #eef4fa; background: #426f9d; border-color: #527fae; }
QPushButton#PrimaryButton:hover { background: #4d7fad; }
QPushButton#DangerButton { color: #e0a0a0; }
QProgressBar { color: #cfd8e3; background: #252b32; border: 1px solid #46515e; }
QProgressBar::chunk { background: #527da8; }
QSplitter::handle { background: #3a424d; }
QLabel#InfoTip { color: #b8cede; background: #263846; border: 1px solid #365365; }
QScrollBar:vertical, QScrollBar:horizontal { background: #242a31; border: none; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background: #48535f; border-radius: 5px; min-height: 22px; min-width: 22px; }
QScrollBar::handle:hover { background: #5a6877; }
"""

SOFT_GRAY_STYLE = COMMON_STYLE + """
QWidget#RootPanel { background: #e5e7e9; color: #343a40; }
QLabel#PageTitle { color: #2e343b; }
QLabel#PageSubtitle, QLabel#MutedTip, QLabel#VersionLabel, QLabel#StatusLabel { color: #66717d; }
QFrame#Card, QFrame#ActionBar { background: #eff0f1; border: 1px solid #c5cbd1; }
QToolButton#CardHeader { color: #3b4650; }
QToolButton#CardHeader:hover { background: #e1e5e8; }
QLineEdit, QComboBox, QSpinBox, QListWidget {
    color: #343a40; background: #e7e9eb; border: 1px solid #b6bec6;
    selection-background-color: #718ca7; selection-color: #f6f8fa;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QListWidget:focus { border: 1px solid #718ca7; }
QPushButton { color: #3f4851; background: #e1e4e7; border: 1px solid #b9c1c8; }
QPushButton:hover { background: #d5dbe0; }
QPushButton#PrimaryButton { color: #f4f7f9; background: #607f9f; border-color: #607f9f; }
QPushButton#PrimaryButton:hover { background: #547391; }
QPushButton#DangerButton { color: #9b5555; }
QProgressBar { color: #46515a; background: #dde1e4; border: 1px solid #b9c1c8; }
QProgressBar::chunk { background: #6d8bab; }
QSplitter::handle { background: #c1c8ce; }
QLabel#InfoTip { color: #4e667a; background: #dce6ed; border: 1px solid #bdceda; }
"""

THEME_STYLES = {
    "follow_ida": FOLLOW_IDA_STYLE,
    "soft_dark": SOFT_DARK_STYLE,
    "soft_gray": SOFT_GRAY_STYLE,
}



class CollapsibleCard(QtWidgets.QFrame):
    """现代卡片式折叠区。"""
    def __init__(self, title: str, expanded: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.toggle = QtWidgets.QToolButton(text=title, checkable=True, checked=expanded)
        self.toggle.setObjectName("CardHeader")
        self.toggle.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggle.setArrowType(QtCore.Qt.ArrowType.DownArrow if expanded else QtCore.Qt.ArrowType.RightArrow)
        self.toggle.clicked.connect(self._on_toggled)
        self.content = QtWidgets.QWidget()
        self.content.setVisible(expanded)
        self.content_layout = QtWidgets.QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(16, 6, 16, 14)
        self.content_layout.setSpacing(10)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.toggle)
        layout.addWidget(self.content)

    def _on_toggled(self, checked: bool) -> None:
        self.toggle.setArrowType(QtCore.Qt.ArrowType.DownArrow if checked else QtCore.Qt.ArrowType.RightArrow)
        self.content.setVisible(checked)


class RuleListEditor(QtWidgets.QWidget):
    """字符串规则编辑器。"""
    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self._rules: Dict[str, List[str]] = {
            key: core.deduplicate_strings(cfg.get(key, [])) for key, _ in RULE_SECTIONS
        }
        self.category = QtWidgets.QComboBox()
        for key, label in RULE_SECTIONS:
            self.category.addItem(label, key)
        self.category.currentIndexChanged.connect(self._refresh)
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("搜索当前类别……")
        self.search.textChanged.connect(self._refresh)
        self.items = QtWidgets.QListWidget()
        self.items.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.items.itemDoubleClicked.connect(lambda _: self.edit_selected())
        self.entry = QtWidgets.QLineEdit()
        self.entry.setPlaceholderText("输入一个规则后按 Enter 或点击“添加”")
        self.entry.returnPressed.connect(self.add_entry)
        add_btn = QtWidgets.QPushButton("添加")
        edit_btn = QtWidgets.QPushButton("编辑")
        delete_btn = QtWidgets.QPushButton("删除")
        clear_btn = QtWidgets.QPushButton("清空")
        paste_btn = QtWidgets.QPushButton("批量粘贴")
        add_btn.clicked.connect(self.add_entry)
        edit_btn.clicked.connect(self.edit_selected)
        delete_btn.clicked.connect(self.delete_selected)
        clear_btn.clicked.connect(self.clear_current)
        paste_btn.clicked.connect(self.paste_many)
        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("规则类别"))
        top.addWidget(self.category, 1)
        top.addWidget(self.search, 1)
        buttons = QtWidgets.QHBoxLayout()
        buttons.setSpacing(6)
        for btn in (add_btn, edit_btn, delete_btn, clear_btn, paste_btn):
            buttons.addWidget(btn)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(7)
        layout.addLayout(top)
        layout.addWidget(self.items, 1)
        layout.addWidget(self.entry)
        layout.addLayout(buttons)
        self._replace_category_labels()
        self._refresh()

    def _current_key(self) -> str:
        return str(self.category.currentData())

    def _replace_category_labels(self) -> None:
        for index, (key, label) in enumerate(RULE_SECTIONS):
            self.category.setItemText(index, f"{label}（{len(self._rules.get(key, []))} 项）")

    def _refresh(self) -> None:
        key = self._current_key()
        query = self.search.text().strip().lower()
        self.items.clear()
        for value in self._rules.get(key, []):
            if not query or query in value.lower():
                self.items.addItem(value)

    def add_values(self, values: List[str]) -> None:
        key = self._current_key()
        self._rules[key] = core.deduplicate_strings([*self._rules.get(key, []), *values])
        self._replace_category_labels()
        self._refresh()

    def add_entry(self) -> None:
        value = self.entry.text().strip()
        if value:
            self.add_values([value])
            self.entry.clear()

    def edit_selected(self) -> None:
        selected = self.items.selectedItems()
        if len(selected) != 1:
            QtWidgets.QMessageBox.information(self, "编辑规则", "请选择一个规则后再编辑。")
            return
        old = selected[0].text()
        new, ok = QtWidgets.QInputDialog.getText(self, "编辑规则", "规则字符串：", text=old)
        new = str(new).strip()
        if ok and new:
            key = self._current_key()
            self._rules[key] = core.deduplicate_strings([new if item == old else item for item in self._rules.get(key, [])])
            self._replace_category_labels()
            self._refresh()

    def delete_selected(self) -> None:
        selected = {item.text() for item in self.items.selectedItems()}
        if selected:
            key = self._current_key()
            self._rules[key] = [value for value in self._rules.get(key, []) if value not in selected]
            self._replace_category_labels()
            self._refresh()

    def clear_current(self) -> None:
        if QtWidgets.QMessageBox.question(self, "清空规则", "确定清空当前类别中的全部规则吗？") == QtWidgets.QMessageBox.StandardButton.Yes:
            self._rules[self._current_key()] = []
            self._replace_category_labels()
            self._refresh()

    def paste_many(self) -> None:
        text, ok = QtWidgets.QInputDialog.getMultiLineText(
            self, "批量添加规则", "每行一个字符串，也可以使用分号分隔。模板函数名称中的逗号不会被拆分。", ""
        )
        if ok:
            values = [item.strip() for item in str(text).replace(";", "\n").splitlines() if item.strip()]
            self.add_values(values)

    def get_rules(self) -> Dict[str, List[str]]:
        return {key: core.deduplicate_strings(values) for key, values in self._rules.items()}


class ExporterPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("RootPanel")
        self.cfg = load_config()
        self.cancel_requested = False
        self._build_ui()
        self._load_to_widgets(self.cfg)
        self._apply_theme(str(self.cfg.get("ui_theme") or "soft_dark"))

    def sizeHint(self):
        return QtCore.QSize(1260, 820)

    def minimumSizeHint(self):
        return QtCore.QSize(900, 620)

    def _apply_theme(self, theme_key: str) -> None:
        theme_key = theme_key if theme_key in THEME_STYLES else "soft_dark"
        self.setStyleSheet(THEME_STYLES[theme_key])

    def _on_theme_changed(self) -> None:
        if hasattr(self, "ui_theme"):
            self._apply_theme(str(self.ui_theme.currentData() or "soft_dark"))

    def _build_ui(self) -> None:
        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(12)

        header = QtWidgets.QHBoxLayout()
        title_box = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(PLUGIN_NAME)
        title.setObjectName("PageTitle")
        subtitle = QtWidgets.QLabel("Hex-Rays 函数伪代码批量导出 · 自动路径优化 · 类目录与批次目录分类")
        subtitle.setObjectName("PageSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch(1)
        version = QtWidgets.QLabel(f"V{PLUGIN_VERSION}")
        version.setObjectName("VersionLabel")
        header.addWidget(QtWidgets.QLabel("界面主题"))
        self.ui_theme = QtWidgets.QComboBox()
        for key, label in THEME_OPTIONS:
            self.ui_theme.addItem(label, key)
        self.ui_theme.setMinimumWidth(150)
        self.ui_theme.currentIndexChanged.connect(self._on_theme_changed)
        header.addWidget(self.ui_theme)
        header.addWidget(version)
        outer.addLayout(header)

        self.splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.left_layout = self._make_scroll_column()
        self.right_layout = self._make_scroll_column()
        self.splitter.addWidget(self.left_scroll)
        self.splitter.addWidget(self.right_scroll)
        self.splitter.setStretchFactor(0, 55)
        self.splitter.setStretchFactor(1, 45)
        self.splitter.setSizes([680, 580])
        outer.addWidget(self.splitter, 1)

        self._build_task_card()
        self._build_rules_card()
        self.left_layout.addStretch(1)
        self._build_output_card()
        self._build_filter_card()
        self._build_stability_card()
        self._build_expert_card()
        self.right_layout.addStretch(1)

        action_frame = QtWidgets.QFrame()
        action_frame.setObjectName("ActionBar")
        action = QtWidgets.QHBoxLayout(action_frame)
        action.setContentsMargins(10, 7, 10, 7)
        self.save_defaults = QtWidgets.QCheckBox("保存为用户默认配置")
        self.save_defaults.setChecked(True)
        self.export_names_btn = QtWidgets.QPushButton("导出全部函数名称")
        self.preview_btn = QtWidgets.QPushButton("仅预演")
        self.export_btn = QtWidgets.QPushButton("开始导出")
        self.export_btn.setObjectName("PrimaryButton")
        self.cancel_btn = QtWidgets.QPushButton("取消当前导出")
        self.cancel_btn.setObjectName("DangerButton")
        self.cancel_btn.setEnabled(False)
        self.export_names_btn.clicked.connect(self.export_all_function_names_from_panel)
        self.preview_btn.clicked.connect(lambda: self.start_export(True))
        self.export_btn.clicked.connect(lambda: self.start_export(False))
        self.cancel_btn.clicked.connect(self.request_cancel)
        action.addWidget(self.save_defaults)
        action.addStretch(1)
        action.addWidget(self.export_names_btn)
        action.addWidget(self.preview_btn)
        action.addWidget(self.export_btn)
        action.addWidget(self.cancel_btn)
        outer.addWidget(action_frame)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        outer.addWidget(self.progress)
        self.status = QtWidgets.QLabel("就绪")
        self.status.setWordWrap(True)
        self.status.setObjectName("StatusLabel")
        outer.addWidget(self.status)

    def _make_scroll_column(self):
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        body = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(body)
        layout.setContentsMargins(4, 4, 8, 4)
        layout.setSpacing(12)
        scroll.setWidget(body)
        if not hasattr(self, "left_scroll"):
            self.left_scroll = scroll
        else:
            self.right_scroll = scroll
        return layout

    def _card(self, parent_layout, title: str, expanded: bool = False) -> CollapsibleCard:
        card = CollapsibleCard(title, expanded)
        parent_layout.addWidget(card)
        return card

    def _row_with_browse(self, layout, label: str):
        row = QtWidgets.QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(QtWidgets.QLabel(label))
        line = QtWidgets.QLineEdit()
        button = QtWidgets.QPushButton("浏览…")
        row.addWidget(line, 1)
        row.addWidget(button)
        layout.addLayout(row)
        return line, button

    def _add_checkbox_grid(self, card, specs, columns=1):
        grid = QtWidgets.QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(5)
        result = {}
        for index, (key, text) in enumerate(specs):
            cb = QtWidgets.QCheckBox(text)
            result[key] = cb
            grid.addWidget(cb, index // columns, index % columns)
        card.content_layout.addLayout(grid)
        return result

    def _spin(self, minimum=0, maximum=10_000_000, step=1):
        spin = QtWidgets.QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setSingleStep(step)
        spin.setMinimumWidth(110)
        return spin

    def _build_task_card(self) -> None:
        card = self._card(self.left_layout, "一、导出任务", True)
        form = QtWidgets.QFormLayout()
        form.setRowWrapPolicy(QtWidgets.QFormLayout.RowWrapPolicy.WrapLongRows)
        self.scope = QtWidgets.QComboBox()
        for key, label in core.SCOPE_OPTIONS:
            self.scope.addItem(label, key)
        form.addRow("导出范围", self.scope)
        card.content_layout.addLayout(form)
        self.output_dir, browse_output = self._row_with_browse(card.content_layout, "输出根目录")
        self.resume_dir, browse_resume = self._row_with_browse(card.content_layout, "断点续导目录")
        browse_output.clicked.connect(lambda: self._browse_dir(self.output_dir))
        browse_resume.clicked.connect(lambda: self._browse_dir(self.resume_dir))
        tip = QtWidgets.QLabel("断点续导目录留空时会自动新建 run_<时间> 目录。路径过长时插件会自动重定向到短路径目录。")
        tip.setWordWrap(True)
        tip.setObjectName("MutedTip")
        card.content_layout.addWidget(tip)

    def _build_rules_card(self) -> None:
        card = self._card(self.left_layout, "二、字符串筛选规则", True)
        tip = QtWidgets.QLabel("按类别管理规则。批量粘贴时建议每行一个字符串；模板函数名称中的逗号不会被拆分。")
        tip.setWordWrap(True)
        tip.setObjectName("MutedTip")
        card.content_layout.addWidget(tip)
        self.rules = RuleListEditor(self.cfg)
        self.rules.setMinimumHeight(390)
        card.content_layout.addWidget(self.rules, 1)

    def _build_output_card(self) -> None:
        card = self._card(self.right_layout, "三、输出分类", True)
        self.output_checks = self._add_checkbox_grid(card, (
            ("group_files_by_batch", "按批次目录分组"),
            ("group_files_by_class", "按照类名称建立子目录"),
            ("class_folder_include_namespaces", "类目录保留命名空间层级"),
            ("group_files_by_segment", "按照段名称建立子目录"),
            ("write_dependency_edges", "写入依赖关系 CSV"),
            ("write_tracebacks", "失败日志写入完整 Python 堆栈"),
        ), columns=1)
        form = QtWidgets.QFormLayout()
        self.functions_per_batch = self._spin(1, 1_000_000, 100)
        form.addRow("每个批次目录包含的函数数量", self.functions_per_batch)
        self.filename_mode = QtWidgets.QComboBox()
        for key, label in core.FILENAME_OPTIONS:
            self.filename_mode.addItem(label, key)
        form.addRow("文件名策略", self.filename_mode)
        card.content_layout.addLayout(form)
        path_tip = QtWidgets.QLabel(
            "路径长度无需手工设置：插件会自动缩短类目录和文件名；必要时退化为地址 + 哈希，并自动切换到短路径存储目录。"
        )
        path_tip.setWordWrap(True)
        path_tip.setObjectName("InfoTip")
        card.content_layout.addWidget(path_tip)
        order_tip = QtWidgets.QLabel("目录顺序：functions / batch_0001 / segment（可选） / 命名空间 / 类名 / 函数.c")
        order_tip.setWordWrap(True)
        order_tip.setObjectName("MutedTip")
        card.content_layout.addWidget(order_tip)

    def _build_filter_card(self) -> None:
        card = self._card(self.right_layout, "四、过滤选项", False)
        self.filter_checks = self._add_checkbox_grid(card, (
            ("skip_imported_functions", "跳过导入函数"),
            ("skip_external_segments", "跳过外部段函数"),
            ("skip_non_executable_segments", "跳过不可执行段函数"),
            ("skip_ida_library_functions", "跳过 IDA 库签名函数"),
            ("skip_standard_cpp_names", "跳过 C++ 标准库名称"),
            ("skip_common_c_names", "跳过常见 C 标准库名称"),
            ("skip_runtime_helpers", "跳过编译器和运行时辅助函数"),
            ("skip_known_third_party_names", "跳过已知第三方模块名称（V8、Blink、Skia 等）"),
            ("skip_thunks", "跳过 thunk 跳板函数"),
            ("skip_autogenerated_names", "跳过 sub_xxx 等自动命名函数"),
        ), columns=1)

    def _build_stability_card(self) -> None:
        card = self._card(self.right_layout, "五、稳定性与恢复", False)
        self.stability_checks = self._add_checkbox_grid(card, (
            ("stable_mode", "启用稳定模式"),
            ("write_active_checkpoint", "写入正在处理函数的崩溃检查点"),
            ("auto_quarantine_previous_active_on_resume", "续导时自动隔离上次未完成函数"),
            ("clear_target_cache_after_each_function", "每个函数后清理目标函数缓存"),
            ("retry_failed_after_local_analysis", "失败后局部分析并重试一次"),
            ("wait_for_global_auto_analysis", "导出前等待 IDA 完成全部自动分析"),
        ), columns=1)
        form = QtWidgets.QFormLayout()
        self.clear_all_interval = self._spin(0, 100000, 1)
        self.gc_interval = self._spin(0, 100000, 1)
        self.cooldown = self._spin(0, 60000, 10)
        self.progress_interval = self._spin(1, 100000, 1)
        self.flush_interval = self._spin(1, 100000, 1)
        self.session_limit = self._spin(0, 10_000_000, 100)
        form.addRow("全部缓存清理间隔", self.clear_all_interval)
        form.addRow("Python GC 间隔", self.gc_interval)
        form.addRow("每个函数后暂停毫秒数", self.cooldown)
        form.addRow("进度刷新间隔", self.progress_interval)
        form.addRow("日志强制刷新间隔", self.flush_interval)
        form.addRow("本次最多处理函数数（0 不限制）", self.session_limit)
        card.content_layout.addLayout(form)

    def _build_expert_card(self) -> None:
        card = self._card(self.right_layout, "六、范围与专家参数", False)
        form = QtWidgets.QFormLayout()
        self.include_regex = QtWidgets.QLineEdit()
        self.exclude_regex = QtWidgets.QLineEdit()
        self.case_sensitive = QtWidgets.QCheckBox("筛选时区分大小写")
        self.range_start = QtWidgets.QLineEdit()
        self.range_end = QtWidgets.QLineEdit()
        self.max_depth = self._spin(0, 10000, 1)
        self.min_length = self._spin(0, 0x7FFFFFFF, 16)
        self.max_length = self._spin(0, 0x7FFFFFFF, 16)
        self.max_count = self._spin(0, 10_000_000, 100)
        self.skip_existing = QtWidgets.QCheckBox("断点续导时跳过已有文件")
        self.confirm_before = QtWidgets.QCheckBox("导出前确认目标函数数量")
        form.addRow("包含正则表达式", self.include_regex)
        form.addRow("排除正则表达式", self.exclude_regex)
        form.addRow("", self.case_sensitive)
        form.addRow("地址范围起始值", self.range_start)
        form.addRow("地址范围结束值", self.range_end)
        form.addRow("依赖递归最大深度（0 不限制）", self.max_depth)
        form.addRow("最小函数长度", self.min_length)
        form.addRow("最大函数长度（0 不限制）", self.max_length)
        form.addRow("最多导出函数数量（0 不限制）", self.max_count)
        form.addRow("", self.skip_existing)
        form.addRow("", self.confirm_before)
        card.content_layout.addLayout(form)

    def _browse_dir(self, line_edit) -> None:
        selected = QtWidgets.QFileDialog.getExistingDirectory(self, "选择目录", line_edit.text().strip() or str(Path.cwd()))
        if selected:
            line_edit.setText(selected)

    def _load_to_widgets(self, cfg: dict) -> None:
        self.ui_theme.setCurrentIndex(option_index(THEME_OPTIONS, cfg.get("ui_theme", "soft_dark")))
        self.scope.setCurrentIndex(option_index(core.SCOPE_OPTIONS, cfg["scope"]))
        self.output_dir.setText(str(cfg.get("output_dir") or ""))
        self.resume_dir.setText(str(cfg.get("resume_run_dir") or ""))
        for mapping in (self.filter_checks, self.output_checks, self.stability_checks):
            for key, widget in mapping.items():
                widget.setChecked(bool(cfg.get(key)))
        self.functions_per_batch.setValue(int(cfg.get("functions_per_batch_folder", 1000)))
        self.filename_mode.setCurrentIndex(option_index(core.FILENAME_OPTIONS, cfg.get("filename_mode", "auto_readable")))
        self.clear_all_interval.setValue(int(cfg["clear_all_cache_interval"]))
        self.gc_interval.setValue(int(cfg["python_gc_interval"]))
        self.cooldown.setValue(int(cfg["cooldown_milliseconds"]))
        self.progress_interval.setValue(int(cfg["progress_update_interval"]))
        self.flush_interval.setValue(int(cfg["flush_interval"]))
        self.session_limit.setValue(int(cfg["maximum_functions_per_session"]))
        self.include_regex.setText(str(cfg.get("include_regex") or ""))
        self.exclude_regex.setText(str(cfg.get("exclude_regex") or ""))
        self.case_sensitive.setChecked(bool(cfg.get("case_sensitive_filters")))
        self.range_start.setText(str(cfg.get("range_start") or "0x0"))
        self.range_end.setText(str(cfg.get("range_end") or "0x0"))
        self.max_depth.setValue(int(cfg["maximum_dependency_depth"]))
        self.min_length.setValue(int(cfg["minimum_function_length"]))
        self.max_length.setValue(int(cfg["maximum_function_length"]))
        self.max_count.setValue(int(cfg["maximum_export_count"]))
        self.skip_existing.setChecked(bool(cfg["skip_existing_files_when_resuming"]))
        self.confirm_before.setChecked(bool(cfg["confirm_before_export"]))

    def collect_config(self, dry_run: bool) -> dict:
        cfg = dict(self.cfg)
        cfg.update(self.rules.get_rules())
        cfg["ui_theme"] = str(self.ui_theme.currentData() or "soft_dark")
        cfg["scope"] = str(self.scope.currentData())
        cfg["output_dir"] = self.output_dir.text().strip()
        cfg["resume_run_dir"] = self.resume_dir.text().strip()
        for mapping in (self.filter_checks, self.output_checks, self.stability_checks):
            for key, widget in mapping.items():
                cfg[key] = bool(widget.isChecked())
        cfg["functions_per_batch_folder"] = int(self.functions_per_batch.value())
        cfg["filename_mode"] = str(self.filename_mode.currentData())
        cfg["clear_all_cache_interval"] = int(self.clear_all_interval.value())
        cfg["python_gc_interval"] = int(self.gc_interval.value())
        cfg["cooldown_milliseconds"] = int(self.cooldown.value())
        cfg["progress_update_interval"] = int(self.progress_interval.value())
        cfg["flush_interval"] = int(self.flush_interval.value())
        cfg["maximum_functions_per_session"] = int(self.session_limit.value())
        cfg["include_regex"] = self.include_regex.text().strip()
        cfg["exclude_regex"] = self.exclude_regex.text().strip()
        cfg["case_sensitive_filters"] = bool(self.case_sensitive.isChecked())
        cfg["range_start"] = self.range_start.text().strip() or "0x0"
        cfg["range_end"] = self.range_end.text().strip() or "0x0"
        cfg["maximum_dependency_depth"] = int(self.max_depth.value())
        cfg["minimum_function_length"] = int(self.min_length.value())
        cfg["maximum_function_length"] = int(self.max_length.value())
        cfg["maximum_export_count"] = int(self.max_count.value())
        cfg["skip_existing_files_when_resuming"] = bool(self.skip_existing.isChecked())
        cfg["confirm_before_export"] = bool(self.confirm_before.isChecked())
        cfg["dry_run"] = bool(dry_run)
        return core.normalize_config(cfg)

    def request_cancel(self) -> None:
        self.cancel_requested = True
        self.status.setText("已请求取消，将在当前函数处理结束后的安全点停止。")

    def _set_busy(self, busy: bool) -> None:
        self.export_btn.setEnabled(not busy)
        self.preview_btn.setEnabled(not busy)
        self.export_names_btn.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)

    def export_all_function_names_from_panel(self) -> None:
        try:
            export_all_function_names_interactive(self)
        except Exception as exc:
            log(f"函数名称导出失败：{type(exc).__name__}: {exc}")
            log(traceback.format_exc())
            QtWidgets.QMessageBox.critical(self, "函数名称导出失败", f"{type(exc).__name__}: {exc}\n\n详细信息请查看 IDA 输出窗口。")

    def _progress_callback(self, index, total, stats, target) -> None:
        self.progress.setValue(int(index * 100 / max(1, total)))
        self.status.setText(
            f"进度 {index}/{total}　当前 0x{target.start_ea:X} {target.raw_name}\n"
            f"成功 {stats.exported_count}　已有 {stats.existing_count}　失败 {stats.failed_count}　隔离 {stats.quarantined_count}"
        )
        QtWidgets.QApplication.processEvents()

    def start_export(self, dry_run: bool) -> None:
        self.cancel_requested = False
        self.progress.setValue(0)
        self._set_busy(True)
        try:
            cfg = self.collect_config(dry_run)
            core.validate_config(cfg)
            if self.save_defaults.isChecked():
                save_user_config(cfg)
            hexrays_ok, hexrays_diagnostics = ensure_hexrays_available()
            for diagnostic_line in hexrays_diagnostics:
                log(diagnostic_line)
            if not hexrays_ok:
                diagnostic_text = "\n".join(hexrays_diagnostics[-10:])
                raise RuntimeError(
                    "当前数据库无法使用 Hex-Rays 反编译器。\n\n"
                    "插件已经尝试自动加载当前架构对应的反编译器模块，但仍未成功。\n"
                    "请先在任意函数内手工按 F5 测试。\n\n"
                    f"最近诊断信息：\n{diagnostic_text}"
                )
            if cfg["wait_for_global_auto_analysis"]:
                self.status.setText("正在等待 IDA 完成全部自动分析……")
                QtWidgets.QApplication.processEvents()
                ida_auto.auto_wait()
            self.status.setText("正在枚举函数并应用筛选条件……")
            QtWidgets.QApplication.processEvents()
            run_dir, attempt_dir, retained, skipped, targets, root_count, edges, imports = core.create_export_attempt(cfg, log)
            if dry_run:
                self.progress.setValue(100)
                self.status.setText(f"预演完成：目标函数 {len(targets)}，筛选排除 {len(skipped)}。报告目录：{attempt_dir}")
                QtWidgets.QMessageBox.information(self, "预演完成", f"目标函数：{len(targets)}\n筛选排除：{len(skipped)}\n\n报告目录：{attempt_dir}")
                return
            if cfg["confirm_before_export"]:
                answer = QtWidgets.QMessageBox.question(
                    self, "确认导出",
                    f"导出范围：{core.get_option_label(core.SCOPE_OPTIONS, cfg['scope'])}\n"
                    f"根函数：{root_count}\n目标函数：{len(targets)}\n筛选排除：{len(skipped)}\n"
                    f"运行目录：{run_dir}\n\n是否继续？",
                )
                if answer != QtWidgets.QMessageBox.StandardButton.Yes:
                    self.status.setText("已取消导出。")
                    return
            result = core.process_targets(
                targets, cfg, run_dir, attempt_dir, session_id="interactive", logger=log,
                cancel_checker=lambda: self.cancel_requested, progress_callback=self._progress_callback,
            )
            stats = result.stats
            self.progress.setValue(100 if not stats.cancelled else self.progress.value())
            self.status.setText(
                f"导出完成：成功 {stats.exported_count}，已有 {stats.existing_count}，失败 {stats.failed_count}，隔离 {stats.quarantined_count}。\n"
                f"运行目录：{run_dir}"
            )
            QtWidgets.QMessageBox.information(
                self, "导出完成",
                f"成功导出：{stats.exported_count}\n已有文件：{stats.existing_count}\n失败：{stats.failed_count}\n"
                f"隔离：{stats.quarantined_count}\n取消：{stats.cancelled}\n\n运行目录：{run_dir}\n本次报告：{attempt_dir}",
            )
        except Exception as exc:
            log(f"严重错误：{type(exc).__name__}: {exc}")
            log(traceback.format_exc())
            self.status.setText(f"导出失败：{type(exc).__name__}: {exc}")
            QtWidgets.QMessageBox.critical(self, "导出失败", f"{type(exc).__name__}: {exc}\n\n详细信息请查看 IDA 输出窗口。")
        finally:
            self._set_busy(False)


class ExporterPluginForm(ida_kernwin.PluginForm):
    def OnCreate(self, form) -> None:
        # IDA 9.3 / PySide6：使用新的通用 Qt Python 绑定转换函数。
        # 这里不要传 ida_kernwin / idaapi 作为 ctx；ctx 是给旧 PyQt/sip 包装路径用的。
        parent = ida_kernwin.PluginForm.TWidgetToQtPythonWidget(form)
        if parent is None:
            raise RuntimeError("无法把 IDA PluginForm 转换为 PySide6 QWidget。")

        layout = parent.layout()
        if layout is None:
            layout = QtWidgets.QVBoxLayout(parent)
            layout.setContentsMargins(0, 0, 0, 0)
        else:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)

        panel = ExporterPanel(parent)
        panel.setMinimumSize(820, 560)
        layout.addWidget(panel)
        self.panel = panel

    def OnClose(self, form) -> None:
        global ACTIVE_FORM
        ACTIVE_FORM = None

def show_exporter_window() -> None:
    global ACTIVE_FORM
    if ACTIVE_FORM is None:
        ACTIVE_FORM = ExporterPluginForm()
    options = (
        ida_kernwin.PluginForm.WOPN_PERSIST
        | ida_kernwin.PluginForm.WOPN_RESTORE
        | ida_kernwin.PluginForm.WOPN_DP_FLOATING
        | ida_kernwin.PluginForm.WOPN_DP_SZHINT
    )
    ACTIVE_FORM.Show(PLUGIN_NAME, options=options)


def choose_existing_directory_qt(title: str, default_dir: str, parent=None) -> str:
    try:
        Path(default_dir).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    selected = QtWidgets.QFileDialog.getExistingDirectory(
        parent,
        title,
        default_dir,
        QtWidgets.QFileDialog.Option.ShowDirsOnly,
    )
    return str(selected or "")


def export_all_function_names_interactive(parent=None) -> None:
    default_dir = str(core.get_default_output_root())
    selected = choose_existing_directory_qt("选择全部函数名称导出目录", default_dir, parent)
    if not selected:
        return
    report_dir = core.export_all_function_names(selected, log)
    ida_kernwin.info(f"全部函数名称导出完成。\n\n输出目录：{report_dir}")


class ShowPanelActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        show_exporter_window()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ExportAllFunctionNamesActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            export_all_function_names_interactive()
        except Exception as exc:
            log(f"函数名称导出失败：{type(exc).__name__}: {exc}")
            log(traceback.format_exc())
            ida_kernwin.warning(f"函数名称导出失败。\n\n{type(exc).__name__}: {exc}")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_plugin_actions() -> None:
    global ACTIONS_REGISTERED
    if ACTIONS_REGISTERED:
        return
    action_specs = (
        (ACTION_SHOW_PANEL, f"{PLUGIN_NAME}：打开导出面板", ShowPanelActionHandler(), "", "打开伪代码批量导出面板。"),
        (ACTION_EXPORT_NAMES, f"{PLUGIN_NAME}：导出全部函数名称", ExportAllFunctionNamesActionHandler(), "", "不调用 Hex-Rays，直接导出当前数据库中的全部函数名称。"),
    )
    for action_name, label, handler, shortcut, tooltip in action_specs:
        try:
            ida_kernwin.unregister_action(action_name)
        except Exception:
            pass
        ida_kernwin.register_action(ida_kernwin.action_desc_t(action_name, label, handler, shortcut, tooltip, -1))
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", action_name, ida_kernwin.SETMENU_APP)
    ACTIONS_REGISTERED = True


class PseudocodeExporterPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        try:
            show_exporter_window()
        except Exception as exc:
            log(f"严重错误：{type(exc).__name__}: {exc}")
            log(traceback.format_exc())
            ida_kernwin.warning(f"{PLUGIN_NAME} 无法打开。\n\n{type(exc).__name__}: {exc}\n\n详细信息请查看 IDA 输出窗口。")
        return True


class PseudocodeExporterPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "IDA 9.3 / PySide6 中文 Hex-Rays 函数伪代码导出器：批量导出伪代码，并可单独导出全部函数名称"
    help = "适用于 IDA Pro 9.3 的通用函数伪代码导出插件"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        register_plugin_actions()
        return PseudocodeExporterPlugmod()


def PLUGIN_ENTRY():
    return PseudocodeExporterPlugin()
