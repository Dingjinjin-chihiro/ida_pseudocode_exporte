# 变更记录

## 3.5.1-ida93-pyside6-zh

- 修复 IDA 9.3 下插件窗口无法启动的问题：`PluginForm.OnCreate()` 改用 `ida_kernwin.PluginForm.TWidgetToQtPythonWidget(form)`。
- 移除不存在的 `ida_kernwin.ask_dir()` 调用，函数名称导出目录选择改用 PySide6 `QFileDialog.getExistingDirectory()`。
- 面板底部新增“导出全部函数名称”按钮；菜单动作仍保留同名独立功能。
- 不再添加 PyQt5 / IDA 9.0 兼容路径。

## 3.5.0-ida93-pyside6-zh

- 升级到 IDA 9.3 / Qt6 / PySide6。
- 移除 IDA 9.0 / Qt5 / PyQt5 兼容逻辑。
- 新增“导出全部函数名称”独立动作。
- 配置文件升级为 schema 10。
