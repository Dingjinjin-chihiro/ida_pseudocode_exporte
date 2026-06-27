# 通用函数伪代码导出器 V3.5.1（IDA 9.3 / PySide6 中文版）

适用于 **IDA Pro 9.3 + IDAPython + Hex-Rays Decompiler**。

本版本不再向下兼容 IDA 9.0 / Qt5 / PyQt5，界面层已升级为 **Qt6 / PySide6**。插件保留原有的函数伪代码批量导出、筛选、分类、断点续导和稳定性保护能力，并新增一个完全独立的功能：**导出全部函数名称**。

## 1. 主要功能

- 批量导出 Hex-Rays 伪代码：按全部函数、匹配函数、当前函数、地址范围和依赖递归导出。
- 自动路径优化：自动缩短类目录和文件名，避免 Windows 长路径失败。
- 分类输出：支持按批次、段名、命名空间、类名建立目录。
- 稳定性保护：活动函数检查点、失败函数隔离、缓存清理、断点续导。
- 独立导出全部函数名称：不调用 Hex-Rays，不需要反编译器许可证，只枚举 IDA 当前数据库中的函数名称。

## 2. 安装

将整个目录复制到：

```text
<IDA Pro 9.3 安装目录>\plugins\ida_pseudocode_exporter\
```

保留以下核心文件：

```text
ida-plugin.json
ida_pseudocode_exporter.py
ida_pseudocode_export_core.py
ida_pseudocode_exporter_config.json
```

启动 IDA 9.3 后，插件会通过 `ida-plugin.json` 自动加载。

## 3. 使用入口

### 打开主面板

在 IDA 中通过插件菜单打开：

```text
Edit → Plugins → 通用函数伪代码导出器：打开导出面板
```

也可以从 IDA 的插件列表运行“通用函数伪代码导出器”。

### 单独导出全部函数名称

有两种方式：

1. 在主面板底部点击 **导出全部函数名称**。
2. 直接从菜单执行：

```text
Edit → Plugins → 通用函数伪代码导出器：导出全部函数名称
```

该功能不会调用 `ida_hexrays.decompile()`，因此不会受 Hex-Rays 反编译失败影响。

## 4. 全部函数名称导出结果

输出目录格式：

```text
function_names_<数据库名>_<时间戳>\
```

目录内包含：

```text
all_function_names.csv
all_function_names.json
all_function_raw_names.txt
all_function_display_names.txt
summary.txt
```

字段说明：

| 字段 | 说明 |
|---|---|
| `index` | 顺序编号 |
| `address` / `start_ea` / `end_ea` | 函数地址范围 |
| `length` | 函数长度 |
| `segment` | 所属段 |
| `raw_name` | IDA 原始函数名 |
| `demangled_name` | 反混淆后的名称，若可用 |
| `display_name` | 优先使用反混淆名称，否则使用原始名称 |
| `flags_hex` | IDA 函数标志位 |
| `is_library` | 是否为 IDA 识别的库函数 |
| `is_thunk` | 是否为 thunk 函数 |
| `is_import_name` | 是否命中导入表名称地址 |

## 5. 本次升级重点

- 移除 PyQt5 导入和旧版配置读取。
- `PluginForm` 改为 `ida_kernwin.PluginForm.TWidgetToQtPythonWidget()`，避免 IDA 9.3 下 `FormToPySideWidget()` / ctx 传参不稳定导致窗口无法创建。
- Qt 枚举改为 PySide6 / Qt6 风格，例如 `QtCore.Qt.Orientation.Horizontal`。
- 新增两个 IDA 动作：打开导出面板、导出全部函数名称。
- 新增核心函数：
  - `collect_all_function_name_records()`
  - `export_all_function_names()`
- 配置 schema 升级到 `10`。
- 插件版本升级到 `3.5.1-ida93-pyside6-zh`。

## 6. 静态检查

在插件目录运行：

```bat
run_static_checks.bat
```

或手动执行：

```bat
python pyside6_static_test.py
python core_batch_static_test.py
python auto_path_static_test.py
```


## 3.5.1 修复

- 修复插件面板无法启动窗口的问题。
- 取消 `ida_kernwin.ask_dir()`，全部函数名称导出目录选择改为 PySide6 `QFileDialog.getExistingDirectory()`。
- 面板底部新增“导出全部函数名称”按钮，菜单动作和面板按钮均可独立导出函数名。
# ida_pseudocode_exporte
