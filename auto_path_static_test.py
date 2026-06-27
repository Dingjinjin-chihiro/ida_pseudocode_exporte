# -*- coding: utf-8 -*-
"""在 IDA 外部验证自动路径降级、批次目录和类目录。"""
import importlib.util
import sys
import tempfile
import types
from pathlib import Path

for name in (
    'ida_auto','ida_diskio','ida_funcs','ida_hexrays','ida_kernwin','ida_lines',
    'ida_loader','ida_nalt','ida_segment','idautils','idc',
):
    sys.modules[name] = types.ModuleType(name)
sys.modules['ida_kernwin'].msg = print

root = Path(__file__).resolve().parent
path = root / 'ida_pseudocode_export_core.py'
spec = importlib.util.spec_from_file_location('ida_pseudocode_export_core_auto_test', path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

cfg = module.normalize_config({
    'group_files_by_batch': True,
    'functions_per_batch_folder': 2,
    'group_files_by_class': True,
    'class_folder_include_namespaces': True,
    'filename_mode': 'auto_readable',
    'internal_path_budget_override': 180,
})
assert module.get_batch_folder_name(1, cfg) == 'batch_0001'
assert module.get_batch_folder_name(2, cfg) == 'batch_0001'
assert module.get_batch_folder_name(3, cfg) == 'batch_0002'

very_long = 'namespace_' + ('A' * 120) + '::Class_' + ('B' * 120) + '::Method_' + ('C' * 180)
target = module.ExportTarget(0x12345678, 0x12345778, very_long, very_long + '()', '__text', 0)
with tempfile.TemporaryDirectory() as td:
    base = Path(td) / ('deep_' + 'x' * 40) / ('nested_' + 'y' * 40)
    function_root = base / 'functions'
    resolved_root = module.resolve_function_root(base, cfg)
    out, category, batch = module.resolve_function_output_dir(resolved_root, target, cfg, 3)
    filename = module.make_safe_filename(out, target, cfg)
    full = out / filename
    assert batch == 'batch_0002'
    assert len(str(full)) <= module.get_auto_path_budget(cfg)
    assert filename.endswith('.c')
    text = module.build_function_file(target, 'int ok;\n', category, batch)
    assert very_long in text

# 测试输出根目录过深时自动切换短目录。
with tempfile.TemporaryDirectory() as td:
    requested = Path(td) / ('R' * 100) / ('S' * 100)
    cfg2 = module.normalize_config({
        'output_dir': str(requested),
        'internal_path_budget_override': 180,
        'auto_compact_root_on_overflow': True,
    })
    run_dir, attempt_dir = module.choose_run_dir(cfg2)
    assert run_dir.exists()
    assert attempt_dir.exists()
    assert len(str(run_dir)) < len(str(requested / 'run_00000000_000000_000'))

print('Automatic path strategy static test: OK')
