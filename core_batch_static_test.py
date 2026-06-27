# -*- coding: utf-8 -*-
"""在 IDA 外部验证批次目录和类目录路径。"""
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
spec = importlib.util.spec_from_file_location('ida_pseudocode_export_core_test', path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

cfg = module.normalize_config({
    'group_files_by_batch': True,
    'functions_per_batch_folder': 2,
    'group_files_by_class': True,
    'class_folder_include_namespaces': True,
    'maximum_full_path_length': 220,
})
assert module.get_batch_folder_name(1, cfg) == 'batch_0001'
assert module.get_batch_folder_name(2, cfg) == 'batch_0001'
assert module.get_batch_folder_name(3, cfg) == 'batch_0002'
assert module.get_batch_folder_name(2001, {**cfg, 'functions_per_batch_folder': 1000}) == 'batch_0003'

target = module.ExportTarget(0x1000, 0x1100, 'demo::Document::Save', 'demo::Document::Save()', '__text', 0)
with tempfile.TemporaryDirectory() as temp_dir:
    output_dir, class_category, batch_folder = module.resolve_function_output_dir(
        Path(temp_dir) / 'functions', target, cfg, 3
    )
    assert batch_folder == 'batch_0002'
    assert class_category == 'demo/Document'
    assert output_dir.parts[-3:] == ('batch_0002', 'demo', 'Document')
    filename = module.make_safe_filename(output_dir, target, cfg)
    assert filename.endswith('.c')
    content = module.build_function_file(target, 'int result;\n', class_category, batch_folder)
    assert 'batch_0002' in content

print('Core batch folder static test: OK')
