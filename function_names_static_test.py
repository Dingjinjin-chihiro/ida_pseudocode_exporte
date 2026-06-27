# -*- coding: utf-8 -*-
"""在 IDA 外部验证全部函数名称导出逻辑。"""
import csv
import importlib.util
import json
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

for name in (
    'ida_auto','ida_diskio','ida_funcs','ida_hexrays','ida_kernwin','ida_lines',
    'ida_loader','ida_nalt','ida_segment','idautils','idc',
):
    sys.modules[name] = types.ModuleType(name)

sys.modules['ida_kernwin'].msg = print
sys.modules['ida_loader'].PATH_TYPE_IDB = 0
sys.modules['ida_loader'].get_path = lambda kind: ''
sys.modules['idc'].INF_SHORT_DN = 0
sys.modules['idc'].get_inf_attr = lambda attr: 0
sys.modules['idc'].demangle_name = lambda name, flags: 'demo::FuncA()' if name == '_Z5FuncAv' else ''
sys.modules['idc'].get_root_filename = lambda: 'sample.bin'
sys.modules['idc'].get_input_file_path = lambda: 'C:/tmp/sample.bin'
sys.modules['ida_nalt'].get_import_module_qty = lambda: 0
sys.modules['idautils'].Functions = lambda: [0x2000, 0x1000]
sys.modules['ida_funcs'].FUNC_LIB = 0x4
sys.modules['ida_funcs'].FUNC_THUNK = 0x8

def get_func(ea):
    if ea == 0x1000:
        return SimpleNamespace(start_ea=0x1000, end_ea=0x1010, flags=0)
    if ea == 0x2000:
        return SimpleNamespace(start_ea=0x2000, end_ea=0x2020, flags=0x4)
    return None

sys.modules['ida_funcs'].get_func = get_func
sys.modules['ida_funcs'].get_func_name = lambda ea: '_Z5FuncAv' if ea == 0x1000 else 'lib_func'
sys.modules['ida_segment'].getseg = lambda ea: SimpleNamespace()
sys.modules['ida_segment'].get_segm_name = lambda seg: '.text'

root = Path(__file__).resolve().parent
path = root / 'ida_pseudocode_export_core.py'
spec = importlib.util.spec_from_file_location('ida_pseudocode_export_core_names_test', path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as td:
    out = module.export_all_function_names(td, print)
    csv_path = out / 'all_function_names.csv'
    json_path = out / 'all_function_names.json'
    raw_path = out / 'all_function_raw_names.txt'
    display_path = out / 'all_function_display_names.txt'
    assert csv_path.is_file()
    assert json_path.is_file()
    assert raw_path.read_text(encoding='utf-8').splitlines() == ['_Z5FuncAv', 'lib_func']
    assert display_path.read_text(encoding='utf-8').splitlines() == ['demo::FuncA()', 'lib_func']
    data = json.loads(json_path.read_text(encoding='utf-8'))
    assert data['count'] == 2
    assert data['items'][0]['address'] == '0x1000'
    assert data['items'][1]['is_library'] is True
    with csv_path.open('r', encoding='utf-8-sig', newline='') as f:
        rows = list(csv.DictReader(f))
    assert rows[0]['raw_name'] == '_Z5FuncAv'
    assert rows[0]['display_name'] == 'demo::FuncA()'

print('Function names export static test: OK')
