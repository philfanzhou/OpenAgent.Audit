import pathlib

p = pathlib.Path(r"D:\OpenAgent.Audit\tests\test_audit_api.py")
text = p.read_text(encoding="utf-8")

# 删除范围过大（误删了 test_audit_log_chain_stays_valid_after_reveals）——恢复并重做
p.write_bytes(text_backup := text.encode("utf-8"))  # placeholder
print("检查误删范围")