import os
import yaml

def test_xss_payloads_exist():
    path = os.path.join("payloads", "xss_payloads.yaml")
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert len(data["payloads"]) > 0

def test_sqli_payloads_exist():
    path = os.path.join("payloads", "sqli_payloads.yaml")
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert len(data["payloads"]) > 0
    assert len(data["error_signatures"]) > 0

def test_lfi_payloads_exist():
    path = os.path.join("payloads", "lfi_payloads.yaml")
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert len(data["payloads"]) > 0