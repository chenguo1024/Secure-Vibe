"""tests/test_python_adv.py — Python deep rules (SSRF/XXE/SSTI/path/ML/JWT/CORS/NoSQL etc.)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validator import Validator  # noqa: E402


def py(code: str):
    return Validator("python").validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


# --- P0: deep-rule malicious detections ---

def test_ssrf_user_url():
    r = py("import requests\nresp = requests.get(user_url)")
    assert "PY-011" in ids(r)


def test_ssrf_metadata_blacklist():
    # cloud metadata address (BL-007)
    r = py('requests.get("http://169.254.169.254/latest/meta-data")')
    assert "BL-007" in ids(r)


def test_xml_parser_xxe():
    r = py("from lxml import etree\ntree = etree.fromstring(xml_data)")
    assert "PY-012" in ids(r)


def test_ssti_render_template_string():
    r = py("from flask import render_template_string\nreturn render_template_string(user_input)")
    assert "PY-013" in ids(r)


def test_path_traversal():
    r = py("target = os.path.join(base_dir, user_filename)\nwith open(target) as f:\n    pass")
    assert "PY-014" in ids(r)


def test_zip_slip():
    r = py("import tarfile\ntf = tarfile.open(archive)\ntf.extractall(dest)")
    assert "PY-015" in ids(r)


def test_nosql_operator_injection():
    r = py('doc = collection.find({"$where": query_string})')
    assert "PY-016" in ids(r)


def test_orm_raw_query():
    r = py('rows = Model.objects.raw("SELECT * FROM t WHERE x = %s" % payload)')
    assert "PY-017" in ids(r)


def test_jwt_alg_none():
    r = py("import jwt\nheader = {'alg': 'none'}")
    assert "PY-018" in ids(r)


def test_regex_dos():
    r = py("import re\nre.search(user_regex, user_input)")
    assert "PY-022" in ids(r)


def test_ml_deserialization():
    r = py("import torch\nmodel = torch.load(model_path)")
    assert "PY-021" in ids(r)


def test_ml_deserialization_joblib_pandas():
    r = py("import joblib, pandas\nm = joblib.load(path)\ndf = pandas.read_pickle(p)")
    assert "PY-021" in ids(r)


# --- P0: safe equivalents, zero false positives ---

def test_torch_weights_only_passes():
    r = py("import torch\nmodel = torch.load(p, weights_only=True)")
    assert "PY-021" not in ids(r)


def test_safe_xml_defusedxml_passes():
    r = py("import defusedxml.ElementTree\ndefusedxml.ElementTree.fromstring(xml_data)")
    assert not any(v.rule_id == "PY-012" for v in r.violations)


def test_safe_path_realpath_passes():
    r = py(
        "import os\n"
        "base = os.path.realpath('/safe/data')\n"
        "target = os.path.realpath(os.path.join(base, name))\n"
        "assert target.startswith(base + os.sep)\n"
    )
    assert "PY-014" not in ids(r)


def test_sqlalchemy_parametrized_passes():
    r = py("from sqlalchemy import text\nconn.execute(text('SELECT * FROM t WHERE x = :x'), {'x': 1})")
    assert "GEN-005" not in ids(r)


def test_literal_url_requests_passes():
    r = py("import requests\nrequests.get('https://api.example.com/health')")
    assert not any(v.rule_id == "PY-011" for v in r.violations)
