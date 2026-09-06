"""tests/test_ast_fixer.py — AST deterministic fix engine tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.ast_fixer import deterministic_fix  # noqa: E402
from core.validator import Validator  # noqa: E402


def fix_of(code: str):
    v = Validator("python")
    result = v.validate(code)
    new_code, applied = deterministic_fix(code, result.violations)
    return new_code, applied, [x.rule_name for x in result.violations]


def test_randint_to_secrets():
    code = "import random\ntoken = random.randint(100000, 999999)"
    new, applied, rules = fix_of(code)
    assert "insecure_random" in applied
    assert "secrets.randbelow" in new
    assert "import secrets" in new
    assert "randint" not in new
    v = Validator("python")
    assert v.validate(new).passed


def test_random_choice_to_secrets():
    code = "import random\nimport string\nx = random.choice(string.ascii_letters)"
    new, applied, _ = fix_of(code)
    assert "secrets.choice" in new
    v = Validator("python")
    assert v.validate(new).passed


def test_weak_hash_to_sha256():
    code = "import hashlib\nd = hashlib.md5(data)"
    new, applied, _ = fix_of(code)
    assert "weak_hash" in applied
    assert "sha256" in new
    assert "md5" not in new
    assert Validator("python").validate(new).passed


def test_yaml_load_to_safe_load():
    code = "import yaml\ncfg = yaml.load(f)"
    new, applied, _ = fix_of(code)
    assert "unsafe_yaml_load" in applied
    assert "safe_load" in new
    assert Validator("python").validate(new).passed


def test_yaml_load_with_loader_dropped():
    code = "import yaml\ncfg = yaml.load(f, Loader=yaml.CLoader)"
    new, applied, _ = fix_of(code)
    assert "unsafe_yaml_load" in applied
    assert "safe_load" in new
    assert "Loader" not in new


def test_hardcoded_secret_to_env():
    code = 'API_KEY = "sk-hardcoded-secret-1234567890"\nprint(len(API_KEY))'
    new, applied, _ = fix_of(code)
    assert "hardcoded_secret" in applied
    assert "import os" in new
    assert "os.environ.get('API_KEY', '')" in new
    assert "sk-hardcoded" not in new
    # after the fix there is no hardcoded-secret violation (print the length, not the value)
    v = Validator("python")
    assert v.validate(new).passed


def test_import_not_duplicated():
    code = 'import os\nAPI_KEY = "sk-hardcoded-secret-1234567890"'
    new, _, _ = fix_of(code)
    assert "import os" in new
    assert new.count("import os") == 1


def test_unfixable_eval_untouched():
    code = "result = eval(user_input)"
    new, applied, _ = fix_of(code)
    assert applied == []
    assert new == code


def test_multi_rule_single_pass():
    code = (
        "import hashlib\n"
        "import random\n"
        'API_KEY = "sk-hardcoded-secret-1234567890"\n'
        "d = hashlib.sha1(data)\n"
        "token = random.randint(1, 99)\n"
    )
    new, applied, _ = fix_of(code)
    assert set(applied) == {"insecure_random", "weak_hash", "hardcoded_secret"}
    assert "secrets" in new and "sha256" in new and "os.environ.get" in new


def test_code_with_docstring_keeps_it():
    code = '"""module doc"""\n' + 'API_KEY = "sk-hardcoded-secret-1234567890"\n'
    new, applied, _ = fix_of(code)
    # the docstring stays at the top
    assert new.lstrip().startswith('"""module doc"""')
    assert "import os" in new
    assert "os.environ.get" in new


def test_index_unchanged_original_if_no_fixable():
    code = "x = 1 + 2"
    new, applied, _ = fix_of(code)
    assert applied == []
    assert new == code
