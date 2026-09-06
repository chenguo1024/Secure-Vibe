"""tests/test_iac.py — Dockerfile/Kubernetes/Terraform IaC rule tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validator import Validator, normalize_language  # noqa: E402


def validate(code: str, language: str):
    return Validator(language).validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


# --- language normalization ---

def test_language_normalization_iac():
    assert normalize_language("docker") == "dockerfile"
    assert normalize_language("containerfile") == "dockerfile"
    assert normalize_language("k8s") == "kubernetes"
    assert normalize_language("kube") == "kubernetes"
    assert normalize_language("tf") == "terraform"
    assert normalize_language("hcl") == "terraform"


# --- Dockerfile ---

def test_docker_detects_root_user():
    code = "FROM alpine:3.20\nUSER root"
    assert "DOCK-001" in ids(validate(code, "dockerfile"))


def test_docker_detects_secret_env():
    code = "FROM alpine:3.20\nENV API_KEY=sk-abcdef123456"
    assert "DOCK-002" in ids(validate(code, "dockerfile"))


def test_docker_detects_curl_pipe_sh():
    code = "RUN curl -s http://x | " + "bash"
    assert "DOCK-003" in ids(validate(code, "dockerfile"))


def test_docker_detects_remote_add():
    code = "FROM alpine:3.20\nADD https://x/file.tar.gz /app/"
    assert "DOCK-004" in ids(validate(code, "dockerfile"))


def test_docker_detects_latest_tag():
    code = "FROM python:latest"
    assert "DOCK-005" in ids(validate(code, "dockerfile"))


def test_docker_safe_passes():
    code = "FROM alpine:3.20\nRUN adduser -D appuser\nUSER appuser"
    assert validate(code, "dockerfile").passed


# --- Kubernetes ---

def test_k8s_detects_privileged():
    code = "securityContext:\n  privileged: true"
    assert "K8S-001" in ids(validate(code, "kubernetes"))


def test_k8s_detects_hostpath():
    code = "volumes:\n- name: h\n  hostPath:\n    path: /"
    assert "K8S-002" in ids(validate(code, "kubernetes"))


def test_k8s_detects_host_network():
    code = "spec:\n  hostNetwork: true\n  hostPID: true"
    assert "K8S-003" in ids(validate(code, "kubernetes"))


def test_k8s_detects_run_as_root():
    code = "securityContext:\n  runAsUser: 0\n  allowPrivilegeEscalation: true"
    assert "K8S-004" in ids(validate(code, "kubernetes"))


def test_k8s_safe_passes():
    code = (
        "securityContext:\n"
        "  runAsNonRoot: true\n"
        "  allowPrivilegeEscalation: false\n"
        "  readOnlyRootFilesystem: true\n"
    )
    assert validate(code, "kubernetes").passed


# --- Terraform ---

def test_tf_detects_open_cidr():
    code = 'resource "aws_security_group" "x" {\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'
    assert "TF-001" in ids(validate(code, "terraform"))


def test_tf_detects_public_rds():
    code = 'resource "aws_db_instance" "d" { publicly_accessible = true }'
    assert "TF-003" in ids(validate(code, "terraform"))


def test_tf_detects_secret_default():
    code = 'variable "db_password" { default = "real-secret-123456789" }'
    assert "TF-004" in ids(validate(code, "terraform"))


def test_tf_safe_passes():
    code = (
        'resource "aws_security_group" "x" {\n'
        '  ingress {\n'
        '    cidr_blocks = ["10.0.0.0/8"]\n'
        '    from_port = 443\n'
        '    to_port = 443\n'
        '  }\n'
        '}\n'
    )
    assert validate(code, "terraform").passed
