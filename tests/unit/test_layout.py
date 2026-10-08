import ast
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parents[1]
LAYERS = {"unit", "integration", "e2e"}


def layer_marks(function):
    return {
        (decorator.func if isinstance(decorator, ast.Call) else decorator).attr
        for decorator in function.decorator_list
        if isinstance(decorator.func if isinstance(decorator, ast.Call) else decorator, ast.Attribute)
    } & LAYERS


def defined_tests(path):
    return [
        node for node in ast.parse(path.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    ]


@pytest.mark.unit
def test_every_test_marker_matches_its_directory():
    assert [
        f"{path.relative_to(TESTS_DIR)}::{function.name} has {sorted(layer_marks(function))}"
        for path in sorted(TESTS_DIR.rglob("test_*.py"))
        for function in defined_tests(path)
        if layer_marks(function) != {path.relative_to(TESTS_DIR).parts[0]}
    ] == []
