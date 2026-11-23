"""Package-level smoke tests: cybersecuritykit imports cleanly and every declared
subpackage re-exports a consistent public API."""

import importlib
import ipaddress

import pytest

import cybersecuritykit as csk

SUBPACKAGES = [
    "classical",
    "symmetric",
    "pqc",
    "protocols",
    "auth",
    "access",
    "software",
    "sidechannel",
    "malware",
    "network",
    "detection",
    "privacy",
    "risk",
]


def test_top_level_import_exposes_declared_names():
    for name in csk.__all__:
        assert hasattr(csk, name), f"cybersecuritykit.{name} listed in __all__ but not importable"


def test_every_subpackage_is_declared():
    assert set(SUBPACKAGES) <= set(csk.__all__)


def test_version_is_a_dotted_string():
    assert isinstance(csk.__version__, str)
    assert csk.__version__.count(".") == 2


@pytest.mark.parametrize("subpackage", SUBPACKAGES)
def test_subpackage_all_resolves(subpackage):
    module = getattr(csk, subpackage)
    for name in module.__all__:
        assert hasattr(module, name), f"cybersecuritykit.{subpackage}.{name} is not importable"


@pytest.mark.parametrize("subpackage", SUBPACKAGES)
@pytest.mark.parametrize("layer", ["core", "core.base", "systems"])
def test_every_layer_name_is_reexported_by_its_subpackage(subpackage, layer):
    module = getattr(csk, subpackage)
    inner = importlib.import_module(f"cybersecuritykit.{subpackage}.{layer}")
    missing = set(inner.__all__) - set(module.__all__)
    assert not missing, f"cybersecuritykit.{subpackage} does not re-export {sorted(missing)}"


@pytest.mark.parametrize("subpackage", SUBPACKAGES)
def test_plot_functions_are_declared(subpackage):
    plots = importlib.import_module(f"cybersecuritykit.{subpackage}.visualizers.plots")
    for name in plots.__all__:
        assert callable(getattr(plots, name)), f"{subpackage}.visualizers.plots.{name}"


def test_constants_match_their_documented_values():
    assert csk.constants.DEFAULT_SEED == csk.DEFAULT_SEED == 2026
    assert "".join(chr(c) for c in range(ord("A"), ord("Z") + 1)) == csk.constants.ALPHABET
    assert csk.constants.EXAMPLE_DOMAIN.endswith(".test")


def test_simulated_networks_are_reserved_for_documentation():
    # Simulated hosts must never collide with a routable address.
    for block in csk.constants.DOCUMENTATION_NETWORKS:
        network = ipaddress.ip_network(block)
        assert network.is_private and not network.is_global


def test_importing_cybersecuritykit_does_not_load_matplotlib():
    # Visualizers are opt-in; the library code must stay standard-library only.
    import subprocess
    import sys

    code = (
        "import sys, cybersecuritykit; print('matplotlib' in sys.modules, 'numpy' in sys.modules)"
    )
    output = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert output.stdout.split() == ["False", "False"]
