"""Sphinx configuration for cybersecuritykit."""

import os
import re
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _release():
    """Installed distribution version, falling back to cybersecuritykit/__init__.py.

    The metadata lookup only succeeds when cybersecuritykit is installed, so a
    docs build from a fresh clone would otherwise die with PackageNotFoundError.
    """
    try:
        return _dist_version("cybersecuritykit")
    except PackageNotFoundError:
        init = Path(__file__).resolve().parents[2] / "cybersecuritykit" / "__init__.py"
        return re.search(r'^__version__\s*=\s*"([^"]+)"', init.read_text(), re.M).group(1)


project = "cybersecuritykit"
author = "Charles Poli"
copyright = "2026, Charles Poli"
release = _release()
del _release

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",  # NumPy-style docstrings
    "sphinx.ext.mathjax",
    "sphinx.ext.doctest",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "myst_parser",
    "sphinx_gallery.gen_gallery",
    "sphinx_design",
    "jupyterlite_sphinx",
    "sphinx_sitemap",
    "sphinxext.opengraph",
]

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "api/gallery/**/*.ipynb"]

napoleon_google_docstring = False
napoleon_numpy_docstring = True
napoleon_use_ivar = True
napoleon_preprocess_types = True
napoleon_type_aliases = {
    "iterable": "collections.abc.Iterable",
    "sequence": "collections.abc.Sequence",
    "mapping": "collections.abc.Mapping",
    "callable": "collections.abc.Callable",
    "collection": "collections.abc.Collection",
    "Mapping": "collections.abc.Mapping",
    # classical
    "ADFGVXBreakResult": "cybersecuritykit.classical.core.base.ADFGVXBreakResult",
    "BombeResult": "cybersecuritykit.classical.core.base.BombeResult",
    "CoincidenceProfile": "cybersecuritykit.classical.core.base.CoincidenceProfile",
    "CribDragHit": "cybersecuritykit.classical.core.base.CribDragHit",
    "CribMenu": "cybersecuritykit.classical.core.base.CribMenu",
    "EnigmaSettings": "cybersecuritykit.classical.core.base.EnigmaSettings",
    "HillBreakResult": "cybersecuritykit.classical.core.base.HillBreakResult",
    "HillClimbResult": "cybersecuritykit.classical.core.base.HillClimbResult",
    "HomophonicResult": "cybersecuritykit.classical.core.base.HomophonicResult",
    "KasiskiResult": "cybersecuritykit.classical.core.base.KasiskiResult",
    "LorenzWheels": "cybersecuritykit.classical.core.base.LorenzWheels",
    "PeriodTest": "cybersecuritykit.classical.core.base.PeriodTest",
    "PlayfairBreakResult": "cybersecuritykit.classical.core.base.PlayfairBreakResult",
    "RejewskiCharacteristic": "cybersecuritykit.classical.core.base.RejewskiCharacteristic",
    "SecrecyResult": "cybersecuritykit.classical.core.base.SecrecyResult",
    "ShiftBreakResult": "cybersecuritykit.classical.core.base.ShiftBreakResult",
    "SpuriousKeyCount": "cybersecuritykit.classical.core.base.SpuriousKeyCount",
    "UnicityResult": "cybersecuritykit.classical.core.base.UnicityResult",
    "VigenereBreakResult": "cybersecuritykit.classical.core.base.VigenereBreakResult",
    # pqc (slice A)
    "AjtaiKey": "cybersecuritykit.pqc.core.base.AjtaiKey",
    "GroverResult": "cybersecuritykit.pqc.core.base.GroverResult",
    "KyberCiphertext": "cybersecuritykit.pqc.core.base.KyberCiphertext",
    "KyberEncapsulation": "cybersecuritykit.pqc.core.base.KyberEncapsulation",
    "KyberKeyPair": "cybersecuritykit.pqc.core.base.KyberKeyPair",
    "KyberPublicKey": "cybersecuritykit.pqc.core.base.KyberPublicKey",
    "LLLResult": "cybersecuritykit.pqc.core.base.LLLResult",
    "LWEAttackResult": "cybersecuritykit.pqc.core.base.LWEAttackResult",
    "LWECiphertext": "cybersecuritykit.pqc.core.base.LWECiphertext",
    "LWEKeyPair": "cybersecuritykit.pqc.core.base.LWEKeyPair",
    "LWEPublicKey": "cybersecuritykit.pqc.core.base.LWEPublicKey",
    "LyubashevskyKeyPair": "cybersecuritykit.pqc.core.base.LyubashevskyKeyPair",
    "LyubashevskyPublicKey": "cybersecuritykit.pqc.core.base.LyubashevskyPublicKey",
    "LyubashevskySignature": "cybersecuritykit.pqc.core.base.LyubashevskySignature",
    "NTRUAttackResult": "cybersecuritykit.pqc.core.base.NTRUAttackResult",
    "NTRUKeyPair": "cybersecuritykit.pqc.core.base.NTRUKeyPair",
    "NTRUPublicKey": "cybersecuritykit.pqc.core.base.NTRUPublicKey",
    "RingLWECiphertext": "cybersecuritykit.pqc.core.base.RingLWECiphertext",
    "RingLWEKeyPair": "cybersecuritykit.pqc.core.base.RingLWEKeyPair",
    "RingLWEPublicKey": "cybersecuritykit.pqc.core.base.RingLWEPublicKey",
    "SISCollision": "cybersecuritykit.pqc.core.base.SISCollision",
    "ShorResult": "cybersecuritykit.pqc.core.base.ShorResult",
    "SignatureLeakage": "cybersecuritykit.pqc.core.base.SignatureLeakage",
    # end pqc (slice A)
    # pqc (slice C)
    "HORSTForgery": "cybersecuritykit.pqc.core.base.HORSTForgery",
    "HORSTKey": "cybersecuritykit.pqc.core.base.HORSTKey",
    "HORSTPublicKey": "cybersecuritykit.pqc.core.base.HORSTPublicKey",
    "HORSTSignature": "cybersecuritykit.pqc.core.base.HORSTSignature",
    "SPHINCSKey": "cybersecuritykit.pqc.core.base.SPHINCSKey",
    "SPHINCSPublicKey": "cybersecuritykit.pqc.core.base.SPHINCSPublicKey",
    "SPHINCSSignature": "cybersecuritykit.pqc.core.base.SPHINCSSignature",
    "WinternitzCost": "cybersecuritykit.pqc.core.base.WinternitzCost",
    "WinternitzForgery": "cybersecuritykit.pqc.core.base.WinternitzForgery",
    "WinternitzKey": "cybersecuritykit.pqc.core.base.WinternitzKey",
    "WinternitzPublicKey": "cybersecuritykit.pqc.core.base.WinternitzPublicKey",
    "WinternitzSignature": "cybersecuritykit.pqc.core.base.WinternitzSignature",
    "XMSSForgery": "cybersecuritykit.pqc.core.base.XMSSForgery",
    "XMSSKey": "cybersecuritykit.pqc.core.base.XMSSKey",
    "XMSSPublicKey": "cybersecuritykit.pqc.core.base.XMSSPublicKey",
    "XMSSSignature": "cybersecuritykit.pqc.core.base.XMSSSignature",
    "XMSSSigned": "cybersecuritykit.pqc.core.base.XMSSSigned",
    # end pqc (slice C)
    # pqc (slice B)
    "GoppaCode": "cybersecuritykit.pqc.core.base.GoppaCode",
    "ISDResult": "cybersecuritykit.pqc.core.base.ISDResult",
    "LinearizationResult": "cybersecuritykit.pqc.core.base.LinearizationResult",
    "MatsumotoImaiKeyPair": "cybersecuritykit.pqc.core.base.MatsumotoImaiKeyPair",
    "MatsumotoImaiPrivateKey": "cybersecuritykit.pqc.core.base.MatsumotoImaiPrivateKey",
    "McElieceBreakResult": "cybersecuritykit.pqc.core.base.McElieceBreakResult",
    "McElieceKeyPair": "cybersecuritykit.pqc.core.base.McElieceKeyPair",
    "McEliecePrivateKey": "cybersecuritykit.pqc.core.base.McEliecePrivateKey",
    "McEliecePublicKey": "cybersecuritykit.pqc.core.base.McEliecePublicKey",
    "NiederreiterKeyPair": "cybersecuritykit.pqc.core.base.NiederreiterKeyPair",
    "NiederreiterPrivateKey": "cybersecuritykit.pqc.core.base.NiederreiterPrivateKey",
    "NiederreiterPublicKey": "cybersecuritykit.pqc.core.base.NiederreiterPublicKey",
    "OilVinegarKeyPair": "cybersecuritykit.pqc.core.base.OilVinegarKeyPair",
    "OilVinegarPrivateKey": "cybersecuritykit.pqc.core.base.OilVinegarPrivateKey",
    "QuadraticMap": "cybersecuritykit.pqc.core.base.QuadraticMap",
    "RainbowBreakResult": "cybersecuritykit.pqc.core.base.RainbowBreakResult",
    # end pqc (slice B)
}

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
autodoc_typehints = "description"
autodoc_member_order = "bysource"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "matplotlib": ("https://matplotlib.org/stable/", None),
}

# Every cross-reference must resolve: a broken link is a build error.
nitpicky = True
# sphinx_gallery_conf holds a function, so Sphinx cannot cache the config.
suppress_warnings = ["config.cache"]
nitpick_ignore: list[tuple[str, str]] = [
    # Type aliases are documented as module attributes, not classes; list them here.
]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# Single source of truth for the subpackages. Every card grid (homepage,
# api/index, examples/index, history/index, and the per-subpackage hub pages)
# and the cross-link strip atop each api/history page is generated from this
# table by _generate_subpackage_docs() below, ported from mathematicskit.
SUBPACKAGES = [
    {
        "name": "classical",
        "category": "Cryptography",
        "blurb": "Substitution and transposition ciphers, frequency analysis, Kasiski and the "
        "index of coincidence, rotor machines, and Shannon's perfect secrecy and unicity "
        "distance.",
    },
    {
        "name": "symmetric",
        "category": "Cryptography",
        "blurb": "Feistel networks and toy DES and AES, differential and linear cryptanalysis, "
        "modes of operation, padding oracles, MACs and authenticated encryption.",
    },
    {
        "name": "pqc",
        "category": "Cryptography",
        "blurb": "Shor's and Grover's threat models, learning with errors, toy Kyber-style "
        "encryption, McEliece, and Lamport and Merkle hash-based signatures.",
    },
    {
        "name": "protocols",
        "category": "Protocols and identity",
        "blurb": "Needham-Schroeder and Lowe's attack, the Dolev-Yao attacker, Kerberos, BAN "
        "logic, and toy TLS handshakes with downgrade and replay attacks.",
    },
    {
        "name": "auth",
        "category": "Protocols and identity",
        "blurb": "Password entropy and guessing, salted and slow hashing from crypt to Argon2, "
        "rainbow tables, HOTP and TOTP, and challenge-response.",
    },
    {
        "name": "access",
        "category": "Protocols and identity",
        "blurb": "Lampson's access matrix, Bell-LaPadula and Biba, Clark-Wilson, the HRU safety "
        "problem, role-based access control, and capability systems.",
    },
    {
        "name": "software",
        "category": "Systems",
        "blurb": "Stack smashing and return-oriented programming on a toy VM, canaries, W^X and "
        "ASLR, fuzzing, symbolic execution, and injection attacks.",
    },
    {
        "name": "sidechannel",
        "category": "Systems",
        "blurb": "Kocher's timing attack, simple and differential power analysis on synthetic "
        "traces, cache timing, fault attacks, and constant-time countermeasures.",
    },
    {
        "name": "malware",
        "category": "Systems",
        "blurb": "Cohen's undecidability result, SI and SIR worm models fitted to Morris, Code Red "
        "and Slammer, scanning strategies, botnets, and patching and quarantine.",
    },
    {
        "name": "network",
        "category": "Networks",
        "blurb": "Packet filters and rule conflicts, simulated port scans, SYN floods and SYN "
        "cookies, ARP and DNS spoofing, and traceback, all on synthetic traffic.",
    },
    {
        "name": "detection",
        "category": "Networks",
        "blurb": "Denning's IDS model, Aho-Corasick signature matching, anomaly scores, the "
        "base-rate fallacy, ROC curves, and alert correlation on synthetic logs.",
    },
    {
        "name": "privacy",
        "category": "Data and decisions",
        "blurb": "Re-identification by linkage, k-anonymity, l-diversity and t-closeness, "
        "randomized response, differential privacy and its composition, and membership "
        "inference.",
    },
    {
        "name": "risk",
        "category": "Data and decisions",
        "blurb": "Attack trees and graphs, CVSS scoring, annualized loss expectancy, the "
        "Gordon-Loeb investment model, and Stackelberg security games.",
    },
]

for _s in SUBPACKAGES:
    _s.setdefault("history_doc", f"{_s['name']}_breakthroughs")
    _s["examples_doc"] = f"api/gallery/{_s['name']}/index"
del _s

_CATEGORY_ORDER = [
    "Cryptography",
    "Protocols and identity",
    "Systems",
    "Networks",
    "Data and decisions",
]
_GALLERY_SUBPACKAGES = [s["name"] for s in SUBPACKAGES]


def _jupyterlite_install_cell(notebook_content, notebook_filename):
    """Prepend a ``%pip install`` cell so the Pyodide kernel fetches cybersecuritykit from PyPI."""
    notebook_content["cells"].insert(
        0,
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": ["%pip install cybersecuritykit"],
        },
    )


sphinx_gallery_conf = {
    "examples_dirs": [f"../../examples/{name}" for name in _GALLERY_SUBPACKAGES],
    "gallery_dirs": [f"api/gallery/{name}" for name in _GALLERY_SUBPACKAGES],
    "filename_pattern": r"/plot_",
    "download_all_examples": True,
    "within_subsection_order": "FileNameSortKey",
    "remove_config_comments": True,
    "abort_on_example_error": True,
    "image_scrapers": ("matplotlib",),
    "capture_repr": (),
    # Lets ".. minigallery::" (used throughout docs/source/history/) resolve.
    "backreferences_dir": "gen_modules/backreferences",
    "doc_module": ("cybersecuritykit",),
    # "Launch JupyterLite" button: runs the notebook in the browser on
    # Pyodide, with no server. cybersecuritykit is pure Python, so it runs there
    # unchanged once it is on PyPI.
    "jupyterlite": {
        "use_jupyter_lab": True,
        "notebook_modification_function": _jupyterlite_install_cell,
    },
    # Run the examples in one worker process per core; CYBERSECURITYKIT_GALLERY_JOBS=1
    # runs them one at a time in the Sphinx process instead.
    "parallel": int(os.environ.get("CYBERSECURITYKIT_GALLERY_JOBS", os.cpu_count() or 1)),
}

doctest_global_setup = "import cybersecuritykit as csk"

html_theme = "pydata_sphinx_theme"

# Search-engine metadata: sphinx-sitemap writes sitemap.xml with absolute
# URLs from html_baseurl, and sphinxext-opengraph adds a <meta
# name="description"> plus og:* link-preview tags from each page"s text.
# html_baseurl also gives every page a <link rel="canonical">.
html_baseurl = "https://cpoli.github.io/cybersecuritykit/"
sitemap_url_scheme = "{link}"
sitemap_excludes = [
    "search.html",
    "genindex.html",
    "py-modindex.html",
    "*sg_execution_times.html",
    "_modules/*",
    # Include-only fragments (card grids, nav strips), not standalone pages.
    "_generated/grid_*",
    "_generated/vars.html",
    "_generated/nav/*",
]
ogp_site_url = html_baseurl
ogp_site_name = project
ogp_image = html_baseurl + "_static/images/cybersecuritykit_logo.png"
ogp_social_cards = {"enable": False}

# Page-view counts with GoatCounter (no cookies, no personal data). One
# site, cpoli.goatcounter.com, covers every cpoli.github.io project; the
# URL path tells the kits apart.
html_js_files = [
    (
        "https://gc.zgo.at/count.js",
        {"async": "async", "data-goatcounter": "https://cpoli.goatcounter.com/count"},
    ),
]
html_title = "cybersecuritykit"
html_logo = "_static/images/cybersecuritykit_logo_transparent.png"
html_theme_options = {
    "github_url": "https://github.com/cpoli/cybersecuritykit",
    "icon_links": [
        {
            "name": "Charles Poli",
            "url": "https://cpoli.github.io/",
            "icon": "fa-solid fa-user",
            "type": "fontawesome",
        },
    ],
    "navbar_end": ["theme-switcher", "navbar-icon-links"],
    "show_toc_level": 2,
    "navigation_with_keys": True,
    "navigation_depth": 2,
    "logo": {
        "alt_text": "cybersecuritykit logo",
    },
}
html_static_path = ["_static"]
html_css_files = ["custom.css"]


def _card(link, blurb, link_title):
    """One sphinx-design grid-item-card, indented for a ``.. grid::`` block."""
    return (
        f"   .. grid-item-card:: {link_title}\n"
        f"      :link: {link}\n"
        "      :link-type: doc\n\n"
        f"      {blurb}\n\n"
    )


def _grid(cards):
    return ".. grid:: 1 2 3 3\n   :gutter: 2\n\n" + "".join(cards)


def _grouped_grid(link_fn):
    """A ``.. grid::`` per category, each preceded by a rubric heading."""
    parts = []
    for category in _CATEGORY_ORDER:
        members = [s for s in SUBPACKAGES if s["category"] == category]
        if not members:
            continue
        parts.append(f".. rubric:: {category}\n\n")
        parts.append(
            _grid([_card(link_fn(s), s["blurb"], f"cybersecuritykit.{s['name']}") for s in members])
        )
        parts.append("\n")
    return "".join(parts)


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _generate_subpackage_docs(app):
    """Generate the card grids, per-subpackage hub pages, and cross-link strips.

    Runs at "builder-inited", before Sphinx reads any source file that
    includes them. Everything lands under _generated/ (gitignored), since it
    is entirely derived from SUBPACKAGES.
    """
    out = Path(app.srcdir) / "_generated"
    _write(out / "vars.rst", f".. |num_subpackages| replace:: {len(SUBPACKAGES)}\n")
    _write(out / "grid_api.rst", _grouped_grid(lambda s: f"/api/{s['name']}"))
    _write(out / "grid_examples.rst", _grouped_grid(lambda s: f"/{s['examples_doc']}"))
    _write(out / "grid_history.rst", _grouped_grid(lambda s: f"/history/{s['history_doc']}"))
    _write(out / "grid_hub.rst", _grouped_grid(lambda s: f"/_generated/subpackages/{s['name']}"))

    for s in SUBPACKAGES:
        name = s["name"]
        title = f"cybersecuritykit.{name}"
        cards = _grid(
            [
                _card(
                    f"/history/{s['history_doc']}",
                    "The breakthroughs behind this subpackage, linked to the implementation.",
                    "History",
                ),
                _card(f"/{s['examples_doc']}", "The runnable example gallery.", "Examples"),
                _card(f"/api/{name}", "Every public class and function.", "API reference"),
            ]
        )
        _write(
            out / "subpackages" / f"{name}.rst",
            f"{title}\n{'=' * len(title)}\n\n{s['blurb']}\n\n{cards}",
        )

        links = [
            f":doc:`cybersecuritykit.{name} hub </_generated/subpackages/{name}>`",
            f":doc:`History </history/{s['history_doc']}>`",
            f":doc:`Examples </{s['examples_doc']}>`",
            f":doc:`API reference </api/{name}>`",
        ]
        _write(
            out / "nav" / f"{name}.rst", f".. container:: subpkg-nav\n\n   {' · '.join(links)}\n"
        )


def setup(app):
    app.connect("builder-inited", _generate_subpackage_docs)
