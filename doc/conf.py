# Sphinx configuration for the Open Bastion documentation.
#
# Two parts live in this one project: the English technical documentation at
# the top level, and the French EBIOS Risk Manager security study under
# security/. Build it with `sphinx-build -W -b html doc <outdir>`, or through
# CMake with -DBUILD_DOC=ON.
import importlib.util
import os
import re

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.dirname(HERE)

project = "Open Bastion"
copyright = "2025-2026, Linagora"
author = "Linagora"


def _version():
    """Single source of truth: the version CMake declares."""
    try:
        with open(os.path.join(REPO, "CMakeLists.txt")) as fh:
            m = re.search(r"project\(open-bastion VERSION ([0-9.]+)", fh.read())
        return m.group(1) if m else ""
    except OSError:
        return ""


version = release = _version()

root_doc = "index"
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# The study under security/ is French, the rest is English. Sphinx has one
# language per project, so the generated UI strings stay English and each page
# speaks for itself.
language = "en"


def _installed(module):
    """True when `module` can be imported, without importing it."""
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


# sphinxcontrib-mermaid is not in every distribution we build on, so it is not
# a build-dependency. Without it the diagrams stay readable as their source --
# what every renderer but GitHub showed of the Markdown originals -- and
# setup() below keeps the directive defined, so no document has to know which
# of the two is installed.
_mermaid = _installed("sphinxcontrib.mermaid")
extensions = ["sphinxcontrib.mermaid"] if _mermaid else []

# Shared with the repository README, which needs it at the root; Sphinx
# resolves html_logo relative to this directory and copies it into the build.
html_logo = "../linagora.png"

# python3-sphinx-rtd-theme is a build-dependency of the Debian packages, but a
# checkout with Sphinx alone still builds, on the stock theme.
_rtd = _installed("sphinx_rtd_theme")
html_theme = "sphinx_rtd_theme" if _rtd else "alabaster"
html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 3,
} if _rtd else {}

html_title = "Open Bastion %s" % version if version else "Open Bastion"
# The reST sources live in the repository; a copy inside the HTML build only
# makes the -doc package bigger.
html_copy_source = False
html_show_sourcelink = False
htmlhelp_basename = "open-bastion-doc"


def setup(app):
    if _mermaid:
        return

    from docutils import nodes
    from docutils.parsers.rst import Directive

    class MermaidFallback(Directive):
        """`.. mermaid::` as a literal block, for builds without the extension."""

        has_content = True
        optional_arguments = 1
        final_argument_whitespace = True
        option_spec = {}

        def run(self):
            text = "\n".join(self.content)
            node = nodes.literal_block(text, text)
            node["language"] = "text"
            return [node]

    app.add_directive("mermaid", MermaidFallback)
