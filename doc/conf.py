# Sphinx configuration for the Open Bastion documentation.
#
# Two parts live in this one project: the English technical documentation at
# the top level, and the French EBIOS Risk Manager security study under
# security/. Build it with `sphinx-build -W -b html doc <outdir>`, or through
# CMake with -DBUILD_DOC=ON.
import importlib.util
import os
import re

from sphinx.util import logging

logger = logging.getLogger("open-bastion.man")

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.dirname(HERE)

project = "Open Bastion"
# Shown in the HTML footer, and emitted as the COPYRIGHT section of every
# generated man page, which is why the licence is part of it: the man pages
# carry no copyright section of their own.
copyright = "2025-2026, Linagora. License: AGPL-3.0+"
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
    "collapse_navigation": True,
    "navigation_depth": 3,
    "prev_next_buttons_location": "bottom"
} if _rtd else {}

html_title = "Open Bastion %s" % version if version else "Open Bastion"
# The reST sources live in the repository; a copy inside the HTML build only
# makes the -doc package bigger.
html_copy_source = False
html_show_sourcelink = False
htmlhelp_basename = "open-bastion-doc"
html_static_path = ["_static"]
html_css_files = ["custom.css"]

manpages_url = "https://manpages.debian.org/{path}"

# The troff man pages the packages install are generated from these documents
# by the `man` builder, one file per entry: (document, name, description,
# authors, section). The description becomes the man page's NAME line; the
# reST documents carry no NAME section of their own. ob-backend-setup(8) and
# ob-standalone-setup(8) document the same program as ob-bastion-setup(8): its
# page lists them in NAME (man_name_aliases below) and they are installed as
# symlinks to it — see the `man` target in CMakeLists.txt.
man_pages = [
    ("references/man/ob-bastion-id", "ob-bastion-id",
     "Print this bastion's identifier (as seen by backends)", "", 1),
    ("references/man/ob-bastion-setup", "ob-bastion-setup",
     "Configure a server as an Open Bastion node with LemonLDAP::NG", "", 8),
    ("references/man/ob-builder", "ob-builder",
     "Generate Open Bastion deployment artefacts", "", 1),
    ("references/man/ob-cache-admin", "ob-cache-admin",
     "Administer the offline credential cache", "", 8),
    ("references/man/ob-cert-daemon", "ob-cert-daemon",
     "Privileged bastion hop-certificate minting service", "", 8),
    ("references/man/ob-cert-request", "ob-cert-request",
     "Unprivileged client for the bastion certificate socket", "", 1),
    ("references/man/ob-client-jwt", "ob-client-jwt",
     "Print a client_secret_jwt assertion without putting the secret on a "
     "command line", "", 8),
    ("references/man/ob-desktop-setup", "ob-desktop-setup",
     "Configure a workstation to log in through LemonLDAP::NG", "", 8),
    ("references/man/ob-enroll", "ob-enroll",
     "Enroll a server with LemonLDAP::NG for PAM authentication", "", 8),
    ("references/man/ob-fp-daemon", "ob-fp-daemon",
     "Privileged sink for the SSH key fingerprint spool", "", 8),
    ("references/man/ob-fp-submit", "ob-fp-submit",
     "Deposit an SSH key fingerprint with ob-fp-daemon", "", 8),
    ("references/man/ob-heartbeat", "ob-heartbeat",
     "Send heartbeat to LemonLDAP::NG server", "", 8),
    ("references/man/ob-krl-refresh", "ob-krl-refresh",
     "Refresh the SSH key revocation list from the portal", "", 8),
    ("references/man/ob-login-shell", "ob-login-shell",
     "Login shell of SSO users on a host that records sessions", "", 8),
    ("references/man/ob-post-upgrade", "ob-post-upgrade",
     "Finish an Open Bastion package upgrade on this host", "", 8),
    ("references/man/ob-record-connect", "ob-record-connect",
     "Unprivileged connector for the session-recording sink", "", 1),
    ("references/man/ob-record-sink", "ob-record-sink",
     "Privileged session-recording sink", "", 8),
    ("references/man/ob-scp", "ob-scp",
     "Bastion file copy to/from/between backends with LLNG certificate "
     "vouching", "", 1),
    ("references/man/ob-session-prune", "ob-session-prune",
     "Compress and expire recorded SSH sessions", "", 8),
    ("references/man/ob-session-monitor", "ob-session-monitor",
     "Revalidate offline sessions once the portal is reachable", "", 8),
    ("references/man/ob-session-recorder", "ob-session-recorder",
     "Record SSH sessions on an Open Bastion host", "", 8),
    ("references/man/ob-sftp", "ob-sftp",
     "Bastion SFTP to a backend with LLNG certificate vouching", "", 1),
    ("references/man/ob-sign-request", "ob-sign-request",
     "Compute the request-signing headers for a /pam/ portal call", "", 8),
    ("references/man/ob-ssh", "ob-ssh",
     "Bastion-to-backend SSH connector with LLNG certificate vouching", "", 1),
    ("references/man/ob-ssh-cert", "ob-ssh-cert",
     "Obtain an SSH certificate from LemonLDAP::NG without a browser", "", 8),
    ("references/man/ob-uninstall", "ob-uninstall",
     "Take Open Bastion off this host, ready for package removal", "", 8),
    ("references/man/openbastion.conf", "openbastion.conf",
     "Configuration file of the Open Bastion PAM module", "", 5),
]

# A man page's NAME line lists every name its command is installed
# under. The man builder derives the whole line — file name included —
# from the man_pages entry, so the aliases are added to the generated
# page once it is written, in _append_man_name_aliases() below.
man_name_aliases = {
    "ob-bastion-setup": ("ob-backend-setup", "ob-standalone-setup"),
}


def _append_man_name_aliases(app, exception):
    """List an aliased command's other names in its man page NAME line."""
    if app.builder.format != "man" or exception:
        return

    for _docname, name, _description, _authors, section in app.config.man_pages:
        aliases = man_name_aliases.get(name)
        if not aliases:
            continue

        path = os.path.join(app.outdir, "%s.%s" % (name, section))
        with open(path, encoding="utf-8") as fh:
            page = fh.read()

        before = ".SH NAME\n%s \\- " % name
        after = ".SH NAME\n%s, %s \\- " % (name, ", ".join(aliases))
        if before not in page:
            logger.warning("no NAME line to extend in %s: whatis(1) and "
                           "apropos(1) will not find %s",
                           path, ", ".join(aliases))
            continue

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(page.replace(before, after, 1))


def _drop_uri_less_reference_targets(app, doctree, docname):
    """Keep the man pages free of empty link targets.

    A reference whose target is another document resolves to no URI at all
    in the man builder, and the man writer then prints its target as an
    empty ``<>`` after the link text — "ob-bastion-setup(8) <>". Removing
    the empty ``refuri`` leaves the link text alone. External targets, such
    as the ``:manpage:`` URLs, are kept and printed as before.
    """
    if app.builder.format != "man":
        return

    from docutils import nodes
    # findall() is docutils >= 0.18.1; EL9 ships an older one (Sphinx 3.4).
    for node in getattr(doctree, "findall", doctree.traverse)(nodes.reference):
        if not node.get("refuri"):
            node.attributes.pop("refuri", None)


def setup(app):
    app.connect("doctree-resolved", _drop_uri_less_reference_targets)
    app.connect("build-finished", _append_man_name_aliases)

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
