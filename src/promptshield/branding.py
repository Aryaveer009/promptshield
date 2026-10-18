"""Author credit and responsible-use text shared by the CLI, reports and docs."""

from __future__ import annotations

from promptshield import __version__

AUTHOR_NAME = "Aryaveer Mankotia"
AUTHOR_URL = "https://github.com/Aryaveer009"
REPO_URL = "https://github.com/Aryaveer009/promptshield"
CREDIT_LINE = f"Built by {AUTHOR_NAME}"

RESPONSIBLE_USE_NOTICE = (
    "Responsible use: run PromptShield only against LLM applications you own or have explicit "
    "written permission to test. Attacking systems without authorization may be illegal."
)

ASCII_LOGO = r"""
 ____                           _   ____  _     _      _     _
|  _ \ _ __ ___  _ __ ___  _ __ | |_/ ___|| |__ (_) ___| | __| |
| |_) | '__/ _ \| '_ ` _ \| '_ \| __\___ \| '_ \| |/ _ \ |/ _` |
|  __/| | | (_) | | | | | | |_) | |_ ___) | | | | |  __/ | (_| |
|_|   |_|  \___/|_| |_| |_| .__/ \__|____/|_| |_|_|\___|_|\__,_|
                          |_|
""".strip("\n")

VERSION = __version__
