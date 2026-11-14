# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the shared OpsCryer UI theme and navigation bar module."""

from __future__ import annotations

import unittest

from route_registry import HTML_PORTAL_ROUTES
from ui_theme import (
    SHARED_PORTAL_LINKS,
    get_ui_theme_manifest,
    render_shared_portal_css,
    render_shared_portal_nav,
)


class UIThemeTests(unittest.TestCase):
    def test_shared_portal_links_cover_all_registered_html_portals(self) -> None:
        nav_routes = {href for href, _ in SHARED_PORTAL_LINKS}
        registered_routes = {entry["path"] for entry in HTML_PORTAL_ROUTES}
        self.assertEqual(nav_routes, registered_routes)
        manifest = get_ui_theme_manifest()
        self.assertEqual(manifest["portal_count"], len(HTML_PORTAL_ROUTES))
        self.assertEqual(manifest["responsive_breakpoint_px"], 1100)

    def test_css_and_nav_render_cleanly_with_current_page_aria(self) -> None:
        css = render_shared_portal_css()
        self.assertIn("--bg:#070d17", css)
        self.assertIn("@media (max-width:1100px)", css)
        nav_html = render_shared_portal_nav("/jev-eval")
        self.assertIn('href="/jev-eval" aria-current="page"', nav_html)
        self.assertEqual(nav_html.count('aria-current="page"'), 1)


if __name__ == "__main__":
    unittest.main()
