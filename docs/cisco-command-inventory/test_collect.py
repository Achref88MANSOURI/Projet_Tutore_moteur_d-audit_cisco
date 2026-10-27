"""Offline checks of research extraction; no application code is imported."""
import unittest

from collect import DOM, extract


def article(name, syntax, modes):
    return f'''<article class="topic reference nested1" id="cmd1">
    <h2>{name}</h2><section class="refsyn">{syntax}</section>
    <section class="command_modes"><h3>Command Modes</h3>{modes}</section>
    <section class="command_history"><table><tr><th>Release</th><th>Modification</th></tr>
    <tr><td>12.4(1)T</td><td>This command was introduced.</td></tr></table></section></article>'''


class ExtractionTests(unittest.TestCase):
    def parse(self, html):
        return extract(DOM(html).root, {"url": "https://www.cisco.com/example.html", "status": "ok", "sha256": "a" * 64, "retrieved_at": "2026-10-27T00:00:00Z"},
                       {"id": "test", "technology": "test", "os_families": ["IOS"]})

    def test_inline_whitespace_and_literal_brackets_survive(self):
        html = article("ip address", '<p><b>ip</b> <b>address</b> <var>address</var> <var>mask</var> [secondary]</p><p>no ip address</p>', '<p>Interface configuration (config-if)</p>')
        inc, exc, errs = self.parse(html)
        self.assertFalse(exc or errs)
        self.assertEqual(inc[0]["syntaxes"], ["ip address address mask [secondary]", "no ip address"])
        self.assertEqual(inc[0]["documented_forms"], ["no", "positive"])
        self.assertEqual(inc[0]["release_history"][0]["change_kinds"], ["introduced"])
        self.assertEqual(inc[0]["confidence"]["persistence"], "unknown")

    def test_does_not_invent_no_or_default(self):
        inc, _, _ = self.parse(article("hostname", "<p>hostname name</p>", "<p>Global configuration</p>"))
        self.assertEqual(inc[0]["documented_forms"], ["positive"])
        self.assertIsNone(inc[0]["context_path"])

    def test_explicit_html_line_break_separates_forms(self):
        inc, _, _ = self.parse(article("shutdown", "<p>shutdown<br/>no shutdown</p>", "<p>Interface configuration</p>"))
        self.assertEqual(inc[0]["syntaxes"], ["shutdown", "no shutdown"])
        self.assertEqual(inc[0]["documented_forms"], ["no", "positive"])

    def test_html_line_wrap_does_not_invent_a_new_command(self):
        inc, _, _ = self.parse(article("ip route", "<p>ip route prefix mask<br/>[distance]</p>", "<p>Global configuration</p>"))
        self.assertEqual(inc[0]["syntaxes"], ["ip route prefix mask [distance]"])

    def test_exec_is_excluded_even_if_config_mode_is_listed(self):
        inc, exc, _ = self.parse(article("show ip route", "<p>show ip route</p>", "<p>Privileged EXEC and global configuration</p>"))
        self.assertFalse(inc)
        self.assertEqual(exc[0]["reason"], "operational_command_even_if_config_mode_listed")

    def test_exec_without_config_is_excluded(self):
        inc, exc, _ = self.parse(article("copy", "<p>copy source destination</p>", "<p>Privileged EXEC</p>"))
        self.assertFalse(inc)
        self.assertEqual(exc[0]["reason"], "no_configuration_mode_documented")

    def test_missing_syntax_is_an_anomaly(self):
        inc, _, errs = self.parse(article("unknown", "", "<p>Global configuration</p>"))
        self.assertFalse(inc)
        self.assertEqual(errs[0]["reason"], "missing_syntax")

    def test_unknown_mode_is_not_promoted(self):
        inc, _, errs = self.parse(article("unknown", "<p>unknown</p>", ""))
        self.assertFalse(inc)
        self.assertTrue(errs)

    def test_document_redirect_is_not_extracted(self):
        inc, exc, errs = extract(DOM("<h1>Cisco Support</h1>").root, {"status": "redirected_to_support"}, {})
        self.assertFalse(inc or exc or errs)

    def test_legacy_anonymous_sections_are_supported(self):
        html = '''<section class="nested1" id="legacy"><h2>router rip</h2><section>
        <section><p>To enable RIP, use this command.</p></section>
        <section><p><b>router</b> <b>rip</b></p><p><b>no</b> <b>router rip</b></p></section>
        <section><h2>Syntax Description</h2><p>No arguments.</p></section>
        <section><h2>Command Modes</h2><p>Global configuration</p></section></section></section>'''
        inc, exc, errs = self.parse(html)
        self.assertFalse(exc or errs)
        self.assertEqual(inc[0]["syntaxes"], ["router rip", "no router rip"])

    def test_legacy_description_is_not_used_as_syntax(self):
        html = '''<section class="nested1" id="legacy"><h2>missing</h2><section>
        <section><p>To enable a feature, use a command.</p></section>
        <section><h2>Syntax Description</h2><p>No arguments.</p></section>
        <section><h2>Command Modes</h2><p>Global configuration</p></section></section></section>'''
        inc, _, errs = self.parse(html)
        self.assertFalse(inc)
        self.assertEqual(errs[0]["reason"], "missing_syntax")

    def test_identical_duplicate_html_articles_are_logged_once(self):
        html = article("hostname", "<p>hostname name</p>", "<p>Global configuration</p>")
        inc, _, errs = self.parse(html + html)
        self.assertEqual(len(inc), 1)
        self.assertEqual(errs[0]["reason"], "duplicate_identical_html_article_ignored")


if __name__ == "__main__":
    unittest.main()
