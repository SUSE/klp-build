import unittest

from klpbuild.ksrc import GitHelper


class GitHelperTesting(unittest.TestCase):
    def test_multiline_upstream_commit_subject(self):
        _, subj = GitHelper.get_commit_data("49c47cc21b5b")
        self.assertEqual(
            "net: tls: fix possible race condition between " "do_tls_getsockopt_conf() and do_tls_setsockopt_conf()",
            subj,
        )


if __name__ == "__main__":
    unittest.main()
