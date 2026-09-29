import unittest

from src.services.spam_analyzer import analyze_spam_headers


class SpamAnalyzerRegressionTests(unittest.TestCase):
    def test_non_finite_scores_are_not_accepted(self):
        for token in ("nan", "inf", "-inf"):
            with self.subTest(token=token):
                spam = analyze_spam_headers(
                    [("X-Spam-Status", f"No, score={token} required=5.0")]
                )

                self.assertIsNone(spam.score)
                self.assertEqual(spam.required_score, 5.0)


if __name__ == "__main__":
    unittest.main()
