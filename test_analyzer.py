import unittest
from password_analyzer import PasswordAnalyzer

class TestPasswordAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_empty_password(self):
        res = self.analyzer.analyze("", check_breach=False)
        self.assertEqual(res['score'], 0)
        self.assertEqual(res['password_length'], 0)
        self.assertEqual(res['entropy']['pool_size'], 0)

    def test_weak_password(self):
        res = self.analyzer.analyze("123456", check_breach=False)
        self.assertLess(res['score'], 30)
        self.assertEqual(res['rating_tier'], "Very Weak")
        # Check alerts contains pattern or dictionary warning
        has_alert = any(a['type'] == 'danger' for a in res['alerts'])
        self.assertTrue(has_alert)

    def test_strong_password(self):
        res = self.analyzer.analyze("Xk9#mP$2vL!8qZ@1nW", check_breach=False)
        self.assertGreaterEqual(res['score'], 80)
        self.assertIn(res['rating_tier'], ["Strong", "Extremely Fortified"])

    def test_entropy_calculation(self):
        pwd = "abcd"
        entropy = self.analyzer.calculate_entropy(pwd)
        self.assertEqual(entropy['pool_size'], 26)
        # Shannon entropy of 'abcd' with distinct chars is log2(4) = 2.0 per char -> total 8.0 bits
        self.assertEqual(entropy['shannon'], 8.0)

    def test_character_composition(self):
        pwd = "Aa1!"
        comp = self.analyzer.get_character_composition(pwd)
        self.assertEqual(comp['lowercase']['count'], 1)
        self.assertEqual(comp['uppercase']['count'], 1)
        self.assertEqual(comp['numbers']['count'], 1)
        self.assertEqual(comp['symbols']['count'], 1)

if __name__ == '__main__':
    unittest.main()
