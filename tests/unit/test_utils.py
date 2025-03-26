import unittest
from galv_cdk.utils import inject_protected_env  # Adjust import path as needed

class TestInjectProtectedEnv(unittest.TestCase):

    def test_injects_new_keys(self):
        env = {"EXISTING": "1"}
        protected = {"SAFE_KEY": "safe"}
        inject_protected_env(env, protected)
        self.assertEqual(env["SAFE_KEY"], "safe")
        self.assertEqual(env["EXISTING"], "1")  # Ensure existing keys are preserved

    def test_raises_on_conflict(self):
        env = {"CLASH": "old"}
        protected = {"CLASH": "new"}
        with self.assertRaises(ValueError) as cm:
            inject_protected_env(env, protected)

        self.assertIn("CLASH", str(cm.exception))
