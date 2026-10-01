"""test_hashing.py - automatic tests for src/security_toolkit/hashing.py

"""

import hashlib
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.hashing import hash_file, verify_file


class TestHashing(unittest.TestCase):
    """Every method whose name starts with 'test' is one test."""

    def make_file(self, content):
        """Helper (not a test): write bytes into a temporary file, return its path."""
        handle, path = tempfile.mkstemp()  
        os.close(handle)                   
        with open(path, "wb") as f:        
            f.write(content)
        self.addCleanup(os.remove, path)   
        return path

    def test_known_sha256(self):        
        path = self.make_file(b"hello")
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        self.assertEqual(hash_file(path), expected)

    def test_empty_file(self):        
        path = self.make_file(b"")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(hash_file(path), expected)

    def test_same_content_gives_same_hash(self):
        first = self.make_file(b"same content")
        second = self.make_file(b"same content")
        self.assertEqual(hash_file(first), hash_file(second))

    def test_one_changed_letter_gives_different_hash(self):
        original = self.make_file(b"hello")
        changed = self.make_file(b"hellp")  
        self.assertNotEqual(hash_file(original), hash_file(changed))

    def test_big_file_is_read_in_several_chunks(self):
        data = b"a" * 200000
        path = self.make_file(data)
        self.assertEqual(hash_file(path), hashlib.sha256(data).hexdigest())

    def test_md5_when_asked(self):
        path = self.make_file(b"hello")
        self.assertEqual(hash_file(path, "md5"), "5d41402abc4b2a76b9719d911017c592")

    def test_verify_accepts_correct_hash(self):
        path = self.make_file(b"hello")
        correct = hash_file(path)
        self.assertTrue(verify_file(path, correct))

    def test_verify_rejects_wrong_hash(self):
        path = self.make_file(b"hello")
        self.assertFalse(verify_file(path, "0" * 64))

    def test_verify_ignores_capitals_and_spaces(self):
        path = self.make_file(b"hello")
        messy = "  " + hash_file(path).upper() + "  "
        self.assertTrue(verify_file(path, messy))

    def test_missing_file_raises_error(self):       
        with self.assertRaises(FileNotFoundError):
            hash_file("this_file_does_not_exist.txt")

    def test_unknown_algorithm_raises_error(self):
        path = self.make_file(b"hello")
        with self.assertRaises(ValueError):
            hash_file(path, "banana")


if __name__ == "__main__":
    unittest.main()
