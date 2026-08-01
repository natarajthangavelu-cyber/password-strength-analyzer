import string

from src.suggestions import generate_strong_password, generate_passphrase, strengthen_password


def test_generate_strong_password_length():
    pwd = generate_strong_password(20)
    assert len(pwd) == 20


def test_generate_strong_password_has_all_char_types():
    pwd = generate_strong_password(16)
    assert any(c in string.ascii_lowercase for c in pwd)
    assert any(c in string.ascii_uppercase for c in pwd)
    assert any(c in string.digits for c in pwd)


def test_generate_strong_password_minimum_length_enforced():
    pwd = generate_strong_password(4)
    assert len(pwd) >= 8


def test_generate_passphrase_word_count():
    phrase = generate_passphrase(4)
    assert len(phrase.split("-")) == 5


def test_strengthen_password_adds_missing_types():
    strengthened = strengthen_password("lowercaseonly")
    assert any(c in string.ascii_uppercase for c in strengthened)
    assert any(c in string.digits for c in strengthened)


def test_strengthen_password_meets_min_length():
    strengthened = strengthen_password("ab")
    assert len(strengthened) >= 12
