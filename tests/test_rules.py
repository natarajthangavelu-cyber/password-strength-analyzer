from src.rules import check_length, check_complexity, check_uniqueness, check_common_password


def test_check_length_fails_when_too_short():
    ok, _ = check_length("ab1!")
    assert ok is False


def test_check_length_passes_when_long_enough():
    ok, _ = check_length("abcdefgh")
    assert ok is True


def test_check_complexity_fails_missing_types():
    ok, msg = check_complexity("alllowercase")
    assert ok is False
    assert "uppercase" in msg.lower() or "digit" in msg.lower()


def test_check_complexity_passes_full_mix():
    ok, _ = check_complexity("Abcdef1!")
    assert ok is True


def test_check_uniqueness_flags_repeated_chars():
    ok, _ = check_uniqueness("aaaBBBB111")
    assert ok is False


def test_check_uniqueness_flags_sequential_run():
    ok, _ = check_uniqueness("test1234")
    assert ok is False


def test_check_uniqueness_passes_clean_password():
    ok, _ = check_uniqueness("Xk9!mQ2r")
    assert ok is True


def test_check_common_password_flags_known_password():
    ok, _ = check_common_password("password")
    assert ok is False


def test_check_common_password_passes_uncommon_password():
    ok, _ = check_common_password("Xk9!mQ2rZp")
    assert ok is True
