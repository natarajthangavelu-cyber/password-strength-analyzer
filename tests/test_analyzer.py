from src.analyzer import analyze_password, calculate_entropy


def test_entropy_zero_for_empty_password():
    assert calculate_entropy("") == 0.0


def test_entropy_increases_with_length():
    short_entropy = calculate_entropy("Abcd1!")
    long_entropy = calculate_entropy("Abcd1!Abcd1!Abcd1!")
    assert long_entropy > short_entropy


def test_weak_password_gets_low_label():
    result = analyze_password("12345")
    assert result["label"] in ("Very Weak", "Weak")


def test_common_password_is_never_rated_strong():
    result = analyze_password("password")
    assert result["label"] in ("Very Weak", "Weak")


def test_strong_random_password_gets_high_label():
    result = analyze_password("Xk9!mQ2r$Tw7@Lp4")
    assert result["label"] in ("Strong", "Very Strong")


def test_result_contains_expected_keys():
    result = analyze_password("Xk9!mQ2r")
    for key in ("password_length", "entropy_bits", "score", "label", "passed", "failed"):
        assert key in result
