import pytest

from app.core.passwords import (
    validate_policy,
    hash_password,
    verify_password,
    WeakPasswordError
)


def test_weak_password():
    with pytest.raises(WeakPasswordError):
        validate_policy("123456")


def test_good_password():
    validate_policy("M7!vQ2#rL9@xT4")


def test_hash():
    password = "M7!vQ2#rL9@xT4"

    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrong", hashed)