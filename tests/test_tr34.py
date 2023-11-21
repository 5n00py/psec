import pytest

from psec import tr34
from psec import tr31 as _tr31

from asn1crypto import core as _core


def test_encapsulated_header_invalid_content_type():
    with pytest.raises(
        ValueError,
        match="Invalid content type for EncapsulatedHeader. Got 1.2.840.113549.1.7.2, expected 1.2.840.113549.1.7.1.",
    ):
        tr34.EncapsulatedHeader(
            {
                "content_type": _core.ObjectIdentifier("1.2.840.113549.1.7.2"),
                "content": tr34.SetOfOctetStrings(
                    [_core.OctetString("A0256K0TB00E0000".encode())]
                ),
            }
        )


def test_header_exception_invalid_tr31_attributes() -> None:
    # Test that a Header instance can handle attribute validation"""
    with pytest.raises(_tr31.HeaderError) as e:
        _ = tr34.Header({"octet": _core.OctetString("X0256K0TB00E0000".encode())})
    assert e.value.args[0] == "Version ID (X) is not supported."


def test_header_str_octet() -> None:
    # Test that a Header instance can be initialized with an octet string as the value and the __str__ method correctly
    # returns the string represenation of an octet type header.

    # Without optional blocks:
    core_header = tr34.Header({"octet": _core.OctetString("A0256K0TB00E0000".encode())})
    assert str(core_header) == "A0256K0TB00E0000"
    # With optional blocks:
    header_opt = tr34.Header(
        {
            "octet": _core.OctetString(
                "B0040P0TE00N0100KS1800604B120F9292800000".encode()
            )
        }
    )
    assert str(header_opt) == "B0040P0TE00N0100KS1800604B120F9292800000"


def test_header_str_encapsulated() -> None:
    # Test that the __str__ method correctly returns the string representation of an encapsulated type header
    encapsulated_header = tr34.EncapsulatedHeader(
        {
            "content_type": _core.ObjectIdentifier("1.2.840.113549.1.7.1"),
            "content": tr34.SetOfOctetStrings(
                [
                    _core.OctetString("B0040P0TE00N0100".encode()),
                    _core.OctetString("KS1800604B120F9292800000".encode()),
                ]
            ),
        }
    )
    header = tr34.Header({"encapsulated": encapsulated_header})
    assert str(header) == "B0040P0TE00N0100KS1800604B120F9292800000"


def test_header_str_unknown_type():
    # Test that the __str__ method returns an empty string when the header is not instantiated"""
    header = tr34.Header()
    assert str(header) == ""
