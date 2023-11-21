import pytest
from psec import padding


@pytest.mark.parametrize(
    ["data", "block_size", "expected"],
    [
        (b"", 8, b"\x08\x08\x08\x08\x08\x08\x08\x08"),
        (b"\x00\x00\x00", 8, b"\x00\x00\x00\x05\x05\x05\x05\x05"),
        (b"\x01\x02\x03\x04", 8, b"\x01\x02\x03\x04\x04\x04\x04\x04"),
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            8,
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x08\x08\x08\x08\x08\x08\x08\x08",
        ),
    ],
)
def test_pad_pkcs7(data: bytes, block_size: int, expected: bytes) -> None:
    assert padding.pad_pkcs7(data, block_size) == expected


@pytest.mark.parametrize(
    "data, block_size",
    [
        (b"\x00", -1),
        (b"\x00", 0),
    ],
)
def test_pad_pkcs7_exception(data: bytes, block_size: int):
    with pytest.raises(ValueError, match="Block size must be a positive integer"):
        padding.pad_pkcs7(data, block_size)


@pytest.mark.parametrize(
    ["data", "expected"],
    [
        (b"\x08\x08\x08\x08\x08\x08\x08\x08", b""),
        (b"\x00\x00\x00\x05\x05\x05\x05\x05", b"\x00\x00\x00"),
        (b"\x01\x02\x03\x04\x04\x04\x04\x04", b"\x01\x02\x03\x04"),
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x08\x08\x08\x08\x08\x08\x08\x08",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
    ],
)
def test_unpad_pkcs7(data: bytes, expected: bytes) -> None:
    assert padding.unpad_pkcs7(data) == expected


@pytest.mark.parametrize(
    ["data", "error"],
    [
        (b"", "Data is empty"),
        (b"\x02\x03", "Invalid padding length"),
        (b"\x01\x02\x03\x04\x05", "Padding bytes are incorrect"),
        (b"\x02\x02\x02\x02\x03", "Padding bytes are incorrect"),
    ],
)
def test_unpad_pkcs7_exception(data: bytes, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        padding.unpad_pkcs7(data)
