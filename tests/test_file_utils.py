import pytest

import os

from psec import file_utils

# Absolute directory of where this file is located
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


@pytest.mark.parametrize(
    ["file_name", "error"],
    [
        ("test_files/empty_file.der", "File is empty."),
        (
            "test_files/invalid_asn1.der",
            "File data is not a valid ASN.1 structure.",
        ),
        ("test_files/invalid_file.txt", "File must have .der or .pem extension."),
        ("invalid/path/to/file.der", "File does not exist."),
    ],
)
def test_get_file_data_exception(file_name: str, error: str) -> None:
    # Test that the read_asn1_file function raises a ValueError with the
    # expected error message when given an invalid file name or an invalid
    # file.
    with pytest.raises(
        ValueError,
        match=error,
    ):
        abs_file_path = os.path.join(TEST_DIR, file_name)
        file_utils.read_asn1_file(abs_file_path)


def test_get_file_data_der_encoded() -> None:
    # Test that the read_asn1_file function correctly reads and returns the data
    # from a DER-encoded file.
    der_file = "test_files/TR34_Sample_KDH_1_IssuerAndSerialNumber.der"
    abs_file_path = os.path.join(TEST_DIR, der_file)

    data = bytes.fromhex(
        "30 4A 30 41 31 0B 30 09 06 03 55 04 06 13 02 55 "
        "53 31 15 30 13 06 03 55 04 0A 13 0C 54 52 33 34 "
        "20 53 61 6D 70 6C 65 73 31 1B 30 19 06 03 55 04 "
        "03 13 12 54 52 33 34 20 53 61 6D 70 6C 65 20 43 "
        "41 20 4B 44 48 02 05 34 00 00 00 06"
    )

    assert data == file_utils.read_asn1_file(abs_file_path)


def test_get_file_data_pem_encoded() -> None:
    # Test that the read_asn1_file function correctly reads and returns the
    # data from a PEM-encoded file.
    pem_file = "test_files/TR34_Sample_KDH_1_IssuerAndSerialNumber.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = bytes.fromhex(
        "30 4A 30 41 31 0B 30 09 06 03 55 04 06 13 02 55 "
        "53 31 15 30 13 06 03 55 04 0A 13 0C 54 52 33 34 "
        "20 53 61 6D 70 6C 65 73 31 1B 30 19 06 03 55 04 "
        "03 13 12 54 52 33 34 20 53 61 6D 70 6C 65 20 43 "
        "41 20 4B 44 48 02 05 34 00 00 00 06"
    )

    assert data == file_utils.read_asn1_file(abs_file_path)
