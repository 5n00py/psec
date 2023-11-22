import pytest

import os

from psec import tr34
from psec import tr31 as _tr31
from psec import file_utils

from asn1crypto import algos as _algos
from asn1crypto import cms as _cms
from asn1crypto import core as _core
from asn1crypto import util as _util
from asn1crypto import x509 as _x509


# Absolute directory of where this file is located
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


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
    # Test that a Header instance can be initialized with an octet string as
    # the value and the __str__ method correctly returns the string
    # represenation of an octet type header.

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
    # Test that the __str__ method correctly returns the string representation
    # of an encapsulated type header
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
    # Test that the __str__ method returns an empty string when the header is
    # not instantiated
    header = tr34.Header()
    assert str(header) == ""


def test_key_block_load_tr34_sample_tdea() -> None:
    # Test that the KeyBlock can be correctly loaded with TDEA (Triple DES) key
    # data from a PEM file Test vector from TR34-2019, B.2.2.2.1: Sample TDEA
    # Key Block Using IssuerAndSerialNumber
    pem_file = "test_files/TR34_Sample_Key_Block_TDES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    assert kb.version == 1
    assert kb.id_kdh.chosen["issuer"].native["country_name"] == "US"
    assert kb.id_kdh.chosen["issuer"].native["organization_name"] == "TR34 Samples"
    assert kb.id_kdh.chosen["issuer"].native["common_name"] == "TR34 Sample CA KDH"
    assert kb.id_kdh.chosen["serial_number"].native == 223338299398
    assert kb.clear_key == bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert str(kb.header) == "A0256K0TB00E0000"


def test_key_block_load_tr34_sample_aes() -> None:
    # test that the KeyBlock can be correctly loaded with AES key data from a
    # PEM file Test vector from TR34-2019, B.2.2.2.1: Sample AES Key Block
    # Using IssuerAndSerialNumber
    pem_file = "test_files/TR34_Sample_Key_Block_AES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    assert kb.version == 1
    assert kb.id_kdh.chosen["issuer"].native["country_name"] == "US"
    assert kb.id_kdh.chosen["issuer"].native["organization_name"] == "TR34 Samples"
    assert kb.id_kdh.chosen["issuer"].native["common_name"] == "TR34 Sample CA KDH"
    assert kb.id_kdh.chosen["serial_number"].native == 223338299398
    assert kb.clear_key == bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    # Note: There is an error in the comment of TR34-2019, example B.2.2.2.4,
    # p. 84 to "TR34 Attribute Header", the "B" is missing in the comment, but
    # the octet string is correct and accordingly fixed here:
    assert str(kb.header) == "D0256K0AB00E0000"


def test_key_block_construct() -> None:
    # Test that a KeyBlock can be correctly constructed from its components
    # Create the IssuerAndSerialNumber Object
    issuer_dict = _util.OrderedDict(
        [
            ("country_name", "US"),
            ("organization_name", "TR34 Samples"),
            ("common_name", "TR34 Sample CA KDH"),
        ]
    )
    issuer = _x509.Name.build(issuer_dict, use_printable=True)
    id_kdh = _cms.IssuerAndSerialNumber(
        {"issuer": issuer, "serial_number": 223338299398}
    )

    # Create the EncapsulatedHeader object
    header = tr34.EncapsulatedHeader(
        {
            "content_type": _core.ObjectIdentifier("1.2.840.113549.1.7.1"),
            "content": tr34.SetOfOctetStrings(
                [_core.OctetString("A0256K0TB00E0000".encode())]
            ),
        }
    )

    # Create the KeyBlock object
    kb = tr34.KeyBlock(
        {
            "version": _cms.CMSVersion(1),
            "id_kdh": id_kdh,
            "clear_key": bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
            "header": header,
        }
    )

    # Test vector from TR34-2019, B.2.2.2.1: Sample TDEA Key Block Using
    # IssuerAndSerialNumber
    pem_file = "test_files/TR34_Sample_Key_Block_TDES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)

    assert kb.dump() == data


def test_key_block_construct_empty() -> None:
    kb = tr34.KeyBlock()

    assert kb.version is None
    assert kb.id_kdh is None
    assert kb.header is None
    assert kb.clear_key is None


def test_key_block_encrypt_tdes() -> None:
    # Test vector from TR34-2019, B.2.2.2.1: Sample TDEA Key Block Using
    # IssuerAndSerialNumber
    pem_file = "test_files/TR34_Sample_Key_Block_TDES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    # Note: The 7th last byte is corrected to 0xC7 compared to TR34-2019, p. 80.
    ct_exp = bytes.fromhex(
        "53 32 A1 F8 45 21 DE 2D 3B 23 EB E3 CB 2D 67 4B"
        "16 11 4E C5 98 21 41 02 C3 DE E1 75 C2 A6 69 40"
        "0E B0 39 13 6E 63 2E 4A 32 14 0A AB 55 46 AC 47"
        "87 99 F7 B7 A0 25 33 5F 45 CC A3 CD 18 94 31 4F"
        "F5 13 E3 E0 25 73 AD B5 13 5D F8 B1 DB 32 77 D9"
        "DE 27 3D C6 A8 B5 E7 9D 21 5F 63 B9 3A 52 13 7D"
        "BA FB E5 CC 3F F4 72 91 9D 86 D2 40 97 62 37 0F"
        "A8 0A 77 AE D1 83 E1 ED 59 7B F9 BF DC 9D 28 69"
        "34 C7 C1 E1 E8 D0 03 FB"
    )

    ephemeral_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210FFEEDDCCBBAA9988")
    iv = bytes.fromhex("0123456789ABCDEF")
    # Create the algorithm object with the given IV
    algo = _algos.EncryptionAlgorithm(
        {"algorithm": "tripledes_3key", "parameters": _core.OctetString(iv)}
    )

    ct = kb.encrypt(ephemeral_key, algo)

    assert ct == ct_exp


@pytest.mark.parametrize(
    ["ephemeral_key", "iv", "error"],
    [
        (
            bytes.fromhex("0123456789ABCDEFFEDCBA9876543210FF"),
            bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            "Invalid ephemeral key length: '17'. Expected '16'",
        ),
        (
            bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
            bytes.fromhex("00112233445566778899AABBCCDDEE"),
            "Invalid IV length: '15'. Expected '16'.",
        ),
    ],
)
def test_key_block_encrypt_aes_exception(
    ephemeral_key: bytes, iv: bytes, error: str
) -> None:
    pem_file = "test_files/TR34_Sample_Key_Block_AES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    # Create the algorithm object with the given IV
    algo = _algos.EncryptionAlgorithm(
        {"algorithm": "aes128_cbc", "parameters": _core.OctetString(iv)}
    )

    with pytest.raises(
        ValueError,
        match=error,
    ):
        kb.encrypt(ephemeral_key, algo)


def test_key_block_sample_encrypt_aes_invalid_iv() -> None:
    # Test vector from TR34-2019, B.2.2.2.1: Sample AES Key Block Using IssuerAndSerialNumber
    pem_file = "test_files/TR34_Sample_Key_Block_AES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    ephemeral_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    # HELP! The TR34 sample does not provide an IV directly but B.2.2.3.2 gives
    # this one from the AES enveloped data which is too short. As long as the
    # proper IV is not known this sample has to be treated as an exception case
    # for "Invalid IV length for AES-128".
    iv = bytes.fromhex("0123456789ABCDEF")

    algo = _algos.EncryptionAlgorithm(
        {"algorithm": "aes128_cbc", "parameters": _core.OctetString(iv)}
    )

    with pytest.raises(
        ValueError,
        match="Invalid IV length: '8'. Expected '16'.",
    ):
        kb.encrypt(ephemeral_key, algo)

    # When fixed remove the above Value Error test and uncomment the following:
    """
    ct_exp = bytes.fromhex("0D DE 93 1D 28 1D EB 8B CC AA F8 01 94 4D F5 A8"
                       "B3 D6 05 6B 67 B3 B5 E6 43 19 DB 02 98 6E 5D 2A"
                       "3B A7 87 1D 50 9F 8E C3 6C 26 9A 3E F9 3C 53 C0"
                       "A8 75 38 DB 78 1C 2D 0D C0 A6 7D 4E 5A 67 97 E9"
                       "67 6B 94 CD 6F 63 E6 10 41 8B 74 37 97 FD 37 DC"
                       "AA 45 FB 89 CC A7 50 7A 38 75 1E 02 EA BF 43 21"
                       "43 B9 A6 06 30 F4 53 C2 E7 36 FE CD D4 9F 4E 62"
                       "F2 6D 53 88 A8 E3 C0 90 9C BA E4 85 4E 3B F6 A9"
                       "34 23 80 26 54 49 DC D4 34 23 C5 F1 97 47 2A D0")

    ct = kb.encrypt(ephemeral_key, iv, "AES-128")
    assert ct == ct_exp
    """


def test_key_block_encrypt_aes() -> None:
    pem_file = "test_files/TR34_Sample_Key_Block_AES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    ephemeral_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    iv = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    algo = _algos.EncryptionAlgorithm(
        {"algorithm": "aes128_cbc", "parameters": _core.OctetString(iv)}
    )

    ct_exp = bytes.fromhex(
        "E8 93 09 D4 36 01 6C 86 ED 3D E1 7F 8F DA 00 6A "
        "51 C6 6C AD 72 4A 2C 06 F0 0B 36 7D E5 1A 8A 1C "
        "AD BE 26 2C 10 A6 95 DA B9 11 09 F8 95 23 9F 16 "
        "93 80 58 33 94 EC E4 0D 26 98 36 2E 09 71 00 04 "
        "76 F5 73 64 3D 04 99 86 3F CC B3 EA 91 68 FE 54 "
        "67 22 73 9C 74 E1 E9 F4 E1 8C 89 4E D8 44 B1 99 "
        "F8 B9 F4 0F 04 F2 24 4F C2 5E E8 1B 81 87 02 35 "
        "29 87 4A 7C 4B 67 A2 69 39 47 A1 B0 2C 6A C4 59 "
        "8C D3 47 11 BC B9 8C BA 29 F7 74 57 36 DD 4F CE"
    )

    ct = kb.encrypt(ephemeral_key, algo)
    assert ct == ct_exp


def test_key_block_encrypt_exception_no_iv_provided() -> None:
    pem_file = "test_files/TR34_Sample_Key_Block_AES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    ephemeral_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    algo = _algos.EncryptionAlgorithm({"algorithm": "aes128_cbc", "parameters": None})

    with pytest.raises(ValueError) as exc_info:
        kb.encrypt(ephemeral_key, algo)
    assert "No IV provided." in str(exc_info.value)


def test_key_block_encrypt_exception_invalid_algorithm() -> None:
    pem_file = "test_files/TR34_Sample_Key_Block_AES_Content.pem"
    abs_file_path = os.path.join(TEST_DIR, pem_file)
    data = file_utils.read_asn1_file(abs_file_path)
    kb = tr34.KeyBlock.load(data)

    ephemeral_key = bytes.fromhex(
        "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210"
    )
    iv = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    algo = _algos.EncryptionAlgorithm(
        {"algorithm": "aes256_cbc", "parameters": _core.OctetString(iv)}
    )

    with pytest.raises(ValueError) as exc_info:
        kb.encrypt(ephemeral_key, algo)
    assert "Algorithm must be either 'tripledes_3key' or 'aes128_cbc'." in str(
        exc_info.value
    )
