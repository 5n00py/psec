import os
import base64 as _base64

import asn1crypto.core as _core


__all__ = [
    "read_asn1_file",
]


def read_asn1_file(file_path: str) -> bytes:
    r"""Retrieve and decode byte data from a file with .der or .pem extension,
    specifically intended for ASN.1 encoded data.

    This function is designed to handle cryptographic file formats commonly
    used for storing keys, certificates, and other security-related
    information. It supports both DER (Distinguished Encoding Rules) and PEM
    (Privacy-Enhanced Mail) encoded files, which are prevalent formats for
    ASN.1 (Abstract Syntax Notation One) data structures in cryptographic
    applications.

    Parameters
    ----------
    file_path : str
        The file path and name to be read, including the file extension.

    Returns
    -------
    bytes :
        The byte decoded data from the file.

    Raises
    ------
    ValueError
        File does not exist.
        File must have .der or .pem extension.
        File is empty.
        File data is not a valid ASN.1 structure.
    """
    # Check that the file exists
    if not os.path.exists(file_path):
        raise ValueError("File does not exist.")

    # Make sure the file has .der or .pem extension
    if not file_path.endswith(".der") and not file_path.endswith(".pem"):
        raise ValueError("File must have .der or .pem extension.")

    # Open the file and read the contents
    with open(file_path, "rb") as f:
        data = f.read()

    # Check that the file is not empty
    if not data:
        raise ValueError("File is empty.")

    # If the file is a .pem file, decode the data
    if file_path.endswith(".pem"):
        # Remove headers and footers starting with "--"
        # (e.g. —–BEGIN CERTIFICATE—– and —–END CERTIFICATE—–).
        base64_data = "".join(
            [
                line
                for line in data.decode("ascii").splitlines()
                if not line.startswith("--")
            ]
        )
        data = _base64.b64decode(base64_data)

    # Check if the data is a valid ASN.1 structure
    try:
        _core.Asn1Value.load(data)
    except ValueError:
        raise ValueError("File data is not a valid ASN.1 structure.")

    return data
