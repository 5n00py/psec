r"""
Padding Utilities Module

This module provides functions for adding and removing PKCS#7 padding, as 
specified in RFC 5652, Cryptographic Message Syntax (CMS), which is the basis 
for padding in various cryptographic operations.
"""

__all__ = ["pad_pkcs7", "unpad_pkcs7"]


def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    r"""Add PKCS#7 padding to the given data up to the next multiple of the
    block_size.

    Parameters:
    -----------
    data : bytes
        The data to be padded.
    block_size : int
        The block size to use for the padding.

    Returns:
    --------
    bytes:
        The padded data.

    Raises:
    -------
    ValueError:
        Block size must be a positive integer

    Examples:
    ---------

    >>> from psec.padding import pad_pkcs7
    >>> pad_pkcs7(b"\x01",4).hex()
    '01030303'
    """
    if block_size <= 0:
        raise ValueError("Block size must be a positive integer")

    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def unpad_pkcs7(data: bytes) -> bytes:
    r"""Remove PKCS#7 padding from the given data or raise a ValueError if
    padding format is wrong.

    Parameters:
    -----------
    data : bytes
        The padded data to be unpadded.

    Returns:
    --------
    bytes :
        The unpadded data.

    Raises:
    -------
    ValueError
        Data is empty
        Invalid padding length
        Padding bytes are incorrect

    Examples:
    ---------

    >>> from psec.padding import unpad_pkcs7
    >>> unpad_pkcs7(b"\x01\x03\x03\x03").hex()
    '01'
    """
    if not data:
        raise ValueError("Data is empty")

    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding length")

    padding = data[-pad_len:]
    if all(padding[i] == pad_len for i in range(pad_len)):
        return data[:-pad_len]
    else:
        raise ValueError("Padding bytes are incorrect")
