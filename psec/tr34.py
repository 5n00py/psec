r"""TR34: 2019 

Cf. ASC X9 TR34-2019: Interoperable Method for Distribution of Symmetric Keys
using Asymmetric Techniques. TR34 is an interoperable protocol for devices
using the RSA algorithm with key strength of a minimum of 2048 bits for
asymmetric transport of symmetric keys using either TDEA of 112 or 168 bits
strength or AES keys of 128 bits strength. 

A primary application of TR34 involves transmitting indivudual initial
symmetric transport keys from a Key Distribution Host (KDH) to numerous Key
Receiving Devices (KRDs). A typical example usage of TR34 would be to load
individual initial symmetric transport keys from a Key Distribution Host (KDH)
to a population of PIN entry devices (PEDs).

TR34 makes use of asymmetric cryptography which means that the KDH and the Key
Receiving Devices (KDHs) must have a common relationship with a Certificate
Authority (CA). The CA can be an independent party from both the KRD vendor and
the KDH, or the KRD vendor can be the CA.

This module has so far implemented the Header and KeyBlock components and the
related symmetric encryption process, which is the central part on how the KDH
encrypts the key block containing the transported key and additional parameters 
using an ephemeral symmetrc key.

In further steps the ephemeral key would be encrypted by the KRD public key
using RSA-OAEP as an EnvelopedData type ensuring the secrecy of the key block,
as per CMS standards. Furthermore, to ensure the integrity and authenticity of
the key block, a SignedData type is used. The SignedData type, as per CMS
standards, provides digital signature functionality that verifies the origin
and integrity of the key block.

The implementation is designed with flexibility to accommodate different
interpretations of TR34 by various KRDs, though direct coordination with
hardware aspects and secure certificate storage is essential for real-world
applications.

The implementation does NOT enforce compliance requirements
surch as the strength of the ephemeral key being equal or greater than the
strength of the clear key encrypted, which may be necessary in certain contexts
like PCI.
"""

from typing import Union as _Union

import asn1crypto.algos as _algos
import asn1crypto.cms as _cms
import asn1crypto.core as _core

from psec import aes as _aes
from psec import des as _des
from psec import tr31 as _tr31
from psec.padding import pad_pkcs7 as _pad_pkcs7


__all__ = ["SetOfOctetStrings", "EncapsulatedHeader", "Header", "KeyBlock"]


class SetOfOctetStrings(_core.SetOf):
    r"""SetOfOctetStrings is a subclass of _core.SetOf that represents a set of
    octet strings."""

    _child_spec = _core.OctetString


class EncapsulatedHeader(_cms.EncapsulatedContentInfo):
    r"""EncapsulatedHeader is a subclass of _cms.EncapsulatedContentInfo
    consisting of an object identifier and a set with at least one octet string
    containing the encoded "TR34 Attribute Header" also referred as Key Block
    Header (KBH). The expected OID is "1.2.840.113549.1.7.1"."""

    CONTENT_TYPE_OID = "1.2.840.113549.1.7.1"

    _fields = [("content_type", _core.ObjectIdentifier), ("content", SetOfOctetStrings)]

    def __init__(self, *args, **kwargs):
        r"""Initialize a new EncapsulatedHeader instance.

        Parameters
        ----------
        *args : list
            Positional arguments passed to the parent class constructor.
        **kwargs : dict
            Keyword arguments passed to the parent class constructor.

        Raises
        ------
        ValueError
            Invalid content type for EncapsulatedHeader. Got
            {self['content_type'].native}, expected {self.CONTENT_TYPE_OID}.
        """
        super().__init__(*args, **kwargs)
        if self["content_type"].native != self.CONTENT_TYPE_OID:
            raise ValueError(
                f"Invalid content type for EncapsulatedHeader. Got {self['content_type'].native}, expected "
                f"{self.CONTENT_TYPE_OID}."
            )

    def __str__(self) -> str:
        r"""Concatenate all the octet strings in the set and return it ASCII
        decoded."""
        header_str = ""
        for octet_string in self["content"]:
            header_str += octet_string.native.decode("ascii")

        return header_str


class Header(_core.Choice):
    r"""Header is a subclass of _core.Choice and can be of two types: a
    _coreOctetString or an EncapsulatedHeader.

    An octet string contains the encoded "TR34 Attribute Header" (also referred
    to as Key Block Header or KBH), which describes properties and allowable
    functions of a key wrapped within a key block. An EncapsulatedHeader
    consists of the object identifier "1.2.840.113549.1.7.1" and a set with at
    least one octet string. The TR34 header fields are defined in TR31, however
    not all fields in TR31 are applicable in the context of TR34, cf. TR34:
    2019, p. 28.

    Parameters
    ----------
    name: str, optional
        The name of the Header object.
    value:
        The value of the Header object.
    **kwargs:
        Additional keyword arguments.

    Attributes
    ----------
    _alternatives:
        A list of tuples containing the available choices for the Header
        object. The first element of each tuple is the name of the choice and
        the second element is the corresponding object type

    Notes
    -----
    The parameters are checked using the _tr31.Header load function when a new
    instance is created.
    """

    _alternatives = [("octet", _core.OctetString), ("encapsulated", EncapsulatedHeader)]

    def __init__(self, name=None, value=None, **kwargs):
        """Initializes a new instance of the Header class."""
        super().__init__(name, value, **kwargs)
        if self._choice is not None:
            # Load the string representation of the Header into a _tr31.Header
            # object to get a parameter check.
            _ = _tr31.Header()
            _.load(str(self))

    def __str__(self) -> str:
        """
        Returns the ascii decoded string representation of the TR34 Attribute
        Header.
        """
        if self._choice is not None and self.name == "octet":
            return self.chosen.native.decode("ascii")
        elif self._choice is not None and self.name == "encapsulated":
            return str(self.chosen)
        else:
            return ""


class KeyBlock(_core.Sequence):
    r"""The KeyBlock is a subclass of _core.Sequence that represents a key
    block structure as defined in ASC X9 TR34-2019.

    A key block consists of a sequence of four fields:

        - version: A CMS version field, which specifies the version of the CMS
          (Cryptographic Message Syntax) used.
        - id_kdh: An IssuerAndSerialNumber field which identifies the key
          distribution host (KDH) distributing the key.
        - clear_key: The key / payload being transported encoded as octet
          string.
        - header: A header field, which can either be encoded in an octet
          string or an encapsulated header. The encapsulated header consists of
          a content type identifier and a set with at least one octet string
          representing the "TR34 Attribute Header" also referred as "Key Block
          Header" (KBH). The native header defines attribute information about
          the key and key block and is taken from TR31.

    Parameters
    ----------
    version : _cms.CMSVersion
        The CMS version field.
    id_kdh : _cms.IssuerAndSerialNumber
        The IssuerAndSerialNumber field identifying the KDH.
    clear_key : _core.OctetString
        The key / payload being transported, encoded as an octet string.
    header : HeaderChoice The header field, which can be an octet string or an
        encapsulated header.

    Attributes
    ----------
    version : Union[int, None]
        The CMS version field. Returns None if version is not set.
    id_kdh : Union[IdKdh, None]
        The IssuerAndSerialNumber field identifying the KDH. Returns None if
        id_kdh is not set.
    clear_key : Union[bytes, None]
        The key / payload being transported as bytes. Returns None if clear_key
        is not set.
    header : Union[Header, None]
        The header field, which can be an octet string or an encapsulated
        header. Returns None if header is not set.

    Notes
    ------
    - The format and contents of the native header are not validated in this
      class.
    - TR33-2019, p. 165 defines the header as an octet string. However, the
      examples B.2.2.2 in TR34-2019, p. 79ff. use an encapsulated header. This
      coincides with experiences "in the wild" where CMS structures are mostly
      encapsulated in some sort of ContentInfo. This implementation gives the
      choice of either one.
    """

    _fields = [
        ("version", _cms.CMSVersion),
        ("id_kdh", _cms.SignerIdentifier),
        ("clear_key", _core.OctetString),
        ("header", Header),
    ]

    @property
    def version(self) -> _Union[None, int]:
        r"""Get the version field. Returns the CMS version field as a
        _cms.CMSVersion object."""
        if isinstance(self["version"], _cms.CMSVersion):
            return int(self["version"].native[1:])
        return None

    @property
    def id_kdh(self) -> _Union[None, _cms.SignerIdentifier]:
        r"""Get the id_kdh field. Returns the IssuerAndSerialNumber field as a
        _cms.IssuerAndSerialNumber object."""
        if isinstance(self["id_kdh"], _cms.SignerIdentifier):
            return self["id_kdh"]
        return None

    @property
    def clear_key(self) -> _Union[None, bytes]:
        r"""Get the clear key / payload being transported."""
        if isinstance(self["clear_key"], _core.OctetString):
            return self["clear_key"].native
        return None

    @property
    def header(self) -> _Union[None, Header]:
        r"""Get the header containing the TR34 Attribute Information."""
        if isinstance(self["header"], Header):
            return self["header"]
        return None

    def encrypt(self, ephemeral_key: bytes, algo: _algos.EncryptionAlgorithm) -> bytes:
        r"""Encrypt the DER encoded and PKCS#7 padded key block using the
        specified algorithm and ephemeral key.

        This method supports encryption with either TDES 3 keys or AES-128
        algorithms in CBC mode as specified in TR34-2019, table 15, p. 63. The
        ephemeral key's strength should align with the requirements of the
        encryption algorithm being used.

        IMPORTANT: In the context of TR34 some compliance requirements (e.g. PCI)
        might demand that the strength of the ephemeral key is equal or greater
        to the strength of the clear key to be encrypted within the key block.
        However, the implementation of this function does not ensure this
        requirement!

        Note: The use of PKCS#7 padding is not explicitly mentioned in
        TR34-2019 but given through the CMS context (cf. RFC 5652, section 6.3:
        Content-encryption Process) and verified through the test vectors.


        Parameters
        ----------
        ephemeral_key : bytes
            The ephemeral key used for encryption. Its length must match the
            expected key length of the specified algorithm.
        algo : _algos.EncryptionAlgorithm
            An object representing the encryption algorithm to use, either
            "tripledes_3key" or "aes128_cbc" and an initialization vector (IV).

        Returns
        -------
        bytes :
            The encrypted key block.

        Raises
        ------
        ValueError
            Invalid ephemeral key length: 'actual_length'. Expected 'expected_length'
            No IV provided.
            Invalid IV length: 'actual_length'. Expected 'expected_block_size'.
            Algorithm must be either 'tripledes_3key' or 'aes128_cbc'.
        """

        # Encode the key block using DER:
        plain_data = self.dump()

        if len(ephemeral_key) != algo.key_length:
            raise ValueError(
                f"Invalid ephemeral key length: '{str(len(ephemeral_key))}'. Expected '{str(algo.key_length)}'"
            )

        iv = algo.encryption_iv
        if iv is None:
            raise ValueError("No IV provided.")

        if len(iv) != algo.encryption_block_size:
            raise ValueError(
                f"Invalid IV length: '{str(len(iv))}'. Expected '{str(algo.encryption_block_size)}'."
            )

        if algo["algorithm"].native == "tripledes_3key":
            return _des.encrypt_tdes_cbc(ephemeral_key, iv, _pad_pkcs7(plain_data, 8))

        if algo["algorithm"].native == "aes128_cbc":
            return _aes.encrypt_aes_cbc(ephemeral_key, iv, _pad_pkcs7(plain_data, 16))

        else:
            raise ValueError(
                "Algorithm must be either 'tripledes_3key' or 'aes128_cbc'."
            )
