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
"""

import asn1crypto.cms as _cms
import asn1crypto.core as _core

from psec import tr31 as _tr31


class SetOfOctetStrings(_core.SetOf):
    """SetOfOctetStrings is a subclass of _core.SetOf that represents a set of
    octet strings."""

    _child_spec = _core.OctetString


class EncapsulatedHeader(_cms.EncapsulatedContentInfo):
    """EncapsulatedHeader is a subclass of _cms.EncapsulatedContentInfo
    consisting of an object identifier and a set with at least one octet string
    containing the encoded "TR34 Attribute Header" also referred as Key Block
    Header (KBH). The expected OID is "1.2.840.113549.1.7.1"."""

    CONTENT_TYPE_OID = "1.2.840.113549.1.7.1"

    _fields = [("content_type", _core.ObjectIdentifier), ("content", SetOfOctetStrings)]

    def __init__(self, *args, **kwargs):
        """Initialize a new EncapsulatedHeader instance.

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
        """Concatenate all the octet strings in the set and return it ASCII
        decoded."""
        header_str = ""
        for octet_string in self["content"]:
            header_str += octet_string.native.decode("ascii")

        return header_str


class Header(_core.Choice):
    """
    Header is a subclass of _core.Choice and can be of two types: a
    _coreOctetString or an EncapsulatedHeader.

    An octet string contains the encoded "TR34 Attribute Header" (also referred
    to as Key Block Header or KBH), which describes properties and allowable
    functions of a key wrapped within a key block. An EncapsulatedHeader
    consists of the object identifier "1.2.840.113549.1.7.1" and a set with at
    least one octet string. The TR34 header fields are defined in TR31, however
    not all fields in TR31 are applicable in the context of TR34, cf. TR34: 2019, p. 28.

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
        A list of tuples containing the available choices for the Header object.
        The first element of each tuple is the name of the choice and the
        second element is the corresponding object type

    Notes
    -----
    The parameters are checked using the _tr31.Header load function when a new instance is created.
    """

    _alternatives = [("octet", _core.OctetString), ("encapsulated", EncapsulatedHeader)]

    def __init__(self, name=None, value=None, **kwargs):
        """Initializes a new instance of the Header class."""
        super().__init__(name, value, **kwargs)
        if self._choice is not None:
            # Load the string representation of the Header into a _tr31.Header object to get a parameter check.
            _ = _tr31.Header()
            _.load(str(self))

    def __str__(self) -> str:
        """Returns the ascii decoded string representation of the TR34 Attribute Header."""
        if self._choice is not None and self.name == "octet":
            return self.chosen.native.decode("ascii")
        elif self._choice is not None and self.name == "encapsulated":
            return str(self.chosen)
        else:
            return ""
