r"""psec is a payment security package for protecting sensitive data
for retail payment transactions and cardholder authentication.

psec modules:

    - tr31 - TR-31 key block wrapping and unwrapping
    - tr34 - TR-34 key block wrapping and unwrapping
    - aes - Advanced Encryption Standard
    - des - Triple DES
    - cvv - Card Verification Value
    - mac - Message Authentication Code
    - padding - Adding and removing padding data
    - pin - Personal Identification Number
    - pinblock - PIN Blocks encoding and decoding
    - tools - Miscellaneous tools, such as xor.
    - file_utils - Utilities for file handling, particularly for cryptographic
      files
"""

__version__ = "1.3.0"
__author__ = "Konstantin Novichikhin <konstantin.novichikhin@gmail.com>"

from psec import (
    aes,
    cvv,
    des,
    file_utils,
    mac,
    padding,
    pin,
    pinblock,
    tools,
    tr31,
    tr34,
)
