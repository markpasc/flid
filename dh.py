import random


"""

A Python implementation of Diffie-Hellman key exchange.

"""


DEFAULT_MODULUS = 0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583ABL
"""The default modulus to use in OpenID 2.0 key exchanges, according to
Appendix B of the OpenID 2.0 specification."""

DEFAULT_GENERATOR = 2
"""The default generator to use in OpenID 2.0 key exchanges, according to
Appendix B of the OpenID 2.0 specification."""


class DiffieHellman(object):

    """A Diffie-Hellman key exchange.

    Diffie-Hellman key exchange is based on the formula::

        g^s % p = (g^a)^b % p = (g^b)^a % p

    ``g`` and ``p`` are the `generator` and `modulus`. ``a`` and ``b`` are the
    parties' private keys, and ``g^a`` and ``g^b`` their public keys. Because
    the exponentiation is performed modulo ``p``, it's difficult to find the
    private keys given the public keys.

    As used in OpenID, the protocol goes:

    * Alice requests an association, giving Bob her public key.
    * Bob selects a private key at random.
    * Bob calculates his public key from the private key (and ``g`` and ``p``).
    * Given Alice's public key and his private key, Bob calculates the
      symmetric key.
    * Bob sends his public key to Alice (perhaps along with an encrypted
      ciphertext).
    * Given her private key and Bob's public key, Alice calculates the
      symmetric key.

    At that point, both sides have the symmetric key ``s`` without having sent
    it (or their private keys) to each other. The symmetric key is the key that
    Diffie-Hellman key exchange exchanges.

    This implementation uses plain English variable names. All values are
    numeric `long` instances.

    """

    def __init__(self, generator=None, modulus=None, their_public_key=None):
        self.generator = generator if generator is not None else DEFAULT_GENERATOR
        self.modulus = modulus if modulus is not None else DEFAULT_MODULUS
        self.their_public_key = their_public_key

    def select_key(self):
        """Select a private key at random.

        The key is saved in the instance's `my_private_key` attribute. In the
        formula, this key is ``b`` if you have the other party's public key
        already, or ``a`` otherwise.

        """
        r = random.SystemRandom()  # requires os.urandom
        self.my_private_key = r.randrange(1, self.modulus - 1)

    def calculate_public_key(self):
        """Calculate our public key from the generator, modulus, and our
        private key, and return it.

        Our private key must already be in the instance's `my_private_key`
        attribute, either by setting it manually or calling `select_key()`
        first.

        """
        return pow(self.generator, self.my_private_key, self.modulus)

    def calculate_secret(self):
        """Calculate the secret symmetric key from the modulus, our private
        key, and the other party's public key, and return it.

        """
        secret = pow(self.their_public_key, self.my_private_key, self.modulus)
        return secret
