import random


# From Appendix B of the OpenID 2.0 spec
DEFAULT_MODULUS = 0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583ABL


class DiffieHellman(object):

    def __init__(self, generator=None, modulus=None, their_public_key=None):
        self.generator = generator if generator is not None else 2
        self.modulus = modulus if modulus is not None else DEFAULT_MODULUS
        self.their_public_key = their_public_key

    def select_key(self):
        r = random.SystemRandom()
        self.my_private_key = r.randrange(1, self.modulus - 1)

    def calculate_public_key(self):
        return pow(self.generator, self.my_private_key, self.modulus)

    def calculate_secret(self):
        secret = pow(self.their_public_key, self.my_private_key, self.modulus)
        return secret
