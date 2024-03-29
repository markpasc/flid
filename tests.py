import unittest

from dh import DiffieHellman, DEFAULT_MODULUS
from flid import btwoc, unbtwoc


class DhTests(unittest.TestCase):

    #    ZZ = g ^ (xb * xa) mod p
    # a: ZZ =     (yb ^ xa) mod p
    #          yb = g ^ xb (mod p?)
    # b: ZZ = (ya ^ xb)  mod p

    # "They" are a, giving us ya.
    # "I" am b, selecting xb at random as my private key.
    # With g and xb, I can calculate yb.
    # With ya and xb, I calculate ZZ.
    # I encrypt something with ZZ, then send the ciphertext and yb back to them.

    def configure(self, data):
        p, g, ya, xb, yb, zz = [data[key] for key in ('P', 'G', 'YstatCAVS', 'XstatIUT', 'YstatIUT', 'Z')]
        dh = DiffieHellman(g, p, ya)
        dh.my_private_key = xb
        return dh, yb, zz

    def test_one(self):
        P = 0xda3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35
        G = 0xa51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288
        #XstatCAVS = 0x42c6ee70beb7465928a1efe692d2281b8f7b53d6
        YstatCAVS = 0x5a7890f6d20ee9c7162cd84222cb0c7cb5b4f29244a58fc95327fc41045f476fb3da42fca76a1dd59222a7a7c3872d5af7d8dc254e003eccdb38f291619c51911df2b6ed67d0b459f4bc25819c0078777b9a1a24c72e7c037a3720a1edad5863ef5ac75ce816869c820859558d5721089ddbe331f55bef741396a3bbf85c6c1a
        XstatIUT = 0x54081a8fef2127a1f22ed90440b1b09c331d0614
        YstatIUT = 0x0b92af0468b841ea5de4ca91d895b5e922245421de57ed7a88d2de41610b208e8e233705f17b2e9eb91914bad2fa87f0a58519a7da2980bc06e7411c925a6050526bd86e621505e6f610b63fdcd9afcfaa96bd087afca44d9197cc35b559f731357a5b979250c0f3a254bb8165f5072156e3fd6f9a6e69bcf4b4578f78b3bde7
        Z = 0x8d8f4175e16e15a42eb9099b11528af88741cc206a088971d3064bb291eda608d1600bff829624db258fd15e95d96d3e74c6be3232afe5c855b9c59681ce13b7aea9ff2b16707e4c02f0e82bf6dadf2149ac62630f6c62dea0e505e3279404da5ffd5a088e8474ae0c8726b8189cb3d2f04baffe700be849df9f91567fc2ebb8

        dh, yb, zz = self.configure(locals())
        self.assertEqual(dh.calculate_public_key(), yb)
        self.assertEqual(dh.calculate_secret(), zz)

    def test_two(self):
        P = 0xda3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35
        G = 0xa51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288
        XstatCAVS = 0xd1f3fb87f2bc29a4d17ac1dc2539134e2b0e6ccb
        YstatCAVS = 0x29efe6b495ed5bd2976b8424876c435fb38f281606665f88e01487873f879714ef95702e5fe7e498b65a0b0be97946a5b8e3c534ab4e6a29beac5ac9e6c10a6729d3a291df26f03f7bd05df6f0267b2428be9103c5bc4a5d50de0e1e412213b43c280a9c464fbbfb252dc5ea7816a4b5ad469e9d84f93cadd31d6e78e38763fe
        XstatIUT = 0x303b2364c268fca21e946ca27d9f875eb8c7522a
        YstatIUT = 0xd767c076b28f1a45c45875a42a74205547dd1d6e5f36526d6dde3fe48b5341c4165c85ed0814b7826594c8e17440b9b3f69f3c3cbf8bb31b8082665d45c5329c8e7e9f391a5e1ee289d86d5a1d2e5e592b795d484f3dd5a83ec748d7071a9d506645a0c7cfc8bab1195c7e9d3cd78008ba64fa8c309e13ba75a5f2da44f1beb8
        Z = 0x8d8f4175e16e15a42eb9099b11528af88741cc206a088971d3064bb291eda608d1600bff829624db258fd15e95d96d3e74c6be3232afe5c855b9c59681ce13b7aea9ff2b16707e4c02f0e82bf6dadf2149ac62630f6c62dea0e505e3279404da5ffd5a088e8474ae0c8726b8189cb3d2f04baffe700be849df9f91567fc2ebb8

        dh, yb, zz = self.configure(locals())
        self.assertEqual(dh.calculate_public_key(), yb)
        self.assertNotEqual(dh.calculate_secret(), zz)

    def test_three(self):
        P = 0xda3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35
        G = 0xa51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288
        XstatCAVS = 0x2d0525095ce8caf27dd774c6b5ed08c7a2eab48e
        YstatCAVS = 0xb282ecaed6222bc4fa61f5df5f61a934aeb1df33171a9f146d1f0bac577719bb76629908ba6cef2e3818f617a8eb1cc523154e6d13b0844177e62500e3f620c3c267dfc1a0dc1fd6d71580f17cf274c143c0c7cd6024ad566361d047a99535e11e78768ae4f5717e43f9c0bc63bf9baf18ce9e9f92bdcdd338ae05c8e76dcfac
        XstatIUT = 0x96b2d41592887cfb0daeba29775d196f4017848b
        YstatIUT = 0x1a25a3bae36fa7206224a53962f9df8d2469e0b3c2ebd5825870e9b5b7dee4fc7ac5d55ade0797ac917f05b3ba790ff13ef553f80de8314b917d52e10c9f730af14b1793560017aa2c9de2e0332e75dc9e8ea3f5d50d168496c4821bd6ef49be3b79c9c40d0bf4dd55e2a147dea5caef5706fce5b985c8a198bf44c4c2f8686e
        Z = 0xb845b1c9950f1e20d527aae929430d48554ec8e755e817d950a5623e022145b94c5817bbebfd4dc4e33cab4f1799a79a01f7df3cee8769216abfe08a99046a99d867ef3b0f2b0f0b2f13694e88d1ef532ed32b6552a4ad14bdd88c745f442b7246c051c5b76508f74dbf7f1f8ad5e7d794b77e2748de296552b918e7d2a99307

        dh, yb, zz = self.configure(locals())
        self.assertEqual(dh.calculate_public_key(), yb)
        self.assertEqual(dh.calculate_secret(), zz)


class BtwocTests(unittest.TestCase):

    def test_one(self):
        tests = (
            (37, '%'),
            (3000000, '-\xc6\xc0'),
            (0, '\x00'),
            (1, '\x01'),
            (0x7fffffffffffffff, '\x7f\xff\xff\xff\xff\xff\xff\xff'),  # may be sys.maxint
            (0x8000000000000000, '\x00\x80\x00\x00\x00\x00\x00\x00\x00'),  # but these are longs
            (0xffffffffffffffff, '\x00\xff\xff\xff\xff\xff\xff\xff\xff'),
            (DEFAULT_MODULUS, '\x00\xdc\xf9:\x0b\x889r\xec\x0e\x19\x98\x9a\xc5\xa2\xce1\x0e\x1d7q~\x8d\x95q\xbbv#s\x18f\xe6\x1e\xf7Z.\'\x89\x8b\x05\x7f\x98\x91\xc2\xe2zc\x9c?)\xb6\x08\x14X\x1c\xd3\xb2\xca9\x86\xd2h7\x05W}E\xc2\xe7\xe5-\xc8\x1cz\x17\x18v\xe5\xce\xa7K\x14H\xbf\xdf\xaf\x18\x82\x8e\xfd%\x19\xf1NE\xe3\x82f4\xaf\x19I\xe5\xb55\xcc\x82\x9aH;\x8av">]I\n%\x7f\x05\xbd\xff\x16\xf2\xfb"\xc5\x83\xab'),
        )

        for num, text in tests:
            self.assertEqual(btwoc(num), text, "converting %d (0x%x) to two's complement" % (num, num))
            self.assertEqual(unbtwoc(text), num, "converting %r from two's complement" % text)


if __name__ == '__main__':
    unittest.main()
