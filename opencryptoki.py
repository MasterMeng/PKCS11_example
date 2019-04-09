from PyKCS11 import *

# import ptvsd

# ptvsd.enable_attach(address=('0.0.0.0', 5678))
# ptvsd.wait_for_attach()

aes_iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
          0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]


class OpenCryptoKi:
    def __init__(self, libpath):
        self.pkcs11 = PyKCS11Lib()
        self.pkcs11.load(libpath)
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]

    def login(self, userpin):
        self.session = self.pkcs11.openSession(
            self.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        self.session.login(userpin, user_type=CKU_USER)

    def logout(self):
        self.session.logout()
        self.session.closeSession()

    def initpin(self, sopin, userpin):
        self.session = self.pkcs11.openSession(
            self.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        self.session.login(sopin, user_type=CKU_SO)

        self.session.initPin(userpin)
        self.session.logout()
        self.session.closeSession()

    def genhamc(self, label):
        tem = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
            (CKA_LABEL, label),
            (CKA_PRIVATE, True),
            (CKA_SENSITIVE, True),
            (CKA_ENCRYPT, True),
            (CKA_DECRYPT, True),
            (CKA_TOKEN, True),
            (CKA_EXTRACTABLE, False),
        ]

        hmacs = self.session.findObjects(
            [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_GENERIC_SECRET), (CKA_LABEL, label), ])
        for hmac in hmacs:
            self.session.destroyObject(hmac)
        self.session.generateKey(
            tem, mecha=Mechanism(CKM_GENERIC_SECRET_KEY_GEN))

    def genmkek(self, key_type, key_len, label):
        tem = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, key_type),
            (CKA_VALUE_LEN, key_len),
            (CKA_LABEL, label),
            (CKA_PRIVATE, True),
            (CKA_SENSITIVE, True),
            (CKA_ENCRYPT, True),
            (CKA_DECRYPT, True),
            (CKA_TOKEN, True),
            (CKA_EXTRACTABLE, False),
            (CKA_SIGN, True),
            (CKA_VERIFY, True),
            (CKA_WRAP, True),
            (CKA_UNWRAP, True),
        ]
        mkeks = self.session.findObjects(
            [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, key_type), (CKA_LABEL, label), ])
        for mkek in mkeks:
            self.session.destroyObject(mkek)
        self.session.generateKey(tem, MechanismAESGENERATEKEY)

    def findobjs(self, key_class, key_type, label):
        objs = self.session.findObjects(
            [(CKA_CLASS, key_class), (CKA_KEY_TYPE, key_type), (CKA_LABEL, label), ])
        return objs

    def genkey(self, key_class, key_type, key_len, label):
        tem = [
            (CKA_CLASS, key_class),
            (CKA_KEY_TYPE, key_type),
            (CKA_VALUE_LEN, key_len),
            (CKA_LABEL, label),
            (CKA_PRIVATE, True),
            (CKA_SENSITIVE, True),
            (CKA_ENCRYPT, True),
            (CKA_DECRYPT, True),
            (CKA_TOKEN, True),
            (CKA_EXTRACTABLE, True),
        ]
        objs = self.session.findObjects(
            [(CKA_CLASS, key_class), (CKA_KEY_TYPE, key_type), (CKA_VALUE_LEN, key_len), (CKA_LABEL, label), ])
        for obj in objs:
            self.session.destroyObject(obj)
        self.session.generateKey(tem, MechanismRSAGENERATEKEYPAIR)

    def genkeypair(self, label):
        pubTem = [
            (CKA_MODULUS_BITS, 0x0400),
            (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
        ]
        priTem = [
        ]
        return self.session.generateKeyPair(
            pubTem, priTem, MechanismRSAGENERATEKEYPAIR)

    def wrap(self, key, wrapping):
        return self.session.wrapKey(key, wrapping, Mechanism(CKM_AES_CBC_PAD, aes_iv))

    def unwrap(self, key, wrapped, wrapped_class):
        return self.session.unwrapKey(key, wrapped, [(CKA_CLASS, wrapped_class)], Mechanism(CKM_AES_CBC_PAD, aes_iv))

    def encrypt(self, key, msg):
        enc = self.session.encrypt(
            key, msg.encode('utf-8'), Mechanism(CKM_AES_CBC))
        return bytes(enc)

    def decrypt(self, key, enc):
        dec = self.session.decrypt(key, enc, Mechanism(CKM_AES_CBC))
        return bytes(dec)


if __name__ == "__main__":
    t = OpenCryptoKi('/usr/local/lib/opencryptoki/libopencryptoki.so')
    t.login('123456')

    t.genmkek(CKK_AES, 32, 'MKEK')
    # print('######## MKEK #######')
    obj = t.findobjs(CKO_SECRET_KEY, CKK_AES, 'MKEK')[0]
    # for obj in objs:
    #     print(obj)

    # t.genhamc('HMAC')
    # print('######## HMAC #######')
    # objs = t.findobjs(CKO_SECRET_KEY,CKK_GENERIC_SECRET, 'HMAC')
    # for obj in objs:
    #     print(obj)

    pub, pri = t.genkeypair('RSA Key')
    pri = t.findobjs(CKO_PRIVATE_KEY, CKK_RSA, 'RSA Key')[0]
    # print(pri)

    wrapped = t.wrap(obj, pri)
    print(wrapped)
    print(bytes(wrapped))
    t.logout()
