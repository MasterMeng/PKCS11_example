from PyKCS11 import *

Mechanisms = {
    'CKK_AES': MechanismAESGENERATEKEY,
}


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
            (CKA_EXTRACTABLE, True),
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
            (CKA_EXTRACTABLE, True),
            (CKA_SIGN, True),
            (CKA_VERIFY, True),
            (CKA_WRAP, True),
            (CKA_UNWRAP, True),
        ]
        mkeks = self.session.findObjects(
            [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, key_type), (CKA_LABEL, label), ])
        for mkek in mkeks:
            self.session.destroyObject(mkek)
        self.session.generateKey(tem, Mechanisms[key_type])


if __name__ == "__main__":
    t = OpenCryptoKi('/usr/local/lib/opencryptoki/libopencryptoki.so')
    t.initpin('87654321', '123456')
    t.login('123456')
    t.logout()
