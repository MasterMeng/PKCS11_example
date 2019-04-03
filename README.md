# PKCS11_example
pkcs11 example base on opencryptoki and pykcs11

# install opencryptoki
Before using opencryptoki, please make sure the openssl version in your system is 1.0.2*

You can download opencryptoki from github:https://github.com/opencryptoki/opencryptoki
Then unzip opencryptoki.zip && cd opencryptoki
    ./bootstrap.sh && ./configure && make 
    groupadd pkcs11 && usermod -G pkcs11 root
    make install

# install PyKCS11
pip3 install pykcs11

*** Notes ***
You need to use root user 