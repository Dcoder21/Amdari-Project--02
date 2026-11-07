"""Test fixtures for kyc-api.

Sets the matching half of payments-api's throwaway test keypair (see
services/payments-api/tests/conftest.py) into the environment before
app.auth is imported, so kyc-api's tests verify against the same pair
payments-api's tests sign with. The two services build from separate
Docker contexts, so this is a deliberate, clearly-labelled duplication of
the same non-secret test fixture rather than a cross-service import.

kyc-api's app code is only ever given JWT_PUBLIC_KEY_B64 (it never issues
tokens in production), but the *test* private key is also exposed here so
this suite can mint tokens standing in for payments-api, the same way a
real client would present a token payments-api issued.
"""
import base64
import os

_TEST_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUpk0Cj9NvmLl0
xKnS90Imy+V+XbSyc18KPWOAaUmcyaylcW8sOb7BuCruhbTtA5osB1D85fcY2kF0
WWI6L1I8/oxOuDi0/xJEMO7IdjBMLco2O3gYFlnSk0bQet3C0Hsg0l6gKP3EnHlO
Rd8X9e+8TXLIejTPdr7o+viM0vSOHLv8HueC788EmKGG+Y801QWgWA+46U0UhTDI
2eCrMK7i3wFYfcSoSvTIImno8Gh/aagVmfST3HWxJhBDY/WkZlsBA3TQ17gjE4+t
Ss9Yk/a7asyQ2FijVe6qc3Z3Y6unTFE5n+uuY4Gb2PPbh7burjcs+CuWkZNEdFcr
oxn54IzjAgMBAAECggEAFAETQQKA9jYr0wJ6Rik/LkBnOGu82vz6r8KWJtxEa0Sa
psMOrnlw6dnycRnuQK0o7L7pT7dU2vPYNiOnO+RNYWbyE8/n1bezyhh5seFx23aY
DVdQcJFlchiewYSfXk23HDIjSNNrXy+dhYKSpMNUiVc02LTVcYvt4iWQGEd1YMBZ
ighR4Gf/4WUXU2s01UIIc9FJ1uGdOwKo5HhSFHETHKcMD6czxB919LbqfiUf0Kn2
FNNLL28iq8RK0yyt1F2J76rsZZi2eOVjYKAHJRHiavEbE7l+SvJWr+sdOO5YQJwd
P67INydCs9UeC86un2PKhxLb1bhI2VESyR6uyBujHQKBgQDRn4Pr9kYprkBRmUPC
ExjOGNfkARWEpuevAWs3fqe06uLaAk+YjLxr8E7t1hHBTodtwNWqR2LM6fq+6poA
DXgMts7Hy6U9hb4VUERYGjX1b/ItNo2Yhsdc1bjPWeILbhKaTeahwebHGMA7IYFJ
gZLs0SqIwp5CHpeYaPmc7zLrnwKBgQC1iWl6+/CQYhZI6xjKBudub/tteQ8CKJBu
7CjDa8AgGmB6VRWPYjcl0FOSrwPO64RC/LuU+j+EF1sxyAh/O3yHAHfBIpkSSjSv
PCQQqStw6+3yiIeAqUJt1J5n5N+fhzlIgnGGAryeyfwXI0iNUwdaAgNHo3yypTCO
dF0fUiiYPQKBgCYlVwZbfI0dLosqzs/EVeE7WB4frGDFVqfcJDynCbG8hKeTgBSM
l8U0p8hUCksZFT/9tWQVNX+AnKadXoTf7paxtZNaFanKarrKLoWxz1vokTN1F/NH
o4PbSJRDEQVvdGcsAeoxtONKN8EK6dIMiEYcEhdtAwuZMZEEmVfbl3KVAoGAb98d
fKezyRZZS1ht71ov1tP1qrH2uMrMrz6jpEJLpLz8hYbXgYPyHkBysCtgemyTFkDv
TFCnQbyu+0+dROMgy4VTR1cN48KNEwxJ4WaPGcia22KdtoEYKdzkPXxC/ulzOKcC
VKZtHKG2039v33+yQRqKcORkHSdFdBRrqriTwbUCgYEAu9+8lwKiUuP0lQObLoi/
V1O0GP2PTxzqxGsBM7r15KTXrtMKBIgsKCaitCHwGquJk/1DpaGWDeAV3T3uV4LY
C01oKxpLGSjJ9L2ZL1m9RXwODMoHwhZmfjsu31/hJmUfNrpD9TNwWX1coqBxv34T
ISDGtrRcJlDcHb1xE5yfA0M=
-----END PRIVATE KEY-----
"""

_TEST_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlKZNAo/Tb5i5dMSp0vdC
Jsvlfl20snNfCj1jgGlJnMmspXFvLDm+wbgq7oW07QOaLAdQ/OX3GNpBdFliOi9S
PP6MTrg4tP8SRDDuyHYwTC3KNjt4GBZZ0pNG0HrdwtB7INJeoCj9xJx5TkXfF/Xv
vE1yyHo0z3a+6Pr4jNL0jhy7/B7ngu/PBJihhvmPNNUFoFgPuOlNFIUwyNngqzCu
4t8BWH3EqEr0yCJp6PBof2moFZn0k9x1sSYQQ2P1pGZbAQN00Ne4IxOPrUrPWJP2
u2rMkNhYo1XuqnN2d2Orp0xROZ/rrmOBm9jz24e27q43LPgrlpGTRHRXK6MZ+eCM
4wIDAQAB
-----END PUBLIC KEY-----
"""


def _ensure_test_keys_in_env():
    os.environ["JWT_PUBLIC_KEY_B64"] = base64.b64encode(_TEST_PUBLIC_KEY_PEM.encode()).decode()


_ensure_test_keys_in_env()


def get_test_private_key_pem() -> str:
    return _TEST_PRIVATE_KEY_PEM
