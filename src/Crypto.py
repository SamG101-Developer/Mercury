from hashlib import sha256

HASH_ALGORITHM = sha256
DIGEST_SIZE = 32

RSA_KEY_SIZE = 2048
RSA_SIGNATURE_SIZE = 256
RSA_SECRET_KEY_PEM_SIZE = 1704
RSA_PUBLIC_KEY_PEM_SIZE = 426
RSA_CERTIFICATE_SIZE = DIGEST_SIZE + RSA_PUBLIC_KEY_PEM_SIZE
RSA_KEM_SIZE = 256

TIME_LENGTH = 32
IP_SIZE = 16
