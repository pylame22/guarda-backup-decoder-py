import json
import logging
from base64 import b64decode
from getpass import getpass
from hashlib import md5, pbkdf2_hmac

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def _get_backup() -> str:
    with open("guarda_backup.txt") as file:
        return file.read()


class GuardaBackupDecrypt:
    _PASSWORD_SALT = "XB7sHH26Hn&FmPLxnjGccKTfPV(yk"
    _PASSWORD_POSTFIX = "(tXntTbJFzh]4EuQVmjzM9GXHCth8"
    _BLOCK_SIZE = 16

    @staticmethod
    def _get_final_key(data: bytes, *, output_count: int) -> bytes:
        key, final_key = b"", b""
        while len(final_key) < output_count:
            key = md5(key + data).digest()
            final_key += key
        return final_key[:output_count]

    @classmethod
    def _patch_master_password(cls, password: str) -> str:
        hashed_password = pbkdf2_hmac("SHA1", password.encode(), cls._PASSWORD_SALT.encode(), iterations=1, dklen=16)
        return hashed_password.hex() + cls._PASSWORD_POSTFIX

    def __init__(self, password: str, backup_str: str) -> None:
        self._password = self._patch_master_password(password).encode()
        self._backup_encrypted = b64decode(backup_str)

    def _get_key_nonce(self) -> tuple[bytes, bytes]:
        data = self._password + self._backup_encrypted[self._BLOCK_SIZE // 2: self._BLOCK_SIZE]
        final_key = self._get_final_key(data, output_count=self._BLOCK_SIZE * 3)
        return final_key[:self._BLOCK_SIZE * 2], final_key[self._BLOCK_SIZE * 2:]

    def decrypt(self) -> str:
        key, nonce = self._get_key_nonce()
        aes = AES.new(key, AES.MODE_CBC, nonce)
        cipher = aes.decrypt(self._backup_encrypted[self._BLOCK_SIZE:])
        return unpad(cipher, self._BLOCK_SIZE).decode()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    password = getpass()
    gbd = GuardaBackupDecrypt(password, _get_backup())
    try:
        data = gbd.decrypt()
    except ValueError:
        raise Exception("Wrong password") from None
    data_json = json.loads(data)
    logging.info(json.dumps(data_json, indent=2))


if __name__ == "__main__":
    main()
