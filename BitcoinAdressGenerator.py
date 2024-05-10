import os
import binascii
import hashlib
import base58
from ellipticcurve.privateKey import PrivateKey

# Constants
PREFIX_ODD = "03"
PREFIX_EVEN = "02"
VERSION_BYTE = b"\x00"
VERSION_BYTE_SEGWIT = b"\x05"
ADDRESS_LENGTH = 4


def ripemd160(data):
    """Creates a RIPEMD-160 hash of the given data."""
    hasher = hashlib.new('ripemd160')
    hasher.update(data)
    return hasher.digest()


def generate_private_key():
    """Generates a random private key."""
    return binascii.hexlify(os.urandom(32)).decode('utf-8')


def generate_public_key(private_key, compressed=True):
    """Generates a public key from the given private key."""
    private_key_obj = PrivateKey().fromString(bytes.fromhex(private_key))
    public_key_full = '04' + private_key_obj.publicKey().toString().hex()

    if compressed:
        int_y = int(public_key_full[66:130], 16)
        prefix = PREFIX_EVEN if int_y % 2 == 0 else PREFIX_ODD
        return prefix + public_key_full[2:66]
    else:
        return public_key_full


def generate_address(public_key, segwit=False):
    """Generates a Bitcoin address from the given public key."""
    pub_key_bytes = binascii.unhexlify(public_key)
    hash160 = ripemd160(hashlib.sha256(pub_key_bytes).digest())
    version_prefix = VERSION_BYTE_SEGWIT if segwit else VERSION_BYTE
    payload = version_prefix + hash160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:ADDRESS_LENGTH]
    return base58.b58encode(payload + checksum).decode('utf-8')


def main():
    priv_key = generate_private_key()
    public_key_non_comp = generate_public_key(priv_key, compressed=False)
    public_key_comp = generate_public_key(priv_key, compressed=True)

    print("NON-COMPRESSED ADDRESS =", generate_address(public_key_non_comp))
    print("COMPRESSED ADDRESS =", generate_address(public_key_comp))
    print("SEGWIT ADDRESS =", generate_address(public_key_non_comp, segwit=True))
    print("COMPRESSED SEGWIT ADDRESS =", generate_address(public_key_comp, segwit=True))
    print("PRIVATE KEY (HEX) =", priv_key)


if __name__ == "__main__":
    main()
