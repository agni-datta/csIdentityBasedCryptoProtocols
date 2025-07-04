import secrets
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPair:
    """Handles RSA key generation and storage."""

    def __init__(self):
        """Initializes KeyPair."""
        self.generate_keypair()

    def generate_keypair(self):
        """Generates an RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.n = self.public_key.public_numbers().n


class Hasher:
    """Provides hashing functionality using SHA-3."""

    @staticmethod
    def get_hash(data: bytes, hash_algorithm=hashes.SHA3_256()) -> bytes:
        """
        Returns the SHA-3 hash of the given data.

        :param data: Data to be hashed.
        :param hash_algorithm: Hash algorithm to use.
        :return: Hash of the data.
        """
        digest = hashes.Hash(hash_algorithm, backend=default_backend())
        digest.update(data)
        return digest.finalize()


class FiatShamirIdentification:
    """Implements the Fiat-Shamir identification scheme."""

    def __init__(self, password: str, key_pair: KeyPair):
        """
        Initializes the Fiat-Shamir identification process.

        :param password: Password for identification.
        :param key_pair: KeyPair object containing the RSA keys.
        """
        self.password = password
        self.private_key = key_pair.private_key
        self.public_key = key_pair.public_key
        self.n = key_pair.n
        self.password_hash = Hasher.get_hash(password.encode())

    def generate_commitment(self) -> bytes:
        """
        Generates a commitment by selecting a random value and computing its square modulo n.

        :return: Commitment value.
        """
        self.r = secrets.randbits(self.n.bit_length())
        self.r_squared = pow(self.r, 2, self.n)
        self.commitment = Hasher.get_hash(
            self.r_squared.to_bytes(
                (self.r_squared.bit_length() + 7) // 8, byteorder="big"
            )
        )
        return self.commitment

    def generate_challenge(self) -> bytes:
        """
        Generates a random challenge of 64 bytes.

        :return: Challenge value.
        """
        self.challenge = secrets.token_bytes(64)
        return self.challenge

    def compute_response(self, challenge: bytes) -> int:
        """
        Computes the response to the challenge using the commitment and the password.

        :param challenge: Challenge value.
        :return: Response value.
        """
        challenge_int = int.from_bytes(challenge, byteorder="big")
        password_int = int.from_bytes(self.password_hash, byteorder="big")
        self.s = (self.r * pow(password_int, challenge_int, self.n)) % self.n
        return self.s

    def verify_response(self, s: int, challenge: bytes) -> bool:
        """
        Verifies the response to the challenge.

        :param s: Response value.
        :param challenge: Challenge value.
        :return: True if the response is valid, False otherwise.
        """
        challenge_int = int.from_bytes(challenge, byteorder="big")
        password_int = int.from_bytes(self.password_hash, byteorder="big")
        v = pow(s, 2, self.n)
        expected_v = (
            self.r_squared * pow(password_int, 2 * challenge_int, self.n)
        ) % self.n
        return v == expected_v


def rotate_key(key_pair: KeyPair):
    """
    Rotates the RSA key pair.

    :param key_pair: KeyPair object to be rotated.
    """
    key_pair.generate_keypair()


def initialize_fiat_shamir(password: str) -> Tuple[FiatShamirIdentification, KeyPair]:
    """
    Initializes the Fiat-Shamir identification process.

    :param password: Password for identification.
    :return: Tuple containing the FiatShamirIdentification object and the KeyPair object.
    """
    key_pair = KeyPair()
    fsi = FiatShamirIdentification(password, key_pair)
    return fsi, key_pair


def perform_prover_tasks(fsi: FiatShamirIdentification) -> Tuple[bytes, bytes, int]:
    """
    Performs tasks related to the prover in the Fiat-Shamir identification process.

    :param fsi: FiatShamirIdentification object.
    :return: Tuple containing the commitment, challenge, and response.
    """
    commitment = fsi.generate_commitment()
    print("Commitment sent to verifier:", commitment.hex())

    challenge = fsi.generate_challenge()
    print("Challenge sent by verifier:", challenge.hex())

    response = fsi.compute_response(challenge)
    print("Response sent to verifier:", response)

    return commitment, challenge, response


def perform_verifier_tasks(
    fsi: FiatShamirIdentification, challenge: bytes, response: int
) -> bool:
    """
    Performs tasks related to the verifier in the Fiat-Shamir identification process.

    :param fsi: FiatShamirIdentification object.
    :param challenge: Challenge value.
    :param response: Response value.
    :return: True if the response is valid, False otherwise.
    """
    is_valid = fsi.verify_response(response, challenge)
    print("Identification valid:", is_valid)
    return is_valid


def main():
    """
    Main function to orchestrate the Fiat-Shamir identification process.
    """
    # Initialize

    password = "secure_password"
    fsi, key_pair = initialize_fiat_shamir(password)

    # Prover tasks

    commitment, challenge, response = perform_prover_tasks(fsi)

    # Verifier tasks

    is_valid = perform_verifier_tasks(fsi, challenge, response)

    # Rotate keys

    rotate_key(key_pair)


if __name__ == "__main__":
    main()
