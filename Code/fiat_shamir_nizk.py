from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
import secrets
import hashlib


class FiatShamirNIZK:
    """
    Implementation of a Fiat-Shamir Non-Interactive Zero-Knowledge Proof (NIZK) system.
    """

    def __init__(self, key_size=1024, generator=5):
        """
        Initializes the FiatShamirNIZK object.

        Args:
        key_size (int): Size of the key in bits.
        generator (int): Generator for the Diffie-Hellman key exchange.

        Returns:
        None
        """
        self.zkpParameters = dh.generate_parameters(
            generator=generator, key_size=key_size, backend=default_backend()
        )
        self.zkpPrivateKey = self.zkpParameters.generate_private_key()
        self.zkpPublicKey = self.zkpPrivateKey.public_key()

    def zkpKeyGeneration(self):
        """
        Generates key parameters for the Fiat-Shamir NIZK system.

        Returns:
        tuple: A tuple containing the prime modulus (`primeModulus`), generator (`generator`),
        public key (`publicKey`), and private key (`privateKey`).
        """
        primeModulus = self.zkpParameters.parameter_numbers().p
        generator = self.zkpParameters.parameter_numbers().g
        privateKey = self.zkpPrivateKey.private_numbers().x
        publicKey = self.zkpPublicKey.public_numbers().y
        return primeModulus, generator, publicKey, privateKey

    def zkpProverAlgorithm(self, primeModulus, generator, privateKey, userInput):
        """
        Prover's algorithm for the Fiat-Shamir NIZK system.

        Args:
        primeModulus (int): Prime modulus.
        generator (int): Generator of the multiplicative group.
        privateKey (int): Private key.
        userInput (str): User input.

        Returns:
        tuple: A tuple containing the proof values (y, z).
        """
        randomValue = secrets.randbelow(primeModulus - 1)
        yValue = pow(generator, randomValue, primeModulus)
        hashInput = int.from_bytes(
            hashlib.sha3_256(str(userInput + str(yValue)).encode()).digest(),
            byteorder="big",
        )
        zValue = (randomValue - privateKey * hashInput) % (primeModulus - 1)
        return yValue, zValue

    def zkpVerifierAlgorithm(
        self, primeModulus, generator, publicKey, userInput, proof
    ):
        """
        Verifier's algorithm for the Fiat-Shamir NIZK system.

        Args:
        primeModulus (int): Prime modulus.
        generator (int): Generator of the multiplicative group.
        publicKey (int): Public key.
        userInput (str): User input.
        proof (tuple): A tuple containing the proof values (y, z).

        Returns:
        bool: True if the proof is valid, False otherwise.
        """
        yValue, zValue = proof
        hashInput = int.from_bytes(
            hashlib.sha3_256(str(userInput + str(yValue)).encode()).digest(),
            byteorder="big",
        )
        return (
            pow(generator, zValue, primeModulus)
            * pow(publicKey, hashInput, primeModulus)
            % primeModulus
            == yValue
            if 0 < yValue < primeModulus
            and 0 <= zValue < primeModulus - 1
            and 0 <= hashInput < primeModulus - 1
            else False
        )


if __name__ == "__main__":
    zkpInstance = FiatShamirNIZK()
    primeModulus, generator, publicKey, privateKey = zkpInstance.zkpKeyGeneration()
    password = "secured"
    proof = zkpInstance.zkpProverAlgorithm(
        primeModulus, generator, privateKey, password
    )
    isVerified = zkpInstance.zkpVerifierAlgorithm(
        primeModulus, generator, publicKey, password, proof
    )
    print("Public key (p, g, v):", (primeModulus, generator, publicKey))
    print("Proof (y, z):", proof)
    print("Verification Result:", isVerified)
