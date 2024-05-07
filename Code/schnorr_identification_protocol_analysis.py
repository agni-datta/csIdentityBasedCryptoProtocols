from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import List
from typing import Optional
import timeit
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import random
import string
import pandas as pd


def generate_random_unicode_string(length: int = 512) -> str:
    """
    Generates a random Unicode string of specified length.

    Args:
    - length (int): Length of the string to generate.

    Returns:
    - str: Random Unicode string.
    """
    return "".join(random.choices(string.printable, k=length))


class SchnorrProtocol:
    """
    Implements the Schnorr Non-Interactive Identification Protocol.
    """

    def __init__(self):
        """
        Initializes the SchnorrProtocol object.
        """
        pass

    def generate_key_pair(
        self,
    ) -> (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey):
        """
        Generates an elliptic curve key pair.

        Returns:
        - tuple: A tuple containing the private key and public key.
        """
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_nonce(self) -> bytes:
        """
        Generates a random nonce.

        Returns:
        - bytes: Random nonce.
        """
        nonce_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        nonce = nonce_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        return nonce

    def create_challenge(
        self, password: str, nonce: bytes, public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        """
        Creates a challenge for the identification protocol.

        Args:
        - password (str): The password.
        - nonce (bytes): The nonce.
        - public_key (ec.EllipticCurvePublicKey): The public key.

        Returns:
        - bytes: The challenge.
        """
        challenge = (
            password.encode("utf-8")
            + nonce
            + public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
        )
        return challenge

    def hash_challenge(self, challenge: bytes) -> bytes:
        """
        Hashes the challenge using SHA3-256.

        Args:
        - challenge (bytes): The challenge.

        Returns:
        - bytes: The hashed challenge.
        """
        hash_function = hashes.SHA3_256()
        hasher = hashes.Hash(hash_function, default_backend())
        hasher.update(challenge)
        hashed_challenge = hasher.finalize()
        return hashed_challenge

    def sign_challenge(
        self, private_key: ec.EllipticCurvePrivateKey, hashed_challenge: bytes
    ) -> bytes:
        """
        Signs the hashed challenge using the private key.

        Args:
        - private_key (ec.EllipticCurvePrivateKey): The private key.
        - hashed_challenge (bytes): The hashed challenge.

        Returns:
        - bytes: The signature.
        """
        signature = private_key.sign(hashed_challenge, ec.ECDSA(hashes.SHA3_256()))
        return signature

    def verify_signature(
        self,
        public_key: ec.EllipticCurvePublicKey,
        signature: bytes,
        hashed_challenge: bytes,
    ) -> bool:
        """
        Verifies the signature using the public key.

        Args:
        - public_key (ec.EllipticCurvePublicKey): The public key.
        - signature (bytes): The signature.
        - hashed_challenge (bytes): The hashed challenge.

        Returns:
        - bool: True if the signature is valid, False otherwise.
        """
        try:
            public_key.verify(signature, hashed_challenge, ec.ECDSA(hashes.SHA3_256()))
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False


def schnorr_protocol_execution_time(
    password: str, ecc_bits: int, sample_size: int
) -> List[float]:
    """
    Measure the execution time of the Schnorr protocol for a given ECC key size.

    Args:
    - password (str): The password for the identification protocol.
    - ecc_bits (int): The number of bits in the ECC key.
    - sample_size (int): The number of samples to collect for statistics.

    Returns:
    - List[float]: A list of execution times for each sample.
    """
    protocol = SchnorrProtocol()
    execution_times = []

    for _ in range(sample_size):
        private_key, public_key = protocol.generate_key_pair()
        nonce = protocol.generate_nonce()
        challenge = protocol.create_challenge(password, nonce, public_key)
        hashed_challenge = protocol.hash_challenge(challenge)

        start_time = timeit.default_timer()
        signature = protocol.sign_challenge(private_key, hashed_challenge)
        verified = protocol.verify_signature(public_key, signature, hashed_challenge)
        end_time = timeit.default_timer()

        if not verified:
            print("Verification failed. Skipping time measurement.")
            continue
        execution_time = end_time - start_time
        execution_times.append(execution_time)
    return execution_times


def print_statistics(execution_times: List[float], ecc_bits: int) -> None:
    """
    Print statistics of execution times.

    Args:
    - execution_times (List[float]): List of execution times.
    - ecc_bits (int): The number of bits in the ECC key.

    Returns:
    - None
    """
    mean_time = np.mean(execution_times)
    std_dev = np.std(execution_times)

    print(f"ECC Key Size: {ecc_bits} bits")
    print(f"Mean Execution Time: {mean_time:.10f} seconds")
    print(f"Standard Deviation: {std_dev:.10f} seconds")


def plot_execution_times(
    execution_times: List[float], sample_size: int, ecc_bits: int
) -> None:
    """
    Plot the execution times.

    Args:
    - execution_times (List[float]): List of execution times.
    - sample_size (int): The number of samples.
    - ecc_bits (int): The number of bits in the ECC key.

    Returns:
    - None
    """
    sns.set(style="whitegrid")
    plt.figure(figsize=(10, 6))

    # Plotting the execution times with a logarithmic scale on the x-axis

    plt.plot(
        np.arange(1, len(execution_times) + 1),
        execution_times,
        label=f"ECC {ecc_bits} bits",
        marker="o",
    )

    # Adding labels and title

    plt.xlabel("Sample Size (log scale)")
    plt.ylabel("Execution Time (seconds)")
    plt.title(f"Protocol Execution Time Analysis (ECC {ecc_bits} bits)")

    # Adding legend with 10^x format

    plt.legend()
    plt.xscale("log", base=10)
    plt.xticks(
        [10, 100, 1000, 10000, 100000],
        ["$10^1$", "$10^2$", "$10^3$", "$10^4$", "$10^5$"],
    )

    # Using LaTeX Latin Modern font

    plt.rcParams["text.usetex"] = True
    plt.rcParams["font.family"] = "Latin Modern Math"

    # Adjusting DPI for better resolution

    plt.savefig(f"schnorr_protocol_execution_time_ecc_{ecc_bits}_bits.png", dpi=500)

    # Show the plot

    plt.show()


if __name__ == "__main__":
    # Define the increased sample size for testing (e.g., 10000)

    sample_size = 100000

    # Test for ECC key sizes of 192, 224, 256, 384, and 521 bits

    ecc_bits_list = [192, 224, 256, 384, 521]
    all_execution_times = []

    data = {"ECC Key Size": [], "Execution Time": []}
    for ecc_bits in ecc_bits_list:
        password = generate_random_unicode_string()
        execution_times = schnorr_protocol_execution_time(
            password, ecc_bits, sample_size
        )

        # Print statistics

        print_statistics(execution_times, ecc_bits)

        # Plot the execution times

        plot_execution_times(execution_times, sample_size, ecc_bits)

        # Store data for correlation scatterplot

        data["ECC Key Size"].extend([ecc_bits] * sample_size)
        data["Execution Time"].extend(execution_times)
    # Create a DataFrame for correlation scatterplot

    df = pd.DataFrame(data)
