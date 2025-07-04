import os
from typing import ByteString

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def generate_seed() -> ByteString:
    """
    Generates a random seed of 16 bytes using a cryptographically secure pseudorandom number generator (CSPRNG).

    Returns:
        ByteString: A random seed of 16 bytes.
    """
    return os.urandom(16)


def calculate_proof(seed: ByteString, age_actual: int, age_to_prove: int) -> ByteString:
    """
    Calculates the proof based on the given seed and ages.

    Args:
        seed (ByteString): The seed value used for calculations.
        age_actual (int): Peggy's actual age.
        age_to_prove (int): Peggy's age to prove.

    Returns:
        ByteString: The calculated proof.
    """
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(seed)
    proof = digest.finalize()

    for _ in range(age_actual - age_to_prove):
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(proof)
        proof = digest.finalize()

    return proof


def calculate_encrypted_age(seed: ByteString, age_actual: int) -> ByteString:
    """
    Calculates the encrypted age based on the given seed and actual age.

    Args:
        seed (ByteString): The seed value used for calculations.
        age_actual (int): Peggy's actual age.

    Returns:
        ByteString: The calculated encrypted age.
    """
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(seed)
    encrypted_age = digest.finalize()

    for _ in range(age_actual):
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(encrypted_age)
        encrypted_age = digest.finalize()

    return encrypted_age


def verify_age(
    encrypted_age: ByteString, proof: ByteString, age_to_prove: int
) -> ByteString:
    """
    Verifies Peggy's age using the encrypted age and proof.

    Args:
        encrypted_age (ByteString): The encrypted age calculated based on Peggy's actual age.
        proof (ByteString): The proof calculated based on the seed and Peggy's actual age.
        age_to_prove (int): Peggy's age to prove.

    Returns:
        ByteString: The verified age.
    """
    verified_age = proof
    for _ in range(age_to_prove):
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(verified_age)
        verified_age = digest.finalize()
    return verified_age


if __name__ == "__main__":
    # Parameters
    age_actual: int = 19
    age_to_prove: int = 18

    # Generate NIST-specified seed
    seed: ByteString = generate_seed()

    # Calculate proof
    proof: ByteString = calculate_proof(seed, age_actual, age_to_prove)

    # Calculate encrypted age
    encrypted_age: ByteString = calculate_encrypted_age(seed, age_actual)

    # Verify age
    verified_age: ByteString = verify_age(encrypted_age, proof, age_to_prove)

    # Output
    print("Age to prove:\t\t", age_to_prove)
    print("Peggy's Age:\t\t", age_actual)
    print("Seed:\t\t\t", seed.hex())
    print("....")
    print("Encrypted Age:\t", encrypted_age.hex())
    print("Proof:\t\t", proof.hex())
    print("Verified Age:\t", verified_age.hex())

    # Verification
    if encrypted_age == verified_age:
        print("You have proven your age. Please come in.")
    else:
        print("You have not proven your age.")
