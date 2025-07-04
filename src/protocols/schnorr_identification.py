import hashlib
import secrets


def keyGeneration():
    """
    Generates parameters for a Schnorr-like identification scheme.

    Returns:
    tuple: A tuple containing the prime modulus (`primeModulus`), generator (`generator`),
    public key (`publicKey`), and private key (`privateKey`).
    """
    primeModulus = (
        115792089237316195423570985008687907853269984665640564039457584007913129639747
    )
    generator = 5
    privateKey = secrets.randbits(256) % (primeModulus - 1) + 1
    publicKey = pow(generator, privateKey, primeModulus)
    return primeModulus, generator, publicKey, privateKey


def proverAlgorithm(primeModulus, generator, privateKey, userInput):
    """
    Prover's algorithm for the Schnorr-like identification scheme.

    Args:
    primeModulus (int): Prime modulus.
    generator (int): Generator of the multiplicative group.
    privateKey (int): Private key.
    userInput (str): User input (e.g., password).

    Returns:
    tuple: A tuple containing the proof values (y, z).
    """
    randomValue = secrets.randbits(256) % (primeModulus - 1) + 1
    yValue = pow(generator, randomValue, primeModulus)
    hashInput = int.from_bytes(
        hashlib.sha256((str(userInput) + str(yValue)).encode()).digest(),
        byteorder="big",
    )
    zValue = (randomValue - privateKey * hashInput) % (primeModulus - 1)
    return yValue, zValue


def verifierAlgorithm(primeModulus, generator, publicKey, userInput, proof):
    """
    Verifier's algorithm for the Schnorr-like identification scheme.

    Args:
    primeModulus (int): Prime modulus.
    generator (int): Generator of the multiplicative group.
    publicKey (int): Public key.
    userInput (str): User input (e.g., password).
    proof (tuple): A tuple containing the proof values (y, z).

    Returns:
    bool: True if the proof is valid, False otherwise.
    """
    yValue, zValue = proof
    hashInput = int.from_bytes(
        hashlib.sha256((str(userInput) + str(yValue)).encode()).digest(),
        byteorder="big",
    )
    return (
        pow(generator, zValue, primeModulus)
        * pow(publicKey, hashInput, primeModulus)
        % primeModulus
        == yValue
    )


if __name__ == "__main__":
    primeModulus, generator, publicKey, privateKey = keyGeneration()
    password = "secure_password"
    proof = proverAlgorithm(primeModulus, generator, privateKey, password)
    isVerified = verifierAlgorithm(primeModulus, generator, publicKey, password, proof)
    print("Public key (p, g, v):", (primeModulus, generator, publicKey))
    print("Proof (y, z):", proof)
    print("Verification Result:", isVerified)
