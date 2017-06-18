package src.paillier.crypto;

import java.math.BigInteger;
import java.security.*;

/**
 * The PaillierKeyPairGenerator class is used to generate pairs of public and
 * private keys. Key pair generators are constructed using the getInstance
 * factory methods (static methods that return instances of a given class).
 * 
 * A Key pair generator for a particular algorithm creates a public/private key
 * pair that can be used with this algorithm.
 * 
 * There are two ways to generate a key pair: in an algorithm-independent
 * manner, and in an algorithm-specific manner. The only difference between the
 * two is the initialization of the object.
 * 
 * @version 12-02-13
 */
public final class PaillierKeyPairGenerator extends KeyPairGeneratorSpi {

	private int STRENGTH = 0;
	private SecureRandom SECURE_RANDOM = null;
	private int KEYSIZE_MIN = 8;
	private int KEYSIZE_DEFAULT = 64;
	private int KEYSIZE_MAX = 3096;
	
	
	/**
	 * Initialises <code>KeyPairGenerator</code> The key size is bound between 8
	 * and 3096 bits. If its not within this rang, key size is set to default-64
	 * bits.
	 * 
	 * @param strength
	 *            Bit length of modulus n
	 * @param random
	 */
	
	public final void initialize(int strength, SecureRandom random) {
		SECURE_RANDOM = random;
		if(strength < KEYSIZE_MIN || strength > KEYSIZE_MAX)
		STRENGTH = KEYSIZE_DEFAULT;		
		else
			STRENGTH = strength;
	}
	  
	/**
	 * This class is a simple holder for a key pair (a public key and a private
	 * key). Constructs a key pair from the given public key and private key.
	 * @return KeyPair - publicKey and privateKey
	 */
	public final KeyPair generateKeyPair() {
		if (SECURE_RANDOM == null) {
			SECURE_RANDOM = new SecureRandom();
		}
		// for p and q we divide the bits length by 2 , as they create n, 
		// which is the modulus and actual key size is depend on it
		BigInteger p = new BigInteger(STRENGTH / 2, 64, SECURE_RANDOM);
		BigInteger q;
		do {
			q = new BigInteger(STRENGTH / 2, 64, SECURE_RANDOM);
		} while (q.compareTo(p) == 0);

		// lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
		BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q
				.subtract(BigInteger.ONE)).divide(p.subtract(BigInteger.ONE)
				.gcd(q.subtract(BigInteger.ONE)));

		BigInteger n = p.multiply(q); // n = p*q
		BigInteger nsquare = n.multiply(n); // nsquare = n*n
		BigInteger g;
		do {
			// generate g, a random integer in Z*_{n^2}
			do {
				g = new BigInteger(STRENGTH, 64, SECURE_RANDOM);
			} while (g.compareTo(nsquare) >= 0
					|| g.gcd(nsquare).intValue() != 1);

			// verify g, the following must hold: gcd(L(g^lambda mod n^2), n) =
			// 1,
			// where L(u) = (u-1)/n
		} while (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n)
				.gcd(n).intValue() != 1);

		// mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n
		BigInteger mu = g.modPow(lambda, nsquare).subtract(BigInteger.ONE)
				.divide(n).modInverse(n);

		PaillierPublicKey publicKey = new PaillierPublicKey(n, g, nsquare);
		PaillierPrivateKey privateKey = new PaillierPrivateKey(lambda, mu,
				nsquare, n);

		return new KeyPair(publicKey, privateKey);
	}

}
