package src.paillier.crypto;

import java.math.BigInteger;
import java.security.*;

/**
 * The Key interface is the top-level interface for all keys.
 * 
 * An Algorithm - This is the key algorithm for that key - Paillier.
 * 
 * An Encoded Form - This is an external encoded form for the key,the Paillier
 * key does not supported encoded according to a standard format.
 * 
 * The public and private key classes both descend from PaillierKey, which is
 * simply a container for n and nsquare used in both classes PaillierPublicKey
 * and PaillierPrivateKey.
 * 
 * @version 12-03-13
 */
public class PaillierKey implements Key {

	/**
	 * 
	 */
	private static final long serialVersionUID = -956635038205758445L;
	private BigInteger N;
	private BigInteger NSquare;
	private BigInteger R;

	protected PaillierKey(BigInteger n, BigInteger nsquare) {
		N = n;
		NSquare = nsquare;

	}

	public BigInteger getN() {
		return N;
	}

	public BigInteger getNSquare() {
		return NSquare;
	}

	/**
	 * Returns the standard algorithm name for this key.
	 * 
	 * @return Paillier
	 */
	public String getAlgorithm() {
		return "Paillier";
	}

	/**
	 * Returns the key in its primary encoding format, or null if this key does
	 * not support encoding.
	 * 
	 * @return null
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Returns the name of the primary encoding format of this key, or null if
	 * this key does not support encoding.
	 * 
	 * @return null
	 */
	public String getFormat() {
		return "NONE";
	}

	/**
	 * This method generates a random <code>r</code> in <code>Z_{n}^*</code> for
	 * each separate encryption using the same modulus n Paillier cryptosystem
	 * allows the generated r to differ every time, such that the same plaintext
	 * encrypted several times will produce different ciphertext every time.
	 * This method is called from <code>PaillierHomomorphicCipher.encrypt</code>
	 * or <code>PaillierCipher.encrypt</code>.
	 * 
	 * @param n
	 *            -BigInteger
	 * @param SECURE_RANDOM
	 * @return r -BigInteger
	 */
	public BigInteger generateRandomRinZn(BigInteger n,
			SecureRandom SECURE_RANDOM) {
		BigInteger r;
		int strength = 0;
		strength = n.bitLength(); // use the same key size as initialised
		// generate r random integer in Z*_n
		do {
			r = new BigInteger(strength , 64,SECURE_RANDOM);
		} while (r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1);
		
		R = r;
		return r;
	}

	/**
	 * Returns the modulus n and r separate by commas represent in String
	 * format. This method should be removed,its used only for E Voting -
	 * Paillier Application . Instead should be implemented KeyStore,
	 * KeyPairGeneratorSpec - in order to get n.
	 * 
	 * @return keyComponent - the modulus n or r (String)
	 */
	public String toString() {
		return "n:" + N + ",r:" + R;
	}

}
