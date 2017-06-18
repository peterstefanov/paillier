package src.paillier.crypto;

import java.math.BigInteger;
import java.security.*;

/**
 * The PaillierPrivateKey holds lambda and mu.
 * 
 * @version 12-03-13
 * 
 */
public class PaillierPrivateKey extends PaillierKey implements PrivateKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = 120674253906670457L;
	private BigInteger LAMBDA;
	private BigInteger MU;

	protected PaillierPrivateKey(BigInteger lambda, BigInteger mu,
			BigInteger nsquare, BigInteger n) {
		super(n, nsquare);
		LAMBDA = lambda;
		MU = mu;
	}

	public BigInteger getLAMBDA() {
		return LAMBDA;
	}

	public BigInteger getMU() {
		return MU;
	}

	/**
	 * Returns the standard algorithm name for this key.
	 * 
	 * @return String - Paillier
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

}
