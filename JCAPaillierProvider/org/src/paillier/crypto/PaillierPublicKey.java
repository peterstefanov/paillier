package src.paillier.crypto;

import java.math.BigInteger;
import java.security.*;

/**
 * PaillierPublicKey contains n,nsquare,g and r. Because n and nsquare are
 * already contained in PaillierKey, the public key class has to contain just g.
 * R is called from the PaillierHomomorphicCipher each time when encryption needs it. The
 * implementation of R contains in PaillierKey - needs to be removed. Is there
 * for handy way of retrieving R from outside the package which is not
 * recommended. We need for convenience to show randomness of Paillier for
 * particular application. So the r should be declared here in this class and
 * added to the constructor and in PaillierKeyPairGenerator as well after
 * removal.
 * 
 * @version 12-03-13
 * 
 */
public class PaillierPublicKey extends PaillierKey implements PublicKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7321682822593305457L;
	private BigInteger G;

	protected PaillierPublicKey(BigInteger n, BigInteger g, BigInteger nsquare) {
		super(n, nsquare);
		G = g;
	}

	public BigInteger getG() {
		return G;
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

}
