package src;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import src.paillier.crypto.PaillierProvider;

/**
 * This class does encryption and decryption, also contains supported methods.
 * Responsible for adding the PaillierProvider dynamically, initialise the key
 * size and generate public and private keys.
 * 
 * @version 12-03-2013
 * 
 */
public final class PaillierCryptosystemUtil {

	private final PublicKey pubKey;
	private final PrivateKey privKey;
	private  String[] rRandom;

	/**
	 * The constructor PaillierCryptosystemUtil is responsible for adding the
	 * Paillier Provider, initialise the key size and generate public and
	 * private keys. This is done once only here with the clear idea to be used
	 * the same keys for all encryption and decryption operations within the
	 * class. The instance of PaillierCryptosystemUtil is made just once from
	 * the main class, this way we assure that the homomorphic properties of
	 * Paillier Cryptosystem will be in use.
	 * 
	 * @throws NoSuchAlgorithmException
	 * 
	 */
	PaillierCryptosystemUtil() throws NoSuchAlgorithmException {

		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());
		// generates pairs of public and private keys
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		// Initialise key size in bits
		kpg.initialize(32);// 8 bits = 1 byte
		KeyPair keyPair = kpg.generateKeyPair();
		pubKey = keyPair.getPublic();
		privKey = keyPair.getPrivate();

	}

	/**
	 * This method calls the actual encryption method and converts the output
	 * from it into BigInteger[] . The call is made separately for each voter's
	 * sum. So for each encryptions is used newly generated random R. This is
	 * provided by the PaillierHomomorphicCipher functionality.
	 * 
	 * @param votes
	 *            - int[]
	 * @return codedMessage - String[]
	 * @throws Exception
	 * 
	 */
	public final BigInteger[] doEncrypt(BigInteger[] votes) throws Exception {

		rRandom = new String[votes.length];
		BigInteger[] codedMessage = new BigInteger[votes.length];
		for (int j = 0; j < votes.length; j++) {
			codedMessage[j] = encrypt(votes[j].toByteArray(), pubKey);
			// make call after the call for encryption
			// and get the r used for this encryption
			rRandom[j] = getKeyComponent("r");
		}

		return codedMessage;
	}

	/**
	 * The method does the encryption by passing the bytes array and the
	 * Paillier Public key as parameters.
	 * 
	 * @param VoteMessage
	 *            - byte[]
	 * @param pubKey
	 * @return result - BigInteger (ciphertext)
	 * @throws NoSuchAlgorithmException
	 * @throws GeneralSecurityException
	 * 
	 */
	private final BigInteger encrypt(final byte[] VoteMessage, final PublicKey pubKey)
			throws NoSuchAlgorithmException, GeneralSecurityException {

		byte[] cipherText = null;
	    Cipher cipher = Cipher.getInstance("PaillierHP");
		// encrypt the voter's message using the public key
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		cipherText = cipher.update(VoteMessage);
		BigInteger result = new BigInteger(cipherText);

		return result;

	}

	/**
	 * From the API,the method toByteArray(), returns a byte[] containing the
	 * two's-complement representation of this BigInteger. Decryption of the
	 * product of all encrypted vote messages mod n^2 is done here. The result
	 * plaintext - the actual tally in reverse order is returned as a
	 * BigInteger.
	 * 
	 * @param tally
	 *            - BigInteger
	 * @return decryptedTally - BigInteger
	 * @throws Exception
	 * 
	 */
	public final BigInteger doDecrypt(final BigInteger tally) throws Exception {

		byte[] dectyptedBytes = null;
		// decrypt the text using the private key
		Cipher cipher = Cipher.getInstance("PaillierHP");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		dectyptedBytes = cipher.doFinal(tally.toByteArray());
		BigInteger decryptedTally = new BigInteger(dectyptedBytes);

		return decryptedTally;
	}


	/**
	 * Get the n-modulus or r from the PublicKey object. They starts with prefix
	 * n and r, based on that retrieve the correct key component as requested by
	 * passing the right prefix - n(for n modulus) or r(for the random #).
	 * 
	 * @return k - the key component as a String
	 * 
	 */
	public  String getKeyComponent(final String prefix) {
		String delims = "[,]";
		String[] keyComponents = pubKey.toString().split(delims);
		String keyComponent = "";
		for (String keyComponent2 : keyComponents) {
			if (keyComponent2.startsWith(prefix)) {
				keyComponent = keyComponent2.substring(2);// ignoring 'n:' or
															// 'r:'
			}
		}
		return keyComponent;
	}

	/**
	 * Getter for the r random number for each encryption. The array is
	 * populated in doEncrypt() method. Need a getter to make a call from the
	 * GUI class.
	 * 
	 * @return the rRandom - String[]
	 * 
	 */
	protected  String[] getrRandom() {
		return rRandom;
	}
}
