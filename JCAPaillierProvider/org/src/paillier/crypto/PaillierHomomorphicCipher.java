package src.paillier.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

/**
 * This class supports only decimal numbers and the input length should be strictly
 * smaller than the key size, otherwise exception is thrown. Use of this class is only
 * for E-Voting application purposes.
 * 
 * Calling from the application update() and doFinal() methods have the same effect.
 * no difference in this implementation, as we expect input no bigger than the key
 * size otherwise exception is throw.
 *  
 * The block sizes of the cipher depend on the size of the key. When the cipher
 * is initialised for encryption or decryption , we calculate the size of a
 * plaintext block and the size of a ciphertext block. We also store the state
 * of the cipher(Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE) and whatever
 * SecureRandom is passed to the PaillierHomomorphicCipher when it is
 * initialised.
 * 
 * 
 * @version 12-03-13
 */

public final class PaillierHomomorphicCipher extends CipherSpi {


	protected int stateMode;
	protected Key keyPaillier;
	protected SecureRandom SECURE_RANDOM;
	protected int plaintextSize;
	protected int ciphertextSize;
	
	/**
	 * This class support no modes, so engineSetMode() throw exception when
	 * called.
	 */
	protected final void engineSetMode(String mode) throws NoSuchAlgorithmException {
		throw new NoSuchAlgorithmException("Paillier supports no modes.");

	}

	/**
	 * This class support no padding, so engineSetPadding() throw exception when
	 * called.
	 */
	protected final void engineSetPadding(String padding)
			throws NoSuchPaddingException {
		throw new NoSuchPaddingException("Paillier supports no padding.");

	}

	/**
	 * Perform actual encryption ,creates single array and updates the result
	 * after the encryption.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLenth
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 * @throws Exception
	 *             throws if Plaintext m is not in Z_n , m should be less then n
	 */
	protected final int encrypt(byte[] input, int inputOffset, int inputLenth,
			byte[] output, int outputOffset) throws Exception {
		byte[] messageBytes = new byte[plaintextSize];
		int inLenth = Math.min(plaintextSize, inputLenth);
		System.arraycopy(input, inputOffset, messageBytes, 0, inLenth);
		BigInteger m = new BigInteger(input);

		// get the public key in order to encrypt
		PaillierPublicKey key = (PaillierPublicKey) keyPaillier;
		BigInteger g = key.getG();
		BigInteger n = key.getN();
		BigInteger nsquare = key.getNSquare();
		BigInteger r = key.generateRandomRinZn(n,SECURE_RANDOM);
 
		if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(n) >= 0) {
			throw new Exception(
					"PaillierHomomorphicCipher.encryptBlock :Plaintext m is not in Z_n , m should be less then n");
		}
		BigInteger c = (g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)))
				.mod(nsquare);
		byte[] cBytes = c.toByteArray();
		System.arraycopy(cBytes, 0, output,ciphertextSize
				- cBytes.length, cBytes.length);

		return ciphertextSize;
	}

	/**
	 * Perform actual decryption ,creates single array for the output and updates
	 * the result after the decryption.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLenth
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int decrypt(byte[] input, int inputOffset, int inputLenth,
			byte[] output, int outputOffset) {
		PaillierPrivateKey key = (PaillierPrivateKey) keyPaillier;
		BigInteger mu = key.getMU();
		BigInteger lambda = key.getLAMBDA();
		BigInteger n = key.getN();
		BigInteger nsquare = key.getNSquare();

		// extract c
		byte[] cBytes = new byte[input.length];
		System.arraycopy(input, inputOffset, cBytes, 0, input.length);
		BigInteger c = new BigInteger(cBytes);
		// calculate the message
		BigInteger m = c.modPow(lambda, nsquare).subtract(BigInteger.ONE)
				.divide(n).multiply(mu).mod(n);
		byte[] messageBytes = m.toByteArray();
		int gatedLength = Math.min(messageBytes.length, plaintextSize);
		System.arraycopy(messageBytes, 0, output, plaintextSize
				- gatedLength, gatedLength);
		
		return plaintextSize;
	}

	/**
	 * PaillierHomomorphicCipher doesn't recognise any algorithm - specific initialisations
	 * so the algorithm specific engineInit() just calls the previous overloaded
	 * version of engineInit()
	 * 
	 * @param opmode
	 *            -cipher mode
	 * @param key
	 *            - Key
	 * @param params
	 *            - AlgorithmParameterSpec
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key,
	 *      java.security.spec.AlgorithmParameterSpec,
	 *      java.security.SecureRandom)
	 */

	protected final void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		engineInit(opmode, key, random);

	}

	protected final void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		engineInit(opmode, key, random);

	}

	/**
	 * Calls the second overloaded version of the same method.
	 * 
	 * @return the result from encryption or decryption
	 */
	protected final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try {
			 engineUpdate(input, inputOffset, inputLen, out, 0);
		} catch (ShortBufferException sbe) {

		}

		return out;
	}

	/**
	 * Creates a single input array from the buffered data and supplied input
	 * data. Calculates the location and the length of the last fractional block
	 * in the input data. Transforms all full blocks in the input data. Save the
	 * last fractional block in the internal buffer.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLen
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {

			if (stateMode == Cipher.ENCRYPT_MODE)
				try {
					return encrypt(input, inputOffset, inputLen, output,
							outputOffset);
				} catch (Exception e) {
					e.printStackTrace();
				}
			else if (stateMode == Cipher.DECRYPT_MODE)
				return decrypt(input, inputOffset, inputLen, output,
						outputOffset);
		return 0;

	}

	/**
	 * Calls the second overloaded version of the same method,
	 * to perform the required operation based on the state of the cipher.
	 * 
	 * @return returns the result from encryption or decryption
	 */
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {

		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try {
			 engineDoFinal(input, inputOffset, inputLen, out, 0);
		} catch (ShortBufferException sbe) {
		}

		return out;
	}

	/**
	 * Calls encrypt or decrypt based on the state of the cipher. Creates a
	 * single input array from the supplied input data. And returns number of
	 * bytes stored in output.
	 * 
	 * @param input
	 *            - the input buffer
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLen
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int engineDoFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
		// Create a single array of input data
		byte[] totalInput = new byte[inputLen ];
		if (inputLen > 0)
			System.arraycopy(input, inputOffset, totalInput, 0,
					inputLen);
		if (stateMode == Cipher.ENCRYPT_MODE)
			try {
				return encrypt(input, inputOffset, inputLen, output,
						outputOffset);
			} catch (Exception e) {
				e.printStackTrace();
			}
		else if (stateMode == Cipher.DECRYPT_MODE)
			return decrypt(input, inputOffset, inputLen, output,
					outputOffset);

		return 0;

	}

	/**
	 * This method returns the appropriate block size , based on cipher.
	 * 
	 * @return BlockSize - the block size(in bytes).
	 */
	protected final int engineGetBlockSize() {
		if (stateMode == Cipher.DECRYPT_MODE)
			return ciphertextSize ;
		else
			return plaintextSize ;
	}

	/**
	 * This method returns null.
	 */
	protected final byte[] engineGetIV() {
		return null;
	}

	/**
	 * Return  the size based on the state of the cipher. This is one 
	 * shot encryption or decryption, no need to calculate internal buffer.
	 * @param inputLen
	 *            the input length (in bytes)
	 * @return outLength - the required output size (in bytes)
	 */
	protected final int engineGetOutputSize(int inputLen) {
		if (stateMode == Cipher.ENCRYPT_MODE) {
			return  ciphertextSize;
		} else {
			return plaintextSize;
		}

	}

	protected final AlgorithmParameters engineGetParameters() {
		return null;
	}

	/**
	 * Initialises this cipher with key and a source of randomness
	 */
	protected final void engineInit(int mode, Key key, SecureRandom random)
			throws InvalidKeyException {
		if (mode == Cipher.ENCRYPT_MODE)
			if (!(key instanceof PaillierPublicKey))
				throw new InvalidKeyException(
						"I didn't get a PaillierPublicKey. ");
			else if (mode == Cipher.DECRYPT_MODE)
				if (!(key instanceof PaillierPrivateKey))
					throw new InvalidKeyException(
							"I didn't get a PaillierPrivateKey. ");
				else
					throw new IllegalArgumentException("Bad mode: " + mode);

		stateMode = mode;
		keyPaillier = key;
		SECURE_RANDOM = random;
		int modulusLength = ((PaillierKey) key).getN().bitLength();
		calculateBlockSizes(modulusLength);
	}

	/**
	 * Calculates the size of the plaintext block and a ciphertext block, based
	 * on the size of the key used to initialise the cipher. The ciphertext is
	 * twice the length of the n modulus , and plaintext should be slightly
	 * shorter than the modulus. Ciphertext is little more than twice the length
	 * of the plaintext. Plaintext - we adding 8 bits(1 byte) before to divide by 8 to
	 * ensure the bigger possible plaintex will fit into created array.
	 * EngineUpdate and engineDoFinal methods check if the size of the array is
	 * to big and reduced to the right size. Similar for the ciphertext. Where
	 * the initial size is set to the size of the n^2 plus one byte . 
	 * 
	 * @param modulusLength
	 *            - n = p*q
	 */
	protected final void calculateBlockSizes(int modulusLength) {
		plaintextSize = ((modulusLength + 8) / 8);
		ciphertextSize = (((modulusLength + 12) / 8) * 2)-1;

	}

}
