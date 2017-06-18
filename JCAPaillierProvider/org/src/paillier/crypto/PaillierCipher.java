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
 * 
 * PaillierCipher providing the buffering and block handling in implementation
 * of this class. The block sizes of the cipher depend on the size of the
 * key.The class contains the logic that breaks down the input data into
 * block-sized chunks for encrypting or decrypting. The size of the chunks
 * depends on the key size initialized for the cipher. When the cipher is
 * initialised for encryption or decryption , we calculate the size of a
 * plaintext block and the size of a ciphertext block. We also store the state
 * of the cipher(Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE) and whatever
 * SecureRandom is passed to the PaillierCipher when it is initialised.
 * 
 * @version 12-03-13
 */

public final class PaillierCipher extends CipherSpi {

	protected int stateMode;
	protected Key keyPaillier;
	protected SecureRandom SECURE_RANDOM;
	protected int plaintextSize;
	protected int ciphertextSize;
	protected byte[] dataBuffer;
	protected int lengthBuffer;

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
	 * This method is called whenever a full block needs to be
	 * encrypted/decrypted. The input block is contained in input.The
	 * transformed block is written into output starting at otputOfset. The
	 * number of bytes written is returned.
	 * 
	 * @param input
	 *            - byte[]
	 * @param inputOffset
	 *            -int
	 * @param inputLenth
	 *            -int
	 * @param output
	 *            -byte[]
	 * @param outputOffset
	 *            -int
	 * @return The number of bytes written.
	 * @throws ShortBufferException
	 */
	protected final int engineTransformBlock(byte[] input, int inputOffset,
			int inputLenth, byte[] output, int outputOffset)
			throws ShortBufferException {
		if (stateMode == Cipher.ENCRYPT_MODE)
			try {
				return encryptBlock(input, inputOffset, inputLenth, output,
						outputOffset);
			} catch (Exception e) {
				e.printStackTrace();
			}
		else if (stateMode == Cipher.DECRYPT_MODE)
			return decryptBlock(input, inputOffset, inputLenth, output,
					outputOffset);
		return 0;

	}
	
	/**
	 * 
	 * This method may be passed less than a full block.
	 * @param input
	 *            - byte[]
	 * @param inputOffset
	 *            -int
	 * @param inputLenth
	 *            -int
	 * @param output
	 *            -byte[]
	 * @param outputOffset
	 *            -int
	 * @return The number of bytes written.
	 * @throws ShortBufferException
	 */
	protected final int engineTransformBlockFinal(byte[] input, int inputOffset,
			int inputLenth, byte[] output, int outputOffset)
			throws ShortBufferException {
		if (inputLenth == 0)
			return 0;
		return engineTransformBlock(input, inputOffset, inputLenth, output,
				outputOffset);
	}
	
	/**
	 * Perform actual encryption ,creates single array and updates the result
	 * after the encryption.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts 
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
	protected final int encryptBlock(byte[] input, int inputOffset, int inputLenth,
			byte[] output, int outputOffset) throws Exception {
		byte[] messageBytes = new byte[plaintextSize];
		int inLenth = Math.min(plaintextSize, inputLenth);
		System.arraycopy(input, inputOffset, messageBytes, 0, inLenth);
		BigInteger m = new BigInteger(1, messageBytes);

		// get the public key in order to encrypt
		PaillierPublicKey key = (PaillierPublicKey) keyPaillier;
		BigInteger g = key.getG();
		BigInteger n = key.getN();
		BigInteger nsquare = key.getNSquare();
		BigInteger r = key.generateRandomRinZn(n,SECURE_RANDOM);


		if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(n) >= 0) {
			throw new Exception(
					"PaillierCipher.encryptBlock :Plaintext m is not in Z_n , m should be less then n");
		}
		BigInteger c = (g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)))
				.mod(nsquare);

		byte[] cBytes = getBytes(c);
		System.arraycopy(cBytes, 0, output, outputOffset + ciphertextSize
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
	 *            - the offset in input where the input starts 
	 * @param inputLenth
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int decryptBlock(byte[] input, int inputOffset, int inputLenth,
			byte[] output, int outputOffset) {
		PaillierPrivateKey key = (PaillierPrivateKey) keyPaillier;
		BigInteger mu = key.getMU();
		BigInteger lambda = key.getLAMBDA();
		BigInteger n = key.getN();
		BigInteger nsquare = key.getNSquare();

		// extract c
		byte[] cBytes = new byte[ciphertextSize];
		System.arraycopy(input, inputOffset, cBytes, 0, ciphertextSize);
		BigInteger c = new BigInteger(1, cBytes);
		// calculate the message
		BigInteger m = c.modPow(lambda, nsquare).subtract(BigInteger.ONE)
				.divide(n).multiply(mu).mod(n);

		byte[] messageBytes = getBytes(m);
		int gatedLength = Math.min(messageBytes.length, plaintextSize);
		System.arraycopy(messageBytes, 0, output, outputOffset + plaintextSize
				- gatedLength, gatedLength);
		return plaintextSize;
	}

	/**
	 * PaillierCipher doesn't recognise any algorithm - specific initialisations
	 * so the algorithm specific engineInit() just calls the previous overloaded
	 * version of engineInit() (non-Javadoc)
	 * 
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
	 * Checks to see if the buffer exists. If not , or if it is not the same
	 * length as the block size, a new buffer created.
	 * 
	 */
	protected final void checkBuffer() {
		if (dataBuffer == null || dataBuffer.length != engineGetBlockSize()) {
			dataBuffer = new byte[engineGetBlockSize()];
			lengthBuffer = 0;
		}
	}

	/**
	 * Returns the length of the data stored in the buffer.
	 * 
	 * @return lengthBuffer
	 */
	protected final int getDataBufferedLength() {
		checkBuffer();
		return lengthBuffer;

	}

	/**
	 * Retrieved buffered data. The data will be copied into the supplied array
	 * and the internal buffer is reset - by setting lengthBuffer to 0
	 */
	protected final void getBuffer(byte[] output, int offset) {
		checkBuffer();
		System.arraycopy(dataBuffer, 0, output, offset, lengthBuffer);
		lengthBuffer = 0;
	}

	/**
	 * Adds the specified data to the internal buffer.
	 */
	protected final void addToBuffer(byte[] input, int offset, int length) {
		checkBuffer();
		System.arraycopy(input, offset, dataBuffer, lengthBuffer, length);
		lengthBuffer += length;
	}

	/**
	 * Calls the second overloaded version of the same method.
	 */
	protected final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		int length = 0;
		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try {
			length = engineUpdate(input, inputOffset, inputLen, out, 0);
		} catch (ShortBufferException sbe) {

		}
		if (length < out.length) {
			byte[] shorter = new byte[length];
			System.arraycopy(out, 0, shorter, 0, length);
			out = shorter;
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
	 *            - the input buffer
	 * @param inputOffset
	 *            - the offset in input where the input starts
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
		// create a single array of input data
		int lengthBuffer = getDataBufferedLength();
		byte[] totalIn = new byte[inputLen + lengthBuffer];
		getBuffer(totalIn, 0);
		System.arraycopy(input, inputOffset, totalIn, lengthBuffer,
				inputLen);

		// figure out the location of last fractional block
		int blockSize = engineGetBlockSize();
		int lastBlockSize = totalIn.length % blockSize;
		int lastBlockOffset = totalIn.length - lastBlockSize;

		// step through the array
		int outputLength = 0;
		for (int i = 0; i < lastBlockOffset; i += blockSize)
			outputLength += engineTransformBlock(totalIn, i, blockSize,
					output, outputOffset + outputLength);

		// copy the reminder into dataBuffer
		addToBuffer(totalIn, lastBlockOffset, lastBlockSize);

		return outputLength;

	}

	/**
	 * Calls the second overloaded version of the same method.
	 */
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		int length = 0;
		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try {
			length = engineDoFinal(input, inputOffset, inputLen, out, 0);
		} catch (ShortBufferException sbe) {

		}
		if (length < out.length) {
			byte[] smaller = new byte[length];
			System.arraycopy(out, 0, smaller, 0, length);
		}
		return out;
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation.
	 * 
	 * Creates a single input array from the buffered data and supplied input
	 * data. Finds the location and the size of the last partial or full block
	 * in engineUpdate(),just interested in last partial block.. Transforms each
	 * full blocks in the input array by calling engineTransformBlock().
	 * Transform the final partial or full block by calling
	 * engineTransformBlockFinal().
	 * 
	 * @param input
	 *            - the input buffer
	 * @param inputOffset
	 *            - the offset in input where the input starts
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
		int lengthBuffer = getDataBufferedLength();
		byte[] totalIn = new byte[inputLen + lengthBuffer];
		getBuffer(totalIn, 0);
		if (inputLen > 0)
			System.arraycopy(input, inputOffset, totalIn, lengthBuffer,
					inputLen);

		// Find the location of the last partial or full block.
		int blockSize = engineGetBlockSize();
		int lastBlockSize = totalIn.length % blockSize;
		if (lastBlockSize == 0 && totalIn.length > 0)
			lastBlockSize = blockSize;
		int lastBlockOffset = totalIn.length - lastBlockSize;

		// Step through the array
		int outputLength = 0;
		for (int i = 0; i < lastBlockOffset; i += blockSize)
			outputLength += engineTransformBlock(totalIn, i, blockSize,
					output, outputOffset + outputLength);

		// Transform the final partial or full block
		outputLength += engineTransformBlockFinal(totalIn, lastBlockOffset,
				lastBlockSize, output, outputOffset + outputLength);

		return outputLength;

	}

	/**
	 * engineGetBlockSize() returns the appropriate size , based on cipher.
	 * 
	 * @return plaintextSize - the block size(in bytes).
	 */
	protected int engineGetBlockSize() {
		if (stateMode == Cipher.DECRYPT_MODE)
			return ciphertextSize;
		else
			return plaintextSize;
	}

	/**
	 * This implementation runs just in Electronic Codebook(ECB) mode -
	 * "each block is encrypted separately of other blocks" , so this method
	 * returns null.
	 */
	protected byte[] engineGetIV() {
		return null;
	}

	/**
	 * Based on the state of the cipher, figure out how many input blocks are
	 * represented by inputLen. Then the number of output bytes need to be
	 * calculated.
	 * 
	 * @param inputLen
	 *            the input length (in bytes)
	 * @return outLength - the required output buffered size (in bytes)
	 */
	protected int engineGetOutputSize(int inputLen) {
		int inBlocks;
		int outLength;
		if (stateMode == Cipher.ENCRYPT_MODE) {
			inBlocks = (inputLen + getDataBufferedLength() + plaintextSize - 1)
					/ plaintextSize;
			outLength = inBlocks * ciphertextSize;
		} else {
			inBlocks = (inputLen + getDataBufferedLength() + plaintextSize - 1)
					/ ciphertextSize;
			outLength = inBlocks * plaintextSize;
		}
		return outLength;
	}

	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	/**
	 * Initialises this cipher with key and a source of randomness
	 */
	protected void engineInit(int mode, Key key, SecureRandom random)
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
	 * on the size of the key used to initialise the cipher.
	 * 
	 * @param modulusLength
	 *            - n = p*q
	 */
	protected void calculateBlockSizes(int modulusLength) {
		plaintextSize = (modulusLength - 1) / 8;
		ciphertextSize = ((modulusLength + 7) / 8) * 2;

	}




	/**
	 * This helper method returns an array of bytes that is only as long as it
	 * needs to be , ignoring the sign of the number.
	 * 
	 * @param big
	 * @return an array of bytes
	 */
	protected byte[] getBytes(BigInteger big) {
		byte[] bigBytes = big.toByteArray();
		if ((big.bitLength() % 8) != 0) {
			return bigBytes;
		} else {
			byte[] smallerBytes = new byte[big.bitLength() / 8];
			System.arraycopy(bigBytes, 1, smallerBytes, 0, smallerBytes.length);
			return smallerBytes;
		}

	}
}