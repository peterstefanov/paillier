import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javax.crypto.Cipher;

import src.paillier.crypto.PaillierProvider;


/**
 * This class has a testing purpose. It aims to test the JCA PaillierProvider.
 * Both implementation of Cipher are tested.
 * 
 * 
 */

@SuppressWarnings("restriction")
public class TestJCAProvider {


	public static void main(String[] args) throws Exception {

		TestJCAProvider d = new TestJCAProvider();
		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());
		
		/////////////////////////////////////////////////////////////////////
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		kpg.initialize(32);
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();
		PrivateKey privKey = keyPair.getPrivate();
		final Cipher cipher = Cipher.getInstance("Paillier");
		final Cipher cipherHP = Cipher.getInstance("PaillierHP");
		System.out.println("The Paillier public key through Generator is \n"+keyPair.toString());
		System.out.println("The Paillier public key is \n"+keyPair.getPublic().toString());
		System.out.println("The Paillier private key is \n"+keyPair.getPrivate().toString());
		String plainText = "101";
		String plaintext1 = "101";
		// get the n
		String delims = "[,]";
		String[] keyComponents = pubKey.toString().split(delims);
		String keyComponent = "";
		for (String keyComponent2 : keyComponents) {
			if (keyComponent2.startsWith("n")) {
				keyComponent = keyComponent2.substring(2);// ignoring 'n:' or 'r:'
			}
		}
		BigInteger n = new BigInteger(keyComponent);
		BigInteger first = new BigInteger(plainText);
		BigInteger second = new BigInteger(plaintext1);
		BigInteger n2 = n.multiply(n);

		// encrypt
		BigInteger codedBytes = d.encrypt(first.toByteArray(), pubKey,cipherHP);
		BigInteger codedBytes12 = d.encrypt(second.toByteArray(), pubKey,cipherHP);
		//product
		BigInteger product = codedBytes.multiply(codedBytes12);

		// product mod n^2
		BigInteger tallyProduct = product.mod(n2);
	    System.out.println(" Product mod n^2:      "+tallyProduct);
	    d.decrypt(tallyProduct.toByteArray(), privKey,cipherHP);

		d.decrypt(codedBytes.toByteArray(),privKey,cipherHP);
		d.decrypt(codedBytes12.toByteArray(),privKey,cipherHP);
		
		//////////////////////////////BLOCK EXAMPLE/////////////////////////////////
		String plainTextBlock = "This Provider working correctly and its safe 10000000000000000011000000000000000001";
		System.out.println("This is the message which will be encrypted: " + plainTextBlock);
		
		// encrypt
		byte[] codedBytesBlock = d.encryptBlock(plainTextBlock.getBytes(), pubKey,cipher);
		String codedMessageBlock = new String(codedBytesBlock);
		String codedMessageBlockInHEX = formatingHexRepresentation(codedBytesBlock);
		System.out.println("\n" + "ENCRYPTED :  \n" + codedMessageBlock);
		System.out.println("\n" + "ENCRYPTED in HEX:  \n" + codedMessageBlockInHEX);

		// decrypt
		byte[] encodedBytesBlock = d.decryptBlock(codedMessageBlock, privKey,cipher);
		String encodedMessageBlock = new String(encodedBytesBlock);
		System.out.println("\n" + "DECRYPTED:  \n" + encodedMessageBlock);
			
		}// end of main method...

	public byte[] encryptBlock(final byte[] text, final PublicKey key,final Cipher cipher) throws Exception {
		
		byte[] cipherText = null;
		
		System.out.println("\n" + "Provider encryption is: " + cipher.getProvider().getInfo());
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);		
		cipherText = cipher.doFinal(text);
		final BASE64Encoder encoder = new BASE64Encoder();
		final String base64 = encoder.encode(cipherText);
		final byte[] encryptedBytes = base64.getBytes();
		return encryptedBytes;

	}
	
	public byte[] decryptBlock(final String text, final PrivateKey key,final Cipher cipher) throws Exception {

		byte[] dectyptedBytes = null;
		System.out.println("\n" + "Provider for decryption is: "
				+ cipher.getProvider().getInfo());
		cipher.init(Cipher.DECRYPT_MODE, key);
		final BASE64Decoder decoder = new BASE64Decoder();
		final byte[] raw = decoder.decodeBuffer(text);
		dectyptedBytes = cipher.doFinal(raw);
		
		return dectyptedBytes;

	}

	/**
	 * Convert byte[] to HEX by invoking the byteToHex() and after that splitting 
	 * every two symbols with ':'
	 * 
	 * @param codedBytes
	 * @return String in Hex form with ":" between every two symbols
	 */
	public static String formatingHexRepresentation(final byte[] codedBytes) {
		String hexRepresentation = "";
		String eye;
		for (int i = 0; i < codedBytes.length; i++) {
			eye = byteToHex(codedBytes[i]);
			hexRepresentation += eye;
			if (i < codedBytes.length - 1) {
				hexRepresentation += ":";
			}
		}
		return hexRepresentation;
	}

	public BigInteger encrypt(final byte[] text, final PublicKey key,final Cipher cipher) throws Exception {
		
		byte[] cipherText = null;
		System.out.println("\n" + "Provider encryption is: "
				+ cipher.getProvider().getInfo());
	
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		cipherText = cipher.doFinal(text);
		BigInteger result = new BigInteger(cipherText);
		System.out.println("BigInteger ciphertext: "+result);

		return result;

	}

	public BigInteger decrypt(final byte[] text, final PrivateKey key,final Cipher cipher) throws Exception {

		byte[] dectyptedBytes = null;
		System.out.println("\n" + "Provider for decryption is: "
				+ cipher.getProvider().getInfo());
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedBytes = cipher.doFinal(text);
		BigInteger resultPlain = new BigInteger(dectyptedBytes);
		System.out.println("BigInteger plaintext: "+resultPlain);
		
		return resultPlain;

	}

	/**
	 * Convenience method to convert a byte to a hex string.
	 * 
	 * @param data
	 *            the byte to convert
	 * @return String the converted byte
	 */
	public static String byteToHex(byte data) {
		StringBuffer buf = new StringBuffer();
		buf.append(toHexChar((data >>> 4) & 0x0F));
		buf.append(toHexChar(data & 0x0F));
		return buf.toString();
	}

	/**
	 * Convenience method to convert an int to a hex char.
	 * 
	 * @param i
	 *            the int to convert
	 * @return char the converted char
	 */
	public static char toHexChar(int i) {
		if ((0 <= i) && (i <= 9))
			return (char) ('0' + i);
		else
			return (char) ('A' + (i - 10));
	}
}
