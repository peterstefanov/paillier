package paillierPrototype;

import java.math.*;

public class isGcd {

	/**
	 * <ol>
	 * Check if the two chosen prime numbers p and q satisfied following
	 * condition gcd(pq,(p-1)(q-1)) if yes it assured that both primes are of
	 * equivalent length , i.e p,q ∈ 1||{0,1}^s−1 for security parameter s
	 * </ol>
	 * 
	 * @param args
	 * @return boolean
	 */
	public static boolean isGcdOne(String pPrime, String qPrime) {
		BigInteger n;
		BigInteger w;
		BigInteger p = new BigInteger(pPrime);
		BigInteger q = new BigInteger(qPrime);
		// n = p*q
		n = q.multiply(q);
		// (p-1)*(q-1)
		w = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		if (n.gcd(w).equals(BigInteger.ONE)) {

			return true;
		} else
			return false;

	}
}
