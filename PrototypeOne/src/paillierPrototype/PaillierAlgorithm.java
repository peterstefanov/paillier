package paillierPrototype;

import java.math.BigInteger;
import java.security.*;

public class PaillierAlgorithm {

	private int STRENGTH = 0;
	private SecureRandom SECURE_RANDOM = null;
	private BigInteger N;
	private BigInteger G;
	private BigInteger R;
	private BigInteger P;
	private BigInteger Q;
	private BigInteger NSquare;
	private BigInteger MU;
	private BigInteger LAMBDA;
	private BigInteger C;

	protected void initialize(int strength) {
		STRENGTH = strength;

	}

	protected void generateKeyPair() {
		if (STRENGTH == 0) {
		//	STRENGTH = 512;
		}
		SECURE_RANDOM = new SecureRandom();
		BigInteger p = new BigInteger(STRENGTH, 16, SECURE_RANDOM);
		P = p;
		BigInteger q;
		do {
			q = new BigInteger(STRENGTH, 16, SECURE_RANDOM);
		} while (q.compareTo(p) == 0);

		Q = q;
		// lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
		BigInteger lambda = (p.subtract(BigInteger.ONE).multiply(q
				.subtract(BigInteger.ONE))).divide(p.subtract(BigInteger.ONE)
				.gcd(q.subtract(BigInteger.ONE)));
		LAMBDA = lambda;

		BigInteger n = p.multiply(q); // n = p*q
		N = n;
		BigInteger nsquare = n.multiply(n); // nsquare = n*n
		NSquare = nsquare;
		BigInteger g;
		do {
			// generate g, a random integer in Z*_{n^2}
			do {
				g = new BigInteger(STRENGTH * 2, SECURE_RANDOM);
			} while (g.compareTo(nsquare) >= 0
					|| g.gcd(nsquare).intValue() != 1);
			G = g;

			// verify g, the following must hold: gcd(L(g^lambda mod n^2), n) =
			// 1,
			// where L(u) = (u-1)/n
		} while (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n)
				.gcd(n).intValue() != 1);

		// mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n
		BigInteger mu = g.modPow(lambda, nsquare).subtract(BigInteger.ONE)
				.divide(n).modInverse(n);
		MU = mu;

	}

	/**
	 * c = g^m * r^n mod n^2
	 */
	protected BigInteger encrypt(BigInteger m) throws Exception {
		BigInteger r;
		// generate r, a random integer in Z*_n
		do {
			r = new BigInteger(STRENGTH * 2, SECURE_RANDOM);
		} while (r.compareTo(N) >= 0 || r.gcd(N).intValue() != 1);
		R = r;
		if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(N) >= 0) {
			throw new Exception(
					"encrypt(BigInteger m): plaintext m is not in Z_n");
		}
		// c = g^m*r^n mod n^2
		BigInteger c = (G.modPow(m, NSquare).multiply(R.modPow(N, NSquare)))
				.mod(NSquare);
		C = c;
		return c;
	}

	/**
	 * m = L(c^lambda mod n^2)mu mod n
	 */
	protected BigInteger decrypt(BigInteger c) {

		BigInteger m = c.modPow(LAMBDA, NSquare).subtract(BigInteger.ONE)
				.divide(N).multiply(MU).mod(N);

		return m;
	}

	protected BigInteger getN() {
		return N;
	}

	protected BigInteger getG() {
		return G;
	}

	protected BigInteger getR() {
		return R;
	}

	protected BigInteger getP() {
		return P;
	}

	protected BigInteger getQ() {
		return Q;
	}

	protected BigInteger getNSquare() {
		return NSquare;
	}

	protected BigInteger getMU() {
		return MU;
	}

	protected BigInteger getLAMBDA() {
		return LAMBDA;
	}

	protected BigInteger getC() {
		return C;
	}
}
