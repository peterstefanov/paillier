package src;

import java.math.BigInteger;

/**
 * Use enum types to represent a fixed set of constants. Candidates needs for
 * the table head and also for the base prefix. Each enum contains two
 * parameters String and BigInteger - base to the power as a String and its
 * representation in BigInteger.
 * 
 * @version 12-03-2013
 * 
 */
public enum Candidates {
	CANDIDATE1("10^0", BigInteger.ONE, "Alan "), CANDIDATE2("10^1",
			BigInteger.TEN, "Phil "), CANDIDATE3("10^2", new BigInteger(
			"100"), "Margaret "), CANDIDATE4("10^3", new BigInteger("1000"),
			"Ronald ");

	private final String exp;
	private final BigInteger value;
	private final String name;

	private Candidates(final String exp, final BigInteger value, final String name) {
		this.exp = exp;
		this.value = value;
		this.name = name;

	}

	/**
	 * @return the exp
	 */
	protected final String getExp() {
		return exp;
	}

	/**
	 * @return the value
	 */
	protected final BigInteger getValue() {
		return value;
	}

	/**
	 * @return the name
	 */
	protected final String getName() {
		return name;
	}
}
