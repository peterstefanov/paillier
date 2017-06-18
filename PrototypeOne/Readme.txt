 NOTES
Simple UI using \(java.awt\) to visualise the process of encryption and decryption
and to show the homomorphic properties that the Paillier Cryptosystem possess.       

USAGE

    GUIPaillier
        Usage: Creates a JFrame and responsible for interaction
        with the PaillierAlgorithm class. Option to save the output
        results from encryption and decryption.
    isGcd 
       Usage: Check if the two chosen prime numbers p and q satisfied following
	   condition gcd(pq,(p-1)(q-1)) if yes it assured that both primes are of
	   equivalent length , i.e p,q ∈ 1||{0,1}^s−1 for security parameter s. This
	   method has more testing purposes, as the generated p and q should pass
	   this condition during generation.
    PaillierAlgorithm
        Usage:Generates the public and private keys and performs
        encryption and decryption.