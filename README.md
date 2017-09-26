## NOTES 
    
     The Java™ Cryptography Architecture requires that Java security providers be 
     code-signed (using a code-signing certificate issued by Oracle Corporation).
     
     OpenJDK does not require special handling of the JCE policy files since 
     it's open source and therefore not export-restricted in the United States. 
     This provider will work only with OpenJDK. If you run the Oracle or Sun Java JDK
     you wont be able to use this package, since the Provider is not registered.
  
      
## USAGE
    Import the jar file into your built path, as an external jar file and  
    add dynamically the provider do: `Security.addProvider(new PaillierProvider());
    in your application.
    
    * KeyPairGenerator for Paillier
        Usage: KeyPairGenerator.getInstance("Paillier");
        The PaillierKeyPairGenerator class is used to generate pairs of public and
        private keys. Key pair generators are constructed using the getInstance
        factory methods (static methods that return instances of a given class).
        default modulus n bit length: 64
        KeyPair = <PaillierPublicKey, PaillierPrivateKey>
   
    * PaillierHomomorphicCipher 
       Usage: Cipher.getInstance("PaillierHP");
       Operates with BigInteger as input and strictly the key size should be bigger than m-message.
       Suitable only for EVoting system , using decimal representation of the voter's choices.
    
    * PaillierCipher
        Usage: Cipher.getInstance("Paillier");
        Operates with any input and the key size could be less than m-message.       
        Usage of this implementation is for large text files to be encrypted/decrypted,
        as the implementation using internal buffer for chopping the message in smaller
        bits, based on the length of the key.   
    
    * PaillierKey
        The Key interface is the top-level interface for all keys.
        The public and private key classes both descend from PaillierKey, which is
        simply a container for n and nsquare used in both classes PaillierPublicKey
        and PaillierPrivateKey.   
     
 ## PREREQUSITES 
 * OpenJDK
 
 ## AUTHOR
 * **Petar Stefanov** - *inital work* - [git(peterstefanov)](https://github.com/peterstefanov/paillier)
