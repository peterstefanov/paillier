 NOTES
       GUI using \(java.awt\) to visualise the process of encryption and decryption
       and to show the homomorphic properties that the Paillier Cryptosystem possess. 
       The aplication use JCAPaillierProvider as referenced  library, the provider is 
       added dynamically. Election performed is simple with four candidates and eight
       voters. The system used based ten as a distinguisher for the candidates.     

USAGE

    GUI.class
        Usage: Creates a JFrame and responsible for interaction
        with the PaillierCryptosystem class. Inner class Controls 
        handles all user interaction for voting.
        
    Candidates.class
       Usage: Use enum types to represent a fixed set of constants. 
       Candidates needs for the table head and also for the base prefix.
       
    PaillierCryptosystemUtil.class
        Usage: Added JCAPaillierProvider within this class and initialised 
        KeyPairGenerator for generating KeyPair keys. Initialised Cipher as well
        used for encryption and decryption. Few supported methods for
        generating string expression to be displayed at the screen.
