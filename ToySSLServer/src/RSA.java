/*
* 

* RSA - Generates Private and Public keys for users
* and Encrypts and Decrypts messages

 * @author <Tom Callahan>
 * @date <2/28/2018>
 */



import java.math.BigInteger;
import java.util.Random;

public class RSA {
    
    //Public(n,e) and Private(n,d) Keys
    BigInteger[] publicKey = new BigInteger[2]; 
    BigInteger[] privateKey = new BigInteger[2];
    
    //Generate Public and Private Keys, storing them in class level variables
    public void genKeys()
    {
        //Randomly generate p,q
        Random randNum = new Random();
        BigInteger p = BigInteger.probablePrime(1024, randNum);
        BigInteger q = BigInteger.probablePrime(1024, randNum);

        //Multiply p,q to get n and z
        BigInteger n = p.multiply(q);
        BigInteger z = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        
        //e is a relative prime to z:
        //Conditions: e > 1, e < z, e and z must have GCD of 1.
        //SOURCE: ALL CREDIT TO https://www.nayuki.io/page/java-biginteger-was-made-for-rsa-cryptography
        BigInteger e = BigInteger.ZERO;
        do e = new BigInteger(z.bitLength(), randNum);
        while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(z) >= 0 || !e.gcd(z).equals(BigInteger.ONE));
        
        //d such that ed-1 is exactly divisible by z:   ed % z = 1
        BigInteger d = e.modInverse(z);
        
        publicKey[0] = n;
        publicKey[1] = e;
        privateKey[0] = n;
        privateKey[1] = d;
    }
    
    //Gives just the public key after generated.
    public BigInteger[] getPublicKey()
    {
        return publicKey;
    }
    
    //Gives just the private key after generated
    public BigInteger[] getPrivateKey()
    {
        return privateKey;
    }
    
    //Encrypts message using a public Key
    public BigInteger encrypt(BigInteger message, BigInteger[] Key){
        //Get Publickey's info
        BigInteger n = Key[0];
        BigInteger e = Key[1];
        
        //Create cipher: cipher = (m^e)%n;
        BigInteger cipher;
        cipher = message.modPow(e, n); 
        return cipher;
    }
    
    //Decrypts message using a private Key
    public BigInteger decrypt(BigInteger cipher, BigInteger[] Key){
        //Get PrivateKey's Info
        BigInteger n = Key[0];
        BigInteger d = Key[1];
        
        System.out.println("DECRYPTION KEY: " + n);
        System.out.println("DECRYPTION KEY: " + d);
        //Decrypt Cipher to Message: message = (c^d)%n
        BigInteger message;
        message = cipher.modPow(d, n);
        return message;               
    }  
}
