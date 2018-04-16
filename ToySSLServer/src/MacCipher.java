/**
 *The mac cipher encrypt takes the plain text adds the secret to last position, then the result is hashed using 
 mod 12. Then the plaintext with the hash added to the front is sent
 The mac cipher decrypt takes the encrypted message, extracts location one to get the hash, then the rest is
 is combined with the secret, then that is hashed. The hash from position 0 and the new hash are compared,
 if the result is the same nothing was changed and plaintext is send. If they are different  -1 is sent. 
 * 
* @author <Dariusz Jalowiec>
* @date <2/28/2018>
 */



import java.lang.reflect.Array;
import java.math.*;
import java.util.Arrays;

public class MacCipher {
     BigInteger hashFunc = new BigInteger("12");
    
    public BigInteger encrypt(BigInteger plainText, BigInteger secret){
        //create an int arrray from the plaintext
        int[] numbers = getArr(plainText); 
        int s = secret.intValue();
        //create an array one size bigger then orginal to add secret
        int[] resultArr = new int[numbers.length + 1];
        resultArr= Arrays.copyOf(numbers, numbers.length + 1 );
        //secret is added to back
        resultArr[numbers.length] = s;
        //the int array is converted back to bigInt and then it is hashed
        BigInteger hashResult = toBigInteger(resultArr);
        hashResult = hashResult.mod(hashFunc);
        int result = hashResult.intValue();
        //the hash result is added to the front of the new array, everything else is shifted right 
        for( int index = resultArr.length-2; index >= 0 ; index-- ){
            resultArr[index+1] = resultArr [index];
        }
        resultArr[0] = result;
        //final array converted back to bigint and send
        return toBigInteger(resultArr);
        
    }
     public BigInteger decrypt(BigInteger encypted, BigInteger secret){
        int[] received = getArr(encypted);
        //create an int arrray from the encryoted message
        //get the has out from postion 0
        int hash = received[0];
        //create a new int array with messsage without hash with secret added to back
        System.arraycopy(received, 1, received, 0, received.length - 1);
        received[received.length - 1] = secret.intValue();
        //hash the new combined bigint
        BigInteger message = toBigInteger(received);
        BigInteger hashResult = message.mod(hashFunc);
        int newHash = hashResult.intValue();
        //compare new hash with old received hash, if sae return message if not -1
        BigInteger wrong = new BigInteger("1");
        if(hash == newHash)
            return message;
        else
            return wrong.negate();
     }
       //private method to convert bigint into int array
    private int[] getArr(BigInteger num){
        String biStr = num.toString();
        int[] ints = new int[biStr.length()];
        for(int i=0; i<biStr.length(); i++) {
            ints[i] = Integer.parseInt(String.valueOf(biStr.charAt(i)));
        }
        return ints;
}
//private method to convert int array into bigint 
    private BigInteger toBigInteger(int[] data) {
        String p = "";
        for(int current = 0; current < data.length; current++){
            p = p + data[current];
        }
        BigInteger numBig  = new BigInteger(p);
        return numBig;
    }
}
