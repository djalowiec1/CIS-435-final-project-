/*
 *This class verifies a users ID with their Key
 *
 *@author <Cameron Conklin>
 *@date <3/1/2018>
 */



import java.math.*;
public class CA {
	
    public BigInteger[][] people = new BigInteger[2][99999];
    BigInteger empty = new BigInteger("0");

    public void fill() {
            BigInteger a,b,c,d,e;
            a = new BigInteger("0");
            b= new BigInteger("0");
            c= new BigInteger("0");
            d= new BigInteger("0");
            e= new BigInteger("0");

            people[1][0] = a;
            people[0][1] = a;
            people[1][1] = a;		
            people[0][2] = a;
            people[1][2] = a;
            people[0][3] = a;
            people[1][3] = a;



          for(int i=0; i<people.length; i++) {
            for(int j=4; j<people[i].length; j++) {
             people[i][j] = e;
            }
          }
    }

    public BigInteger register(BigInteger ID, BigInteger Key[]){
        int p = ID.intValue();
        if (people[0][p] == null&&people[1][p] == null){
            people[0][p] = (Key[0]);
            people[1][p] = (Key[1]);
        }
        else{
            while (!(people[0][p].equals(empty)&&people[1][p].equals(empty))){
                //System.out.println(people[p]);
                p++;
            }
            System.out.println("Given ID is unavailable. Genereating new ID...");
            System.out.println("New ID is " + p);
            people[0][p].equals(Key[0]);
            people[1][p].equals(Key[1]);


        }

         BigInteger ID_registered = BigInteger.valueOf(p);

    return ID_registered;    
    }


    public BigInteger[] getKey(BigInteger ID) {
        int p = ID.intValue();
            BigInteger Key[] = new BigInteger[2];
 

            Key[0] = people[0][p];
            Key[1] = people[1][p];

            return Key;
    }		
}

