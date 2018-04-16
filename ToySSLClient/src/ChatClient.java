
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * This program is one end of a simple command-line interface chat program.
 * It acts as a client which makes a connection to a CLChatServer program.  
 * The computer to connect to must be given as a command-line argument to the
 * program.  The two ends of the connection
 * each send a HANDSHAKE string to the other, so that both ends can verify
 * that the program on the other end is of the right type.  Then the connected 
 * programs alternate sending messages to each other.  The client always sends 
 * the first message.  The user on either end can close the connection by 
 * entering the string "quit" when prompted for a message.  Note that the first 
 * character of any string sent over the connection must be 0 or 1; this
 * character is interpreted as a command for security purpose. 
 */
class ChatClient {

   /**
    * Port number on server, if none is specified on the command line.
    */
   static final int DEFAULT_PORT = 1728;

   /**
    * Handshake string. Each end of the connection sends this  string to the 
    * other just after the connection is opened.  This is done to confirm that 
    * the program on the other side of the connection is a CLChat program.
    */
   static final String HANDSHAKE = "CIS435535";

   /**
    * This character is prepended to every message that is sent.
    */
   static final char MESSAGE = '0'; //more like the type in SSL

   /**
    * This character is sent to the connected program when the user quits.
    */
   static final char CLOSE = '1';  //more like the type in SSL

   
   //variables for the 3 parameters both client and server need to use
   private int ClientNC;
   private int ServerNC;
   private int pre_master_key;
   private int AlgoChoice;
   private int KC;
   private int MC;
   private int KS;
   private int MS;
   String[] CP01 = new  String[4];
   RSA rsa = new RSA();
   MacCipher mac = new MacCipher();
   List<String[]> Queue = new ArrayList<String[]>();
     


   public static void main(String[] args) {

      String computer = "localhost";  // The computer where the server is running,
                        // as specified on the command line.  It can
                        // be either an IP number or a domain name.

      int port = DEFAULT_PORT;   // The port on which the server listens.

      Socket connection;      // For communication with the server.

      BufferedReader incoming;  // Stream for receiving data from server.
      PrintWriter outgoing;     // Stream for sending data to server.
      String messageOut;        // A message to be sent to the server.
      String messageIn;         // A message received from the server.

      BufferedReader userInput; // A wrapper for System.in, for reading
                                  // lines of input from the user.

    
      /* Open a connetion to the server.  Create streams for 
         communication and exchange the handshake. */
      try {
         System.out.println("Connecting to " + computer + " on port " + port);
         connection = new Socket(computer,port);
         incoming = new BufferedReader(
                       new InputStreamReader(connection.getInputStream()) );
         outgoing = new PrintWriter(connection.getOutputStream());
        System.out.println("-----------------------------------------");
        System.out.println("STEP 1: Client sends CP01. It Contains");
        ChatClient chat = new ChatClient();

         
       
         
        // step 1: client sends out CP01
         String[] CP01 = chat.startHandshake();
         String CP01String = chat.converttoString(CP01);
         outgoing.println(CP01String);
         outgoing.flush();

         
         
       // step 3: client receives SP01, verifies the server and sends out CP02
        String SP01 = incoming.readLine();
        String CP02 [] = chat.certifyServer(SP01);
        outgoing.println(chat.converttoString(CP02));
        outgoing.flush();
   
         //step 4: keys are generated
         chat.clientGenerateKeys();
         
         //step 5: THE mac is generated and send out to server
         String MAC = chat.generateClientMAC();
         outgoing.println(MAC);
         outgoing.flush();
              

        // step 7: MAC is checked
        String ServerMAC = incoming.readLine();  
        if(chat.CheckMAC(ServerMAC) == false)
        {
            throw new Exception("Connected program is not a ChatServer!");
        }
         System.out.println("Connected.  Enter your first message.");
          System.out.println("----------------------------------------");
      }
      catch (Exception e) {
         System.out.println("An error occurred while opening connection.");
         System.out.println(e.toString());
         return;
      }

      /* Exchange messages with the other end of the connection until one side or 
         the other closes the connection.  This client program send the first message.
         After that,  messages alternate strictly back and forth. */

      try {
         userInput = new BufferedReader(new InputStreamReader(System.in));
         System.out.println("NOTE: Enter 'quit' to end the program.\n");
         while (true) {
            System.out.print("SEND:      ");
            messageOut = userInput.readLine();
            if (messageOut.equalsIgnoreCase("quit"))  {
                  // User wants to quit.  Inform the other side
                  // of the connection, then close the connection.
               outgoing.println(CLOSE);
               outgoing.flush();
               connection.close();
               System.out.println("Connection closed.");
               break;
            }
            outgoing.println(MESSAGE + messageOut);
            outgoing.flush();
            if (outgoing.checkError()) {
               throw new IOException("Error occurred while transmitting message.");
            }
            System.out.println("WAITING...");
            messageIn = incoming.readLine();
            if (messageIn.length() > 0) {
                    // The first character of the message is a command. If 
                    // the command is CLOSE, then the connection is closed.  
                    // Otherwise, remove the command character from the 
                    // message and procede.
               if (messageIn.charAt(0) == CLOSE) {
                  System.out.println("Connection closed at other end.");
                  connection.close();
                  break;
               }
               messageIn = messageIn.substring(1);
            }
            System.out.println("RECEIVED:  " + messageIn);
         }
      }
      catch (Exception e) {
         System.out.println("Sorry, an error has occurred.  Connection lost.");
         System.out.println(e.toString());
         System.exit(1);
      }

   }  // end main()


   //this method starts the handshake and sends out the avaaiable choices plus random clientNC
   public String[] startHandshake(){
       
       //the 2 choices put inside the first 2 parts of the packer
       CP01[0] = "Rsa+shift+hash";    
       CP01[1] = "Rsa+shift+hash";
       CP01[2] = "SubstitutionCipher+RSA+DigitalSignature+CA"; 
       //Generate keys wth RSA
       rsa.genKeys();

       //generate random ClientNC
    //   Random random = new Random();
       //int x = random.nextInt(900) + 100;
       //random int converted to string and added
       CP01[3] = Integer.toString(555);
       ClientNC = 555;
       //CP01 is put inside the gueue 
        
      updateQueueMethod(CP01);
   
      
      
          System.out.println("           CP01[0]: " + CP01[0]);
          System.out.println("           CP01[1]: " + CP01[1]);
          System.out.println("           CP01[2]: " + CP01[2]);
          System.out.println("           CP01[3]: " + CP01[3]);
          System.out.println("           CP01 put in Client quoue");
          System.out.println("CP01 is converted into a String and is send");
       return CP01;
 
   }
 

   

   //this method updates the list with any packets
   public void updateQueueMethod(String[] packet){
       Queue.add(packet);
            
          
        
   }
   //Takes the packet generated from pickAlgo() and extracts each part. 
    //Extract the ClientNC with the server public key to make sure the NC is correct. If not, break connection.
    //Generate a pre-master-secret, encrypt it with the servers public key and send out. 
    //call updateQueueMethod() to take note of SP02  then call  updateQueueMethod()  to put CP02 inside 

   public String[] certifyServer(String packetfromServer){
       //put SP01 inside the list of packets
       String[] SP01 = convertToArray(packetfromServer);
       updateQueueMethod(SP01);
        System.out.println("-----------------------------------------");
        System.out.println("STEP 3: Client verifies the Server, generated Pre_master_secret and send out  CP01");
       //extract choice 
       System.out.println("The packet we got from the server is: ");
       AlgoChoice =  Integer.parseInt(SP01[0]);
       System.out.println("          SP01[0]: "  + SP01[0] );
       System.out.println("          SP01[1]: "  + SP01[1] );
       System.out.println("          SP01[2]: "  + SP01[2] );
       System.out.println("          SP01[3]: "  + SP01[3] );
       System.out.println("          SP01 is put inside the Client quoue");
     
       //extract the public key of server 
       String StringFromArray = SP01[3];
       String[] Forsplitting = StringFromArray.split(",");
        
       BigInteger[] ServerPublicKey = new BigInteger[2]; 
              
        ServerPublicKey[0] = new BigInteger(Forsplitting[0]);
        ServerPublicKey[1] = new BigInteger(Forsplitting[1]);

       //certify if Choice Correct with RSA decrypt
       BigInteger encryptedMessage = new BigInteger(SP01[1]);

       //take out the NC and make sure it is the same
       int NCfromServer = (rsa.decrypt(encryptedMessage, ServerPublicKey)).intValue();
       if(NCfromServer != ClientNC){
           System.out.println("does not match the NC");
           return null;
       }
       
       //take out the serverNC 
       ServerNC = Integer.parseInt(SP01[2]);
       
       //encrypt the pre_master_key with server public key
       
       String[] CP02 = new  String[4];
       //generate a PRE MASTER KEY
      //  Random random = new Random();
       //int x = random.nextInt(900) + 100;
       //random int converted to string and added
       pre_master_key = 1234;
    
       //pre-master-key is converted to a string and put inside the CP02, 1's are put in other postions.
       //BigInteger NCinBI = BigInteger.ZERO;
       BigInteger NCinBI = new BigInteger("1234");
       CP02[0] = String.valueOf(rsa.encrypt(NCinBI, ServerPublicKey));
       CP02[1] = "1";
       CP02[2] = "1";
       CP02[3] = "1";
         System.out.println("The Packet that will be send out contains");
       System.out.println("          CP02[0] contains the Pre_master_secrer: "  + CP02[0] );
       System.out.println("          CP02[1] is used for packet padding: "  + CP02[1] );
       System.out.println("          CP02[2] is used for packet padding: "  + CP02[2] );
       System.out.println("          CP02[3] is used for packet padding: "  + CP02[3] );
       System.out.println("          CP02 is put inside the Client quoue");
       //put CP02 in the qoue 
       updateQueueMethod(CP02);
       
       
       //Send out
       return CP02;
       
   }
   //Used the ClientNC , ServerNC , as well as the pre-mater-key   to generate the keys that will be used, all are 3 digits
   public void clientGenerateKeys(){
       //mulitpy together to generate keys
        System.out.println("-----------------------------------------");
        System.out.println("STEP 4: Client Generates the keys on its own");
        String result = Integer.toString(ClientNC * ServerNC * pre_master_key);
        KC = Integer.parseInt(result.substring(0, 2));
        MC =  Integer.parseInt(result.substring(2, 4));
        KS =  Integer.parseInt(result.substring(4, 6));
        MS =  Integer.parseInt(result.substring(6, 8));
        System.out.println("    KC: " + KC);
        System.out.println("    MC: " + MC);
        System.out.println("    KS: " + KS);
        System.out.println("    MS: " + MS);

       
 
   }
   //this generates the MAC of all the packets combined
    public String generateClientMAC(){
        
        System.out.println("-----------------------------------------");
        System.out.println("STEP 5: MAC of all packets is generated using MC");
        
        String[] CP01 = Queue.get(0);
        String[] SP01 = Queue.get(1);
        String[] CP02 = Queue.get(2);
        
        //cp01 IS changed so it has numbers instead of lettes
        
        CP01[0] = "1";
        CP01[1] = "1";
        CP01[2] = "1";
        
        //SP01 [3] is changed so can be converted to bigIntenger
        SP01[3] = "1";
        //Strings added Together
        String a1 = converttoString(CP01);
        String a2 = converttoString(SP01);
        String a3 = converttoString(CP02);
        String finalONE = a1 + a2 + a3;
       finalONE = finalONE.replaceAll("\\s","");
        //all variables converted to bigintenger so we can use them
        BigInteger numBig = new BigInteger(finalONE);
        BigInteger cipher = new  BigInteger( (String.valueOf(MC)) );
        
        //instance of the mac class is created
        
        mac.encrypt(numBig, cipher);
        BigInteger result =  mac.encrypt(numBig, cipher);
        //result is returned using tostring
        System.out.println("    the MAC is send out");
        return result.toString();
    }
    //If MACs (Calculated) == MACs (received) the handhsake was not tampered with and can be used
    public boolean CheckMAC(String fromServer){
        
        
        System.out.println("-----------------------------------------");
        System.out.println("STEP 7:  MAC that is received is compared to the MAC we got from server");
        System.out.println("    Received MAC" + fromServer);
        String[] CP01 = Queue.get(0);
        String[] SP01 = Queue.get(1);
        String[] CP02 = Queue.get(2);
        
        //cp01 IS changed so it has numbers instead of lettes
        
        CP01[0] = "1";
        CP01[1] = "1";
        CP01[2] = "1";
        
        //SP01 [3] is changed so can be converted to bigIntenger
        SP01[3] = "1";
        //Strings added Together
        String a1 = converttoString(CP01);
        String a2 = converttoString(SP01);
        String a3 = converttoString(CP02);
        String finalONE = a1 + a2 + a3;
        finalONE = finalONE.replaceAll("\\s","");
        //all variables converted to bigintenger so we can use them
        BigInteger numBig = new BigInteger(finalONE);
        BigInteger cipher = new  BigInteger( (String.valueOf(MS)) );
        
        //instance of the mac class is created
        MacCipher mac = new MacCipher();
        mac.encrypt(numBig, cipher);
        BigInteger result =  mac.encrypt(numBig, cipher);
        String caluclated = result.toString();
         System.out.println("    Generated MAC" + caluclated);
        if(caluclated.equals(fromServer)){
            System.out.println("The MAC's match, safe to form connection");
            return true;
        }
        else{
            System.out.println("The MAC's DO NOT match");
            return false;
        }

    }
    
    
    private String[] convertToArray(String packet){
         return packet.split(" ");
     }

    
    
    
    private String converttoString(String[] packet){
        String delimiter = " ";
        String result = String.join(delimiter, packet);
        return result;
    
    }
} //end class ChatClient
