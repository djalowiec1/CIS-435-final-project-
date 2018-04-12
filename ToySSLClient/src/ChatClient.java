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
   RSA rsa = new RSA();


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
         outgoing.println(HANDSHAKE);  // Send handshake to client.
         outgoing.flush();
         messageIn = incoming.readLine();  // Receive handshake from client.
         if (! messageIn.equals(HANDSHAKE) ) {
            throw new IOException("Connected program is not CLChat!");
         }
         System.out.println("Connected.  Enter your first message.");
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
       String[] CP01 = new  String[4];
       //the 2 choices put inside the first 2 parts of the packer
       CP01[0] = "Rsa + shift + hash";    
       CP01[1] = "Rsa + shift + hash";
       CP01[2] = "SubstitutionCipher + RSA + DigitalSignature + CA"; 
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
       return CP01;
 
   }
   List<String[]> Queue = new ArrayList<String[]>();

   

   //this method updates the list with any packets
   public void updateQueueMethod(String[] packet){
        for (int i = 0; i < 4; i++) {
            if(Queue.get(i) == null ){
                Queue.set(i, packet);
                return;
            }
        }
   }
   //Takes the packet generated from pickAlgo() and extracts each part. 
    //Extract the ClientNC with the server public key to make sure the NC is correct. If not, break connection.
    //Generate a pre-master-secret, encrypt it with the servers public key and send out. 
    //call updateQueueMethod() to take note of SP02  then call  updateQueueMethod()  to put CP02 inside 

   public String[] certifyServer(String[] SP01){
       //put SP01 inside the list of packets
       updateQueueMethod(SP01);
       
       //extract choice 
       AlgoChoice =  Integer.parseInt(SP01[0]);
       
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
       BigInteger NCinBI = new BigInteger("pre_master_key"); 
       CP02[0] = String.valueOf(rsa.encrypt(NCinBI, ServerPublicKey));
       CP02[1] = "1";
       CP02[2] = "1";
       CP02[3] = "1";
       
       //put CP02 in the qoue 
       updateQueueMethod(CP02);
       
       
       //Send out
       return CP02;
       
   }
   //Used the ClientNC , ServerNC , as well as the pre-mater-key   to generate the keys that will be used, all are 3 digits
   public void clientGenerateKeys(){
       //mulitpy together to generate keys
        String result = Integer.toString(ClientNC * ServerNC * pre_master_key);
        KC = Integer.parseInt(result.substring(0, 2));
        MC =  Integer.parseInt(result.substring(2, 4));
        KS =  Integer.parseInt(result.substring(4, 6));
        MS =  Integer.parseInt(result.substring(6, 8));

       
       //sepeare reulst in 2 char chunks, each representing a key
       //NOT DONE 
   }


} //end class ChatClient
