import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * This program is one end of a simple command-line interface chat program.
 * It acts as a server which waits for a connection from the ChatClient 
 * program.  The port on which the server listens can be specified as a 
 * command-line argument.  
 * This program only supports one connection.  As soon as a connection is 
 * opened, the listening socket is closed down.  The two ends of the connection
 * each send a HANDSHAKE string to the other, so that both ends can verify
 * that the program on the other end is of the right type.  Then the connected 
 * programs alternate sending messages to each other.  The client always sends 
 * the first message.  The user on either end can close the connection by 
 * entering the string "quit" when prompted for a message.  Note that the first 
 * character of any string sent over the connection must be 0 or 1; this
 * character is interpreted as a command for security purpose
 */
public class ChatServer {

   /**
    * Port to listen on, if none is specified on the command line.
    */
   static final int DEFAULT_PORT = 1728;

   /**
    * Handshake string. Each end of the connection sends this  string to the 
    * other just after the connection is opened.  This is done to confirm that 
    * the program on the other side of the connection is a ChatClient program.
    */
   static final String HANDSHAKE = "CIS435535";

   /**
    * This character is prepended to every message that is sent.
    */
   static final char MESSAGE = '0'; //more like the type in SSL


   /**
    * This character is sent to the connected program when the user quits.
    */
   static final char CLOSE = '1'; //more like the type in SSL


   private int ClientNC;
   private int ServerNC;
   private int pre_master_key;
   private int AlgoChoice;
   private int KC;
   private int MC;
   private int KS;
   private int MS;
   RSA rsa = new RSA();
   List<String[]> Queue = new ArrayList<String[]>();
   
   public static void main(String[] args) {

      int port = DEFAULT_PORT;   // The port on which the server listens.

      ServerSocket listener;  // Listens for a connection request.
      Socket connection;      // For communication with the client.

      BufferedReader incoming;  // Stream for receiving data from client.
      PrintWriter outgoing;     // Stream for sending data to client.
      String messageOut;        // A message to be sent to the client.
      String messageIn;         // A message received from the client.
      
      BufferedReader userInput; // A wrapper for System.in, for reading
                                // lines of input from the user.

      
      /* Wait for a connection request.  When it arrives, close
           down the listener.  Create streams for communication
           and exchange the handshake. */

      try {
         listener = new ServerSocket(port);
         System.out.println("Listening on port " + listener.getLocalPort());
         connection = listener.accept();
         listener.close();  
         incoming = new BufferedReader( 
                        new InputStreamReader(connection.getInputStream()) );
         outgoing = new PrintWriter(connection.getOutputStream());
         outgoing.println(HANDSHAKE);  // Send handshake to client.
         outgoing.flush();
         messageIn = incoming.readLine();  // Receive handshake from client.
         if (! HANDSHAKE.equals(messageIn) ) {
            throw new Exception("Connected program is not a ChatClient!");
         }
         System.out.println("Connected.  Waiting for the first message.");
      }
      catch (Exception e) {
         System.out.println("An error occurred while opening connection.");
         System.out.println(e.toString());
         return;
      }

      /* Exchange messages with the other end of the connection until one side
         or the other closes the connection.  This server program waits for 
         the first message from the client.  After that, messages alternate 
         strictly back and forth. */

      try {
         userInput = new BufferedReader(new InputStreamReader(System.in));
         System.out.println("NOTE: Enter 'quit' to end the program.\n");
         while (true) {
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
            System.out.print("SEND:      ");
            messageOut = userInput.readLine();
            if (messageOut.equalsIgnoreCase("quit"))  {
                  // User wants to quit.  Inform the other side
                  // of the connection, then close the connection.
               outgoing.println(CLOSE);
               outgoing.flush();  // Make sure the data is sent!
               connection.close();
               System.out.println("Connection closed.");
               break;
            }
            outgoing.println(MESSAGE + messageOut);
            outgoing.flush(); // Make sure the data is sent!
            if (outgoing.checkError()) {
               throw new IOException("Error occurred while transmitting message.");
            }
         }
      }
      catch (Exception e) {
         System.out.println("Sorry, an error has occurred.  Connection lost.");
         System.out.println("Error:  " + e);
         System.exit(1);
      }

   }  // end main()
    

   //gets the inforamtion generated from startHandshake(), this class deicdeds what algos to use as well as send the encypted clientNC for cetryfication
   public String[] pickAlgo(String[] CP01){
      
       //client packet 1 is send to updateQueueMethod() to put inside queue
       updateQueueMethod(CP01);
       String[] SP01 = new  String[4];
       
       //a random fucntion picks between 1 or 2 to pick the algo
       Random random = new java.util.Random();
       int tmp = random.nextInt(3) + 1;
       switch (tmp) {
           case 1:
               SP01[0] = "1";
               break;
           case 2:
               SP01[0] = "2";
               break;
           default:
               SP01[0] = "3";
               break;
       }
       //the clientNC is taken out of packet
       ClientNC = Integer.parseInt(CP01[2]);
       
       ///HERE NEED TO ENCRYPRt WITH SERVER PRIVATE KEY
       rsa.genKeys();
      
       BigInteger NC = new BigInteger("ClientNC"); 
       //encrypt the clientNC with the privaye key of server 
       BigInteger encrypterNC = rsa.encrypt(NC, rsa.privateKey);
       SP01[1] = String.valueOf(encrypterNC);
     
       //generate serverNC
     //  int x = random.nextInt(900) + 100;
       //the random number put inside packet
       SP01[2] = Integer.toString(666);
       ServerNC = 666;
       
       //put public key in last packet spot
       SP01[3] = (rsa.publicKey[0] + "," + rsa.publicKey[1]);
       //the updateQueueMethod() is called and SP01 Is put inside it 
       updateQueueMethod(SP01);
       //Packet returned
       return SP01;
       
       
   }


   //this method updates the list with any packets
   public void updateQueueMethod(String[] packet){
        for (int i = 0; i < 4; i++) {
            if(Queue.get(i) == null ){
                Queue.set(i, packet);
                return;
            }
        }
   }
   //Takes the packet generated from certifyServer() and extracts each part. 
    //Extract the pre-master-secret with the server private key
   //makes sure both have the same key

   public void certifyClient(String[] CP02){
       //put cp02 inside the quoue
       updateQueueMethod(CP02);
       
       //extract the premastersecret    
       BigInteger enryptedSecret = new BigInteger(CP02[0]);
       pre_master_key = (rsa.decrypt(enryptedSecret, rsa.privateKey)).intValue();

       
   } 
   
     public void ServerGenerateKeys(){
       //mulitpy together to generate keys
       //int result = ClientNC * ServerNC * pre_master_key;
       
       //sepeare reulst in 2 char chunks, each representing a key
       String result = Integer.toString(ClientNC * ServerNC * pre_master_key);
        KC = Integer.parseInt(result.substring(0, 2));
        MC =  Integer.parseInt(result.substring(2, 4));
        KS =  Integer.parseInt(result.substring(4, 6));
        MS =  Integer.parseInt(result.substring(6, 8));
   }



} //end class ChatServer
