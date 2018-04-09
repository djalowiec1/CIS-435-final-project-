import java.net.*;
import java.io.*;
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

   public String[] startHandshake(){
       String[] packet = new  String[3];
       //the 2 choices put inside the first 2 parts of the packer
       packet[0] = "Rsa + shift + hash";
       packet[1] = "Rsa + shift + hash";
       
       //the random number is generated from 100 to 999
       Random random = new Random();
    // generate a random integer from 0 to 899, then add 100
       int x = random.nextInt(900) + 100;
       
       //random int converted to string and added
       packet[2] = Integer.toString(x);
       return null;
       
   }


} //end class ChatClient
