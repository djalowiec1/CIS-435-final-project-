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
 * 
 * 
 * 
 * 
 * 
 * @Author <Dariusz Jalowiec, Tom Callahan>
 * 
 * 
 * Simulates the handshake, then simulates the messages being send over the network.
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


   public int ClientNC;
   private int ServerNC;
   private int pre_master_key;
   private int AlgoChoice;
   private int KC;
   private int MC;
   private int KS;
   private int MS;
   RSA rsa = new RSA();
  String[] SP01 = new  String[4];
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
          System.out.println("-----------------------------------------");
         System.out.println("STEP 2: Server Receivers CP01, and Creates SP01");
         
         listener.close();  
         incoming = new BufferedReader( 
                        new InputStreamReader(connection.getInputStream()) );
         outgoing = new PrintWriter(connection.getOutputStream());

         ChatServer server = new ChatServer();
       
          // step 2: server receives packet and sends SP01
          String CP01 = incoming.readLine();  
          String[] SP01 = server.pickAlgo(CP01);
          //System.out.println(server.converttoString(SP01));  
          outgoing.println(server.converttoString(SP01)); 
          outgoing.flush();
       
        
        //certify the client from CP02
         String CP02String = incoming.readLine();
         server.certifyClient(CP02String);
         
         
        //step 4: keys are generated;
       server.ServerGenerateKeys();
       
       
       
                //client mac is received
        String clientMAC = incoming.readLine();  
    //step 6: THE mac is generated and send out to Client
         String MAC = server.generateServerMAC();
         outgoing.println(MAC);
         outgoing.flush();
         

        //step 7: MAC is checked :
        if(server.CheckMAC(clientMAC) == false)
        {
            throw new Exception("Connected program is not a ChatServer!");
        }
         System.out.println("Connected.  Waiting for the first message.");
         System.out.println("----------------------------------------");
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
            
            ChatServer cs = new ChatServer();
            String[] msgArr = cs.convertToArray2(messageIn);
            System.out.println("Recieved Packet is: ");
            System.out.println("        Type: " + msgArr[0]);
            System.out.println("        Length: " + msgArr[1]);
            System.out.println("        Data: " + msgArr[2]);
            System.out.println("        MAC: " + msgArr[3]);


            messageIn = cs.removeFields(cs.convertToArray2(messageIn));
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
            String[] sentPacket = cs.appendFields(messageOut);
            messageOut = cs.converttoString2(sentPacket);
            System.out.println("Sent Packet is: ");
            System.out.println("        Type: " + sentPacket[0]);
            System.out.println("        Length: " + sentPacket[1]);
            System.out.println("        Data: " + sentPacket[2]);
            System.out.println("        MAC: " + sentPacket[3]);
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
   public String[] pickAlgo(String CP01String){
          System.out.println("The Server receivers this packet From client:");
         String[] CP01 = convertToArray(CP01String);
         System.out.println("          CP01[0]: " + CP01[0]);
         System.out.println("          CP01[1]: " + CP01[1]);
         System.out.println("          CP01[2]: " + CP01[2]);
         System.out.println("          CP01[3]: " + CP01[3]);
         System.out.println("          CP01 put in Server quoue");
       //client packet 1 is send to updateQueueMethod() to put inside queue
       updateQueueMethod(CP01);
       String[] SP01 = new  String[4];
        System.out.println("The Packet that will be send out contains");
    
       //a random fucntion picks between 1 or 2 to pick the algo
       Random random = new java.util.Random();
       int tmp = random.nextInt(3)+ 1;
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
       System.out.println("          SP01[0] which contains the algo choice: "  + SP01[0] );
       //the clientNC is taken out of packet
       ClientNC = Integer.parseInt(CP01[3]);
       //System.out.println(ClientNC);
       
       //keys are generated using rsa
       rsa.genKeys();
      
       BigInteger NC = new BigInteger(CP01[3]); 
       //encrypt the clientNC with the privaye key of server 
       BigInteger encrypterNC = rsa.encrypt(NC, rsa.privateKey);
       SP01[1] = String.valueOf(encrypterNC);
       System.out.println("          SP01[1] is the encrypted Client NC with Server Private KEY: "  + SP01[1] );
     
       //generate serverNC
     //  int x = random.nextInt(900) + 100;
       //the random number put inside packet
       SP01[2] = Integer.toString(666);
       ServerNC = 666;
       System.out.println("          SP01[2] contains the ServerNC: "  + SP01[2] );
       
       //put public key in last packet spot
       SP01[3] = (rsa.publicKey[0] + "," + rsa.publicKey[1]);
       //the updateQueueMethod() is called and SP01 Is put inside it 
       System.out.println("          SP01[3] contains the public key of server: "  + SP01[3] );
       System.out.println("          SP01 put in Server quoue");
       updateQueueMethod(SP01);
       //Packet returned
       return SP01;
       
       
   }


   //this method updates the list with any packets
   public void updateQueueMethod(String[] packet){
        Queue.add(packet);
   }
   //Takes the packet generated from certifyServer() and extracts each part. 
    //Extract the pre-master-secret with the server private key
   //makes sure both have the same key
   
   public void certifyClient(String CP02String){
       //put cp02 inside the quoue
       String[] CP02 = convertToArray(CP02String);
       updateQueueMethod(CP02);
       
       //extract the premastersecret    
       BigInteger enryptedSecret = new BigInteger(CP02[0]);
       pre_master_key = (rsa.decrypt(enryptedSecret, rsa.privateKey)).intValue();

       
   } 
    //indepedantly generate keys 
     public void ServerGenerateKeys(){
       //mulitpy together to generate keys
       //int result = ClientNC * ServerNC * pre_master_key;
        System.out.println("-----------------------------------------");
        System.out.println("STEP 4: Server Generates the keys on its own");
       //sepeare reulst in 2 char chunks, each representing a key
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
    //take a packet and make it a array
     private String[] convertToArray(String packet){
         return packet.split(" ");
    }
        //take a packet and make it a array
    private String[] convertToArray2(String packet){
         return packet.split(",");
    }
    //take packet array and make it a string
    private String converttoString(String[] packet){
        String delimiter = " ";
        String result = String.join(delimiter, packet);
        return result;
    
    }
       //take a packet and make it a array
    private String converttoString2(String[] packet){
        String delimiter = ",";
        String result = String.join(delimiter, packet);
        return result;
    
    }
    //generate ServeMAC from the packets
    public String generateServerMAC(){
        
        System.out.println("-----------------------------------------");
        System.out.println("STEP :6 MAC of all packets is generated using MS");
        
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
        //result is returned using tostring
        System.out.println("    the MAC is send out");
        return result.toString();
    }
    
    //take the packet from the client, and compare to the one we generated
    public boolean CheckMAC(String fromServer){
        
        
        System.out.println("-----------------------------------------");
        System.out.println("STEP 7:  MAC that is received is compared to the MAC we got from Client");
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
        BigInteger cipher = new  BigInteger( (String.valueOf(MC)) );
        
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
        
    //Message is Converted to packet for Server
    public String[] appendFields(String message)
    {
        String[] result = new String[4];
        
        //Step 1: Add TYPE
        System.out.println("convert message to packet");
        result[0] = "1";
        System.out.println("        Step 1: Calculate Type = " + result[0]);

        
        //Step 2: Add Length
        int length = message.length();
        result[1] = Integer.toString(length);
        System.out.println("        Step 2: Calculate Length = " + result[1]);

        
        //Step 3: Add Data
        result[2] = message;
        MacCipher MAC = new MacCipher();       
        String finalONE = message.replaceAll("\\s","");
        System.out.println("        Step 3: Calculate Data = " + result[2]);

        //Step 4: Add MAC of data
        BigInteger bigMAC = new BigInteger(finalONE.getBytes());
        String bigMACString = (MAC.encrypt(bigMAC, new BigInteger("2"))).toString();
        result[3] = bigMACString;
        System.out.println("        Step 4: Calculate MAC = " + result[3]);
        return result;
    }
   
    //Extract Data And Compare MAC
    public String removeFields(String[] message){
        System.out.println("Data Extraction and Comparison of MAC:");
        
        //Step 1: Extract Data
        String data = message[2];
        System.out.println("        Step 1: Extract Data From Packet: " + message[2]);
        MacCipher MAC = new MacCipher();
        String finalONE = data.replaceAll("\\s","");
        BigInteger bigMAC = new BigInteger(finalONE.getBytes());
        String bigMACString = (MAC.encrypt(bigMAC, new BigInteger("2"))).toString();
       
        //Step 2: Compare MAC of received data with MAC received
        System.out.println("        Step 2: MAC Calculated and Compared: ");
        System.out.println("            MAC Received: " + message[3]);
        System.out.println("            MAC Calculated: " + bigMACString);
        if(bigMACString.equals(message[3])){
        return data;
        }else{
           System.out.println("Data Changed!");
           return "-1";
        }
    }
} //end class ChatServer
