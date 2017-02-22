//Rebecca Gruver
//rmg2186
//Network Security Programming 1



import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;


public class Server{
	public static void main(String[] args){
	    //Get information from command line
	    int port = 0;
	    String privKeyPath = " ";
	    String pubKeyPath = " ";
	    boolean trusted = false;
	    try{
		String sPort = args[0];
		port = Integer.parseInt(sPort);
		String mode = args[1];
		if(mode.equals("t"))
		    trusted = true;
		else if(mode.equals("u"))
		    trusted = false;
		else{
		    System.out.println("Invalid mode");
		    System.exit(0);
		}		
		privKeyPath = args[2];
		pubKeyPath = args[3];
	    }catch(ArrayIndexOutOfBoundsException e){
		System.out.println("Not enough arguments");
		System.exit(0);
	    }catch(NumberFormatException e){
		System.out.println("Invalid port");
		System.exit(0);
	    }

	    //Create server and client sockets
	    ServerSocket serverSocket = null;
	    try{
		serverSocket = new ServerSocket(port);
	    }catch(IOException e){
		System.out.print("Could not listen on given port");
		System.exit(0);
	    }
	    Socket clientSocket = null;
	    try{
		clientSocket = serverSocket.accept();
	    }catch(IOException e){
		System.out.println("Could not connect to client");
		System.exit(0);
	    }

	    //Get data from Client
	    byte[] pass = null;
	    byte[] message = null;
	    byte[] sign = null;
	    try{
		DataInputStream in = new DataInputStream(clientSocket.getInputStream());
		int messageLength = in.readInt();
		message = null;
		if(messageLength>0){
		    message = new byte[messageLength];
		    in.readFully(message, 0, messageLength);
		}
		int signLength = in.readInt();
		sign = null;
		if(signLength>0){
		    sign = new byte[signLength];
		    in.readFully(sign, 0, signLength);
		}
		int passLength = in.readInt();
		pass = null;
		if(passLength>0){
		    pass = new byte[passLength];
		    in.readFully(pass, 0, passLength);
		}
		in.close();
		clientSocket.close();
		serverSocket.close();
	    }catch(IOException e){
		e.printStackTrace();
		System.exit(0);
	    }
	    byte[] decryptedPass = null;

	    //Get private key
	    try{
		File fileKey = new File(privKeyPath);
		InputStream keyInStream = new FileInputStream(fileKey);
		byte[] byteKey = new byte[(int)fileKey.length()];
		DataInputStream dkInStream = new DataInputStream(keyInStream);
		dkInStream.readFully(byteKey);
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(byteKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(privSpec);
	    
		//Decrypt password
		Cipher rsac = Cipher.getInstance("RSA");
		rsac.init(Cipher.DECRYPT_MODE, privKey);
		decryptedPass = rsac.doFinal(pass);
	    }catch(FileNotFoundException e){
	    	System.out.println("Private Key file not found");
		System.exit(0);
	    }catch(Exception e){
		System.out.println("OOPS, Something went wrong");
		System.exit(0);
	    }	    
	    byte[] bfake = null;
	    try{
		//Get fake file
		File fakeFile = new File("fakefile");
		InputStream fakeInStream = new FileInputStream(fakeFile);
		bfake = new byte[(int)fakeFile.length()];
		DataInputStream dataInStream = new DataInputStream(fakeInStream);
		dataInStream.readFully(bfake);
	    }catch(FileNotFoundException e){
		System.out.println("fakefile not found");
		System.exit(0);
	    }catch(Exception e){
		System.out.println("OOPS, something went wrong");
		System.exit(0);
	    }
	    byte[] decryptedFile = null;
	    try{
		byte[] mess = null;
		if(trusted)
			mess = message;
		else
			mess = bfake;

		//Check length and Seperate IV
		byte[] iv = new byte[16];
		System.arraycopy(mess, 0, iv, 0, 16);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		byte[] encMessage = new byte[mess.length-16];
		System.arraycopy(mess, 16, encMessage, 0, mess.length-16);
		//Decrypt message
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(decryptedPass, "AES");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		decryptedFile = cipher.doFinal(encMessage);

		//Write file
		FileOutputStream out = new FileOutputStream("./decryptedfile");
		out.write(decryptedFile);
		out.close();
	    }catch(Exception e){
		System.out.println("Decryption Failed");
		System.out.println("Verification Failed");
		System.exit(0);
	    }

	    try{
		//Get client public key
		File fileKey = new File(pubKeyPath);
		InputStream keyInStream = new FileInputStream(fileKey);
		byte[] byteKey = new byte[(int)fileKey.length()];
		DataInputStream dkInStream = new DataInputStream(keyInStream);
		dkInStream.readFully(byteKey);
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(byteKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(pubSpec);

		//Verify
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(pubKey);
		System.out.println(trusted);
		sig.update(decryptedFile);
		//Code from previous explination of fakeFile
		//Keeping in case it changes again
		/*if(trusted){
		    sig.update(decryptedFile);
		    System.out.println("a");
		}
		else{
		    sig.update(bfake);
		    System.out.println("b");
		}*/
		boolean ver = sig.verify(sign);
		System.out.println(ver);
		if(ver)
		    System.out.println("Verification Passed");
		else
		    System.out.println("Verification Failed");
	    }catch(FileNotFoundException e){
		System.out.println("Public Key file not found");
	    }catch(Exception e){
		System.out.println("OOPS");
		e.printStackTrace();
	    }
	    
	}
}
