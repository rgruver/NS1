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

public class Client{
    public static void main(String[] args){
	String password = " ";
	String fileName;
	String server = "server";
	int port = 5555;
	try{
	    //get args in proper form
	    password = args[0];
	    if(!(password.length() == 16) || !(isAlphaNum(password))){
		System.out.println("Invalid password");
		System.exit(1);
	    }
	    byte[] pass = password.getBytes();
	    fileName = args[1];
	    server = args[2];
	    InetAddress address = InetAddress.getByName(server);
	    String portS = args[3];
	    port = Integer.parseInt(portS);
	    String privKeyPath = args[4];
	    String pubKeyPath = args[5];	    
	   
	    //Get file as bytearray
	    File file = new File(fileName);
	    InputStream fileInStream = new FileInputStream(file);
	    byte[] bfile = new byte[(int)file.length()];
	    DataInputStream dataInStream = new DataInputStream(fileInStream);
	    dataInStream.readFully(bfile);

	    //Hash file
	    //MessageDigest md = MessageDigest.getInstance("SHA-256");
	    //byte[] hash = md.digest(bfile);

	    //Get private key
	    File fileKey = new File(privKeyPath);
	    InputStream keyInStream = new FileInputStream(fileKey);
	    byte[] byteKey = new byte[(int)fileKey.length()];
	    DataInputStream dkInStream = new DataInputStream(keyInStream);
	    dkInStream.readFully(byteKey);
	    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(byteKey);
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    PrivateKey privKey = keyFactory.generatePrivate(privSpec);

	    //Signature
	    Signature sig = Signature.getInstance("SHA256withRSA");
	    sig.initSign(privKey);
	    sig.update(bfile);
	    byte[] signed = sig.sign();
	    
	    //IV Gen
	    SecureRandom rand = new SecureRandom();
	    byte[] iv = new byte[16];
	    rand.nextBytes(iv);
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);

	    //Encrypt file
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    SecretKeySpec keySpec = new SecretKeySpec(pass, "AES");
	    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
	    byte[] encrypted = cipher.doFinal(bfile);
	    byte[] encryptedFile = new byte[16+encrypted.length];
	    System.arraycopy(iv, 0, encryptedFile, 0, 16);
	    System.arraycopy(encrypted, 0, encryptedFile, 16, encrypted.length);

	    //Get server public key
	    File sFileKey = new File(pubKeyPath);
	    InputStream sKeyInStream = new FileInputStream(sFileKey);
	    byte[] sByteKey = new byte[(int)sFileKey.length()];
	    DataInputStream sdkInStream = new DataInputStream(sKeyInStream);
	    sdkInStream.readFully(sByteKey);
	    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(sByteKey);
	    KeyFactory sKeyFactory = KeyFactory.getInstance("RSA");
	    PublicKey pubKey = sKeyFactory.generatePublic(pubSpec);
	    
	    //Encrypt password
	    byte[] bpass = password.getBytes();
	    Cipher rsac = Cipher.getInstance("RSA");
	    rsac.init(Cipher.ENCRYPT_MODE, pubKey);
	    byte[] encryptedPass = rsac.doFinal(bpass);
	    
	    System.out.println("Boo");
	    //Connect and write to server
	    Socket socket = new Socket(address, port);
	    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
	    System.out.println("a");
	    out.writeInt(encryptedFile.length);
	    System.out.println("b");
	    out.write(encryptedFile);
	    out.writeInt(signed.length);
	    out.write(signed);
	    out.writeInt(encryptedPass.length);
	    out.write(encryptedPass);
	    System.out.println("c");
	    out.close();
	    socket.close();
	    System.out.println("HI");    
	}catch(ArrayIndexOutOfBoundsException e){
	    System.out.println("Not enough arguments");
	}catch(NumberFormatException e){
	    System.out.println("Invalid port");
	}catch(FileNotFoundException e){
	    System.out.println("File not found");
	}catch(UnknownHostException e){
	    System.out.println("Invalid host");
	}catch(IOException e){
	    System.out.println("OOPS, Something went wrong");
	}catch(Exception e){
	    System.out.println("OOPS, Something went wrong");
	}
    }

    public static Boolean isAlphaNum(String str){
	for(int i=1; i<str.length(); i++){
	    if(!(Character.isLetterOrDigit(str.charAt(i)))){
		return false;
	    }
	}
	return true;
    }
}
