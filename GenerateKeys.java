//Rebecca Gruver
//rmg2186


import java.io.*;
import java.security.*;


public class GenerateKeys{
    public static void main(String[] args){
	try{
	    //Generate keys
	    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
	    gen.initialize(2048);
	    KeyPair keys = gen.generateKeyPair();

	    //Write private key
	    File privFile = new File(args[0]);
	    FileOutputStream privOut = new FileOutputStream(privFile);
	    privOut.write(keys.getPrivate().getEncoded());
	    privOut.flush();
	    privOut.close();
	
	    //Write public key
	    File pubFile = new File(args[1]);
	    FileOutputStream pubOut = new FileOutputStream(pubFile);
	    pubOut.write(keys.getPublic().getEncoded());
	    pubOut.flush();
	    pubOut.close();
	}catch(Exception e){
	    System.out.println("oops");
	    e.printStackTrace();
	}
    }
}
