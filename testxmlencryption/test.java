package testxmlencryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class test {
	
	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(n);
	    SecretKey key = keyGenerator.generateKey();
	    return key;
	}
	
	public static IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
	
	public static String encrypt(String algorithm, String input, SecretKey key,
	    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException, InvalidKeyException,
	    BadPaddingException, IllegalBlockSizeException {
	    
	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
	    byte[] cipherText = cipher.doFinal(input.getBytes());
	    return Base64.getEncoder()
	        .encodeToString(cipherText);
	}
	
	public static String decrypt(String algorithm, String cipherText, SecretKey key,
	    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException, InvalidKeyException,
	    BadPaddingException, IllegalBlockSizeException {
	    
	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.DECRYPT_MODE, key, iv);
	    byte[] plainText = cipher.doFinal(Base64.getDecoder()
	        .decode(cipherText));
	    return new String(plainText);
	}

	public static void main(String[] args) throws Exception {
		String input = "hello world";
		System.out.println("input: " + input);
		
	    SecretKey key = test.generateKey(256);
	    System.out.println("key: " + Arrays.toString(key.getEncoded()));// print the byte array representation of the secret key
	    System.out.println("key: " + Base64.getEncoder().encodeToString(key.getEncoded())); // print the base64 string representation of the secret key
	    
	    IvParameterSpec ivParameterSpec = test.generateIv();
	    System.out.println("ivParameterSpec: " + Arrays.toString(ivParameterSpec.getIV()));
	    
	    String algorithm = "AES/CBC/PKCS5Padding";
	    String cipherText = test.encrypt(algorithm, input, key, ivParameterSpec);
	    String plainText = test.decrypt(algorithm, cipherText, key, ivParameterSpec);
	    //Assertions.assertEquals(input, plainText);
	    System.out.println("cipherText: " + cipherText);
	    System.out.println("plainText: " + plainText);
	    
	}

}
