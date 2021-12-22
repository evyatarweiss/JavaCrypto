import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {
	Cipher decryptCipher;

	public Decryptor(Configuration config, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		decryptCipher = Cipher.getInstance(config.Algorithm, config.AlgorithmProvider);
		decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
	}

	public static SecretKey decryptKey(Key privateKey, byte[] encryptedKey, Configuration config) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		Cipher cipherKey = Cipher.getInstance(config.keyEncryptionAlgorithm, config.keyEncryptionAlgorithmProvider);
		cipherKey.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] keyArray =cipherKey.doFinal(encryptedKey);
		SecretKey key = new SecretKeySpec(keyArray,0 ,keyArray.length ,config.Algorithm.split("/")[0]);
		return key;
	}

	public void decryptFile(File encryptedFile, File plainTextFile) throws IOException {
		FileInputStream input = new FileInputStream(encryptedFile);
		CipherInputStream cipherInput = new CipherInputStream(input, decryptCipher);
		FileOutputStream output = new FileOutputStream("./decryptedFile");
		
		int bufferSize = 1;
		byte[] buffer = new byte[bufferSize];
	    int dataRead = input.read(buffer);
	
	    while (dataRead != -1) {
	
	    	output.write(buffer, 0, dataRead);
	        dataRead = input.read(buffer);
	    }
	    
		cipherInput.close();
		output.flush();
		output.close();
		input.close();
	}



}
