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

	public static SecretKey decryptKey(PrivateKey privateKey, byte[] encryptedKey, Configuration config) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		Cipher cipherKey = Cipher.getInstance(config.keyEncryptionAlgorithm, config.keyEncryptionAlgorithmProvider);
		cipherKey.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] keyArray = cipherKey.doFinal(encryptedKey);
		SecretKey key = new SecretKeySpec(keyArray, config.Algorithm);
		return key;
	}

	public void decryptFile(File encryptedFile, File plainTextFile) throws IOException {
		FileInputStream input = new FileInputStream(encryptedFile);
		CipherInputStream cipherInput = new CipherInputStream(input, decryptCipher);
		FileOutputStream output = new FileOutputStream(plainTextFile);
		int index = cipherInput.read();
		while (index != -1) {
			output.write(index);
			index = cipherInput.read();
		}
		cipherInput.close();
		output.flush();
		output.close();
		input.close();
	}



}
