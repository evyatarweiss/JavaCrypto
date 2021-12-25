
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryptor {
	// algorithm, provider, IV, keystore
	
	private Cipher encryptionCipher;
	private KeyGenerator keyGenerator;
	
	public IV InitEncryptor(Configuration config) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		encryptionCipher = Cipher.getInstance(config.Algorithm, config.AlgorithmProvider);
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[encryptionCipher.getBlockSize()];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);

		keyGenerator = KeyGenerator.getInstance(config.Algorithm.split("/")[0]);
		Key key = keyGenerator.generateKey();
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
		return new IV(ivParams,key);
	}

	public byte[] EncryptKey(Key keyToEncrypt, Configuration config, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(config.keyEncryptionAlgorithm, config.keyEncryptionAlgorithmProvider);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] cipherKey = cipher.doFinal(keyToEncrypt.getEncoded());
		return cipherKey;
	}
	
	public void EncryptFile(String fileLocation, String encryptedFileLocation) throws Exception {
		FileInputStream fis;
		FileOutputStream fos;
		CipherInputStream cis;
		fis = new FileInputStream(fileLocation);
		cis = new CipherInputStream(fis, encryptionCipher);
		fos = new FileOutputStream(encryptedFileLocation);
		byte[] b = new byte[8];
		int i = cis.read(b);
		while (i != -1) {
			//encoding in base64
			fos.write(b, 0, i);
			i = cis.read(b);
		}
		cis.close();
		fos.close();
	}

}
