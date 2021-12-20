
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
	private SecretKey key;
	private KeyGenerator keyGenerator;
	private IV iv;
	
	public Encryptor(Configuration config) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		encryptionCipher = Cipher.getInstance(config.Algorithm, config.AlgorithmProvider);
		keyGenerator = KeyGenerator.getInstance(config.Algorithm.split("/")[0]);
		key = keyGenerator.generateKey();
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key, getRandomIV(config));
	}

	public void writeKeyToConfigurationFile(byte[] key, Configuration config) {
		config.key = key;
	}
	
	public void writeSignatureToConfigurationFile(byte[] Signature, Configuration config) {
		config.Signature = Signature;
	}
	
	public byte[] EncryptKey(Configuration config, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(config.keyEncryptionAlgorithm, config.keyEncryptionAlgorithmProvider);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] cipherKey = cipher.doFinal(this.key.getEncoded());
		return cipherKey;
	}
	
	public void EncryptFile(String fileLocation, String encriptedFileLocation) throws Exception {
		FileInputStream fis;
		FileOutputStream fos;
		CipherInputStream cis;
		fis = new FileInputStream(fileLocation);
		cis = new CipherInputStream(fis, encryptionCipher);
		fos = new FileOutputStream(encriptedFileLocation);
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
	
	private IvParameterSpec getRandomIV(Configuration config) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[encryptionCipher.getBlockSize()];
	    new SecureRandom().nextBytes(iv);
	    this.iv = new IV(new IvParameterSpec(iv));
	    return this.iv.getIvParameterSpec();
	}
	
	public IvParameterSpec getIV() {
		return this.iv.getIvParameterSpec();
	}
}
