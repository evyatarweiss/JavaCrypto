

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.NoSuchPaddingException;


public class EncryptorService {
	
	public static void main(String[] args) {
		// the keypass and keystore are the same for this keystore type
		String keyStorePassword = args[0];
		String keyPassword = keyStorePassword;
		String keyStorePath = args[1];
		// relative paths
		String fileToEncryptPath = "./plaintext.txt";
		String encryptedFilePath = "./ciphertext.txt";
		String configurationFilePath = "./config.properties";
		// the files
	    File configFile = new File(configurationFilePath);
		File plainTextFile = new File(fileToEncryptPath);
		File encryptedFile = new File(encryptedFilePath);
		System.out.println(configFile.getAbsolutePath());
		
		ConfigurationService configSevrice = new ConfigurationService(configFile);
		configSevrice.congfigurationLoader();
		Configuration config = configSevrice.getConfig();
		try {
			KeyStore ks = loadKeyStore(keyStorePath, keyStorePassword, config);
			Encryptor encrypt = new Encryptor(config);
			encrypt.EncryptFile(plainTextFile.getAbsolutePath(), encryptedFile.getAbsolutePath());
			Certificate aliasBCert = ks.getCertificate(config.AliasA);
			PublicKey publicKey = aliasBCert.getPublicKey();
			byte[] encryptedKey = encrypt.EncryptKey(config, publicKey);
			PrivateKey privateKey = (PrivateKey)(ks.getKey(config.AliasA, keyStorePassword.toCharArray()));
			byte[] signature = SignatureChecker.SignFile(privateKey, encryptedFile.getAbsolutePath(), config);
			configSevrice.writeEncryptionDataToFile(encrypt.getIV(), encryptedKey, signature);
			
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	private static KeyStore loadKeyStore(String keyStorePath, String password, Configuration config) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance(config.keyStoreType);
		FileInputStream input = new FileInputStream(keyStorePath); 
		keyStore.load(input, password.toCharArray());
		return keyStore;
	}
	
}
