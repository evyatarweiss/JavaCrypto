import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
public class DecryptorService {

	public static void main(String[] args) {
		// the keypass and keystore pass are the same for this keystore
		String keyStorePassword = args[1];
		String keyPass = keyStorePassword;
		String keyStorePath = args[2];
		// relative paths
		String fileToEncryptPath = "./plaintext.txt";
		String encryptedFilePath = "./ciphertext.txt";
		String configurationFilePath = "./config.properties";
		// the files 
	    File configFile = new File(configurationFilePath);
		File plainTextFile = new File(fileToEncryptPath);
		File encryptedFile = new File(encryptedFilePath);
		ConfigurationService configService = new ConfigurationService(configFile);
		configService.congfigurationLoader();
		configService.loadDecryptionData();
		Configuration config = configService.getConfig();
		KeyStore ks;
		try {
			ks = loadKeyStore(keyStorePath, keyStorePassword, config);
			PrivateKey privateKey = (PrivateKey) ks.getKey(config.AliasB, keyPass.toCharArray());
			SecretKey key = Decryptor.decryptKey(privateKey, config.key, config);
			Decryptor decrypt = new Decryptor((Configuration) config, key, new IvParameterSpec(config.Iv));
			decrypt.decryptFile(encryptedFile, plainTextFile);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
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
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
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
