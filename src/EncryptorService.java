

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
		String keyStorePassword = args[0];
		String keyPassword = args[1];
		String keyStorePath = args[2];
		// relative paths
		String fileToEncryptPath = "./plaintext.txt";
		String encryptedFilePath = "./ciphertext.txt";
		String configurationFilePath = "./config.properties";
		// the files
	    File configFile = new File(configurationFilePath);
		File plainTextFile = new File(fileToEncryptPath);
		File encryptedFile = new File(encryptedFilePath);
		//Loading the properties from the file into the configuration Object
		//Were assuming that the properties file are in the right scheme.
		ConfigurationService configSevrice = new ConfigurationService(configFile);
		configSevrice.congfigurationLoader();
		Configuration config = configSevrice.getConfig();

		try {
			//If the communication goes from ClientA --> ClientB
			//were loading the keystore of clientB in order to pull his public key and to sign our data.
			KeyStore ks = loadKeyStore(keyStorePath, keyStorePassword, config);

			Encryptor encrypt = new Encryptor(config);
			IV Iv = encrypt.InitEncryptor(config);
			encrypt.EncryptFile(plainTextFile.getAbsolutePath(), encryptedFile.getAbsolutePath());

			//signing on the encrypted text
			byte[] signature = signFile(encryptedFile.getAbsolutePath(), keyPassword, config, ks);

			//encrypt the symetric Key
			Certificate aliasBCert = ks.getCertificate(config.AliasB);
			PublicKey publicKey = aliasBCert.getPublicKey();
			byte[] encryptedKey = encrypt.EncryptKey(config, publicKey);
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

	//Loading keystore
	private static KeyStore loadKeyStore(String keyStorePath, String keyStorePassword, Configuration config) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance(config.keyStoreType);
		FileInputStream input = new FileInputStream(keyStorePath); 
		keyStore.load(input, keyStorePassword.toCharArray());
		return keyStore;
	}
	private static byte[] signFile(String encryptedFile, String keyPassword, ConfigurationData config, KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
		PrivateKey privateKey = (PrivateKey)(ks.getKey(config.AliasA, keyPassword.toCharArray()));
		return SignatureManager.signFile(privateKey, encryptedFile, config);
	}
