
import java.io.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.Security.*;
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

			//creating a new encryptor object
			Encryptor encrypt = new Encryptor();

			//The Cipher initialized using the AES algorithm in CTR mode while using random IV
			IV Iv = encrypt.InitEncryptor(config);

			//Encrypt the plainText
			encrypt.EncryptFile(plainTextFile.getAbsolutePath(), encryptedFile.getAbsolutePath());

			//Signing on the encrypted text with ClientA private key
			byte[] signature = signFile(encryptedFile.getAbsolutePath(), keyPassword, config, ks);

			//Get the public key of ClientB
			Certificate aliasBCert = ks.getCertificate(config.AliasB);
			PublicKey publicKey = aliasBCert.getPublicKey();

			//Encrypt the symmetric key using ClientB public key
			byte[] encryptedKey = encrypt.EncryptKey(Iv.getKey(), config, publicKey);

			//The encrypted key as well as additional parameters will be saved in the config file
			//Also the digital signature of the encrypted file
			configSevrice.writeEncryptionDataToFile(Iv.ivParameterSpec, encryptedKey, signature);

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

	private static byte[] signFile(String encryptedFile, String keyPassword, Configuration config, KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeyException, UnrecoverableKeyException, SignatureException {
		PrivateKey privateKey = (PrivateKey) (ks.getKey(config.AliasA, keyPassword.toCharArray()));
		byte[] signature = SignatureChecker.SignFile(privateKey, encryptedFile, config);
		return signature;
	}
}