import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DecryptorService {

	public static void main(String[] args) {
		String keyStorePassword = args[0];
		String keyPass = args[1];
		String keyStorePath = args[2];
		// relative paths

		String fileToDecryptToPath = "./DecryptedPlaintext.txt";
		String encryptedFilePath = "./ciphertext.txt";
		String configurationFilePath = "./config.properties";

		// the files 
	    File configFile = new File(configurationFilePath);
		File plainTextFile = new File(fileToDecryptToPath);
		File encryptedFile = new File(encryptedFilePath);

		ConfigurationService configService = new ConfigurationService(configFile);
		configService.congfigurationLoader();
		configService.loadDecryptionData();
		Configuration config = configService.getConfig();
		KeyStore ks;

		try {
			//Loading clientB keystore in order to pull PrivateKey
			ks = loadKeyStore(keyStorePath, keyStorePassword, config);
			Key privateKey = ks.getKey(config.AliasB, keyPass.toCharArray());

			//Decrypt symmetric key using ClientB private key
			SecretKey SymmetricKey = Decryptor.decryptKey(privateKey, config.key, config);

			//Decrypt Cipher using Symmetric Key
			Decryptor decrypt = new Decryptor(config, SymmetricKey, new IvParameterSpec(config.Iv));
			decrypt.decryptFile(encryptedFile, plainTextFile);

			//validation of signature
			PublicKey publicKey = ks.getCertificate(config.AliasA).getPublicKey();
			boolean validSignature = SignatureChecker.checkFileSignature(publicKey, fileToDecryptToPath, config);
			if (!validSignature) {
				System.out.println("not valid signature");
			}

			System.out.println("file was decrypted successfully and signature is valid");

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException | InvalidKeyException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
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
