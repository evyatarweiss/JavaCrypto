
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.spec.IvParameterSpec;

// Configuration service its an object that contains ..->
// properties that will be loaded from an external file name Configuration.properties
// in roder to provide an Algorithm extensibility etc

public class ConfigurationService {
	private Properties configProperties;
	private File configurationFile;
	private Configuration config;
	
	public ConfigurationService(File configFile) {
		this.configurationFile = configFile;
		this.configProperties = new Properties();
	}
	
	public Configuration getConfig() {
		return this.config;
	}
	
	public void congfigurationLoader() {
		FileInputStream input;
		this.config = new Configuration();
		try {
			input = new FileInputStream(this.configurationFile);
			try {
				configProperties.load(input);
				config.Algorithm = configProperties.getProperty("Algorithm");
				config.AlgorithmProvider = configProperties.getProperty("AlgorithmProvider");
				config.AliasA = configProperties.getProperty("AliasA");
				config.AliasB = configProperties.getProperty("AliasB");
				config.keyEncryptionAlgorithmProvider = configProperties.getProperty("keyEncryptionAlgorithmProvider");
				config.KeyStore = configProperties.getProperty("KeyStore");
				config.keyEncryptionAlgorithm = configProperties.getProperty("keyEncryptionAlgorithm");
				config.keyStoreType = configProperties.getProperty("keyStoreType");
				config.SignatureAlgorithm = configProperties.getProperty("SignatureAlgorithm");
				config.signatureAlgorithmProvider = configProperties.getProperty("signatureAlgorithmProvider");
				config.keySize = Integer.parseInt(configProperties.getProperty("keySize"));
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public void writeEncryptionDataToFile(IvParameterSpec iv, byte[] encryptedKey, byte[] signature) {
		// TODO Auto-generated method stub
		try {
			FileOutputStream output = new FileOutputStream(this.configurationFile);
			String signStr = new String(Base64.getEncoder().encode(signature));
			String ivStr = new String(Base64.getEncoder().encode(iv.getIV()));
			String keyStr = new String(Base64.getEncoder().encode(encryptedKey));
			configProperties.setProperty("signature", signStr);
			configProperties.setProperty("iv", ivStr);
			configProperties.setProperty("key", keyStr);
			configProperties.store(output, null);
			output.flush();
			output.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void loadDecryptionData() {
		// TODO Auto-generated method stub

		try {
			FileInputStream input = new FileInputStream(configurationFile);
			configProperties.load(input);
			config.key = Base64.getDecoder().decode(configProperties.getProperty("key"));
			config.Signature = Base64.getDecoder().decode(configProperties.getProperty("signature"));
			config.Iv = Base64.getDecoder().decode(configProperties.getProperty("iv"));
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
}
