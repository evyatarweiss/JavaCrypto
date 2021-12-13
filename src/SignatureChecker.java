
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureChecker {
	
	public static byte[] SignFile(PrivateKey key, String filePath, Configuration config) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException {
		byte[] signature;
		Signature fileSignature = Signature.getInstance(config.SignatureAlgorithm, config.signatureAlgorithmProvider);
		fileSignature.initSign(key);
		FileInputStream input = new FileInputStream(filePath);
		fileSignature.update(input.readAllBytes());
		signature = fileSignature.sign();
		return signature;
	}
	
	public static boolean checkFileSignature(PublicKey key, String filePath, Configuration config) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException {
		byte[] currentSignature = config.Signature;
		Signature fileSignature = Signature.getInstance(config.SignatureAlgorithm, config.signatureAlgorithmProvider);;
		fileSignature.initVerify(key);
		FileInputStream input = new FileInputStream(filePath);
		fileSignature.update(input.readAllBytes());
		return fileSignature.verify(currentSignature);
	}
}
