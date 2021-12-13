
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;
import java.util.Properties;

public class Configuration implements Serializable {

    public byte[] key;
    public byte[] Signature;
    public byte[] Iv;
    
    public String SignatureAlgorithm;
    public int keySize;
    public String Algorithm;
    public String AliasA;
    public String AliasB;
    public String KeyStore;
    public String signatureAlgorithmProvider;
    public String AlgorithmProvider;
    public String keyEncryptionAlgorithm;
    public String keyEncryptionAlgorithmProvider;
    public String keyStoreType;
    
}
