
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

public class IV{
	public IvParameterSpec getIvParameterSpec() {
		return ivParameterSpec;
	}

	public Key getKey() {
		return key;
	}

	public IV(IvParameterSpec ivParameterSpec, Key key) {
		this.ivParameterSpec = ivParameterSpec;
		this.key = key;
	}

	IvParameterSpec ivParameterSpec;
	Key key;
}

