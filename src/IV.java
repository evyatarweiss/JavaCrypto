
import javax.crypto.spec.IvParameterSpec;

public class IV {

	private IvParameterSpec iv;
	
	public IV(IvParameterSpec inputIV) {
		this.iv = inputIV;
	}
	
	public IvParameterSpec getIvParameterSpec() {
		return this.iv;
	}
}
