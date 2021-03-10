package certFHE;

public class certFHESecretKey implements ISecretKey {

	private byte[] secretKey;
	
	static certFHEjni jniInstance = new certFHEjni();
	
	public certFHESecretKey()
	{
		
		this.secretKey = null;
	}
	
	public certFHESecretKey(byte[] key)
	{
		this.secretKey = key;
		
	}

	@Override
	public byte[] getKey() {
		return this.secretKey;
	}

	@Override
	public void setKey(byte[] key) {
		this.secretKey = key;
		
	}

	@Override
	public ISecretKey applyPermutation(IContext context,IPermutation perm) {
		ISecretKey secKey = new certFHESecretKey();
		byte[] newKey = jniInstance.applyPermutationOverKey(context.getN(), context.getD(), context.getU(), perm.getPermutation() , this.secretKey);
		secKey.setKey(newKey);
		return secKey;
	}

	@Override
	public String getStringSecretKey() {
		  StringBuilder sb = new StringBuilder();
		  
		  for (int i =0;i < this.secretKey.length;i++)
		  {
		       sb.append(String.format("%d", this.secretKey[i]));
		  if ( i != this.secretKey.length-1)
		        	  sb.append("-");
		     }
		    return sb.toString();
	}

	@Override
	public void setStringSecretLey(IContext context, String key) {
		    String[] keyparts = key.split("-");
	        byte[] seckey = new byte [(int) context.getN()];
	        int pos =0;
	        for (String x : keyparts)
	            seckey[pos++] = Byte.parseByte(x);
	         
	        this.secretKey = seckey;
		
	}
		
	
	
	
	
}
