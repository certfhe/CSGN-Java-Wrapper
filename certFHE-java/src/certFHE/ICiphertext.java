package certFHE;

public interface ICiphertext {

	public ICiphertext multiply(ICiphertext a,IContext context);
	public ICiphertext add(ICiphertext a);
	public void print();
	public void encrypt(byte bit,IContext ctx,ISecretKey secretkey);
	public byte decrypt(IContext ctx,ISecretKey secretkey);
	
	public byte[] getValues();
	public int getLen();
	public byte[] getBitLen();
	
	public void setValues(byte[] v);
	public void setLen(int len);
	public void setBitLen(byte[] bitlen);
	
	public ICiphertext applyPermutation(IContext context,IPermutation perm);
	
	String getStringCiphertext();
	void setStringCiphertext(IContext context, String ciphertext);
}
