package certFHE;

public interface IContext {

	public void setup(long n,long d,long u);
	public void setup();
	public ISecretKey generateSecretKey();
	public long getN();
	public long getD();
	public long getU();
	public long getDefN();
	public void setN(long n);
	public void setD(long d);
	public void setU(long u);
	public void setDefN(long defN);
	
	public IPermutation generatePermutation();
	
}
