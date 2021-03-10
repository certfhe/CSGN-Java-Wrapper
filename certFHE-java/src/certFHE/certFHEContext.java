package certFHE;

public class certFHEContext implements IContext {
	
	
	private long _n = 0; 
	private long _d = 0;
	private  long _u =0;
	private  long _defLen =0;
	
	static certFHEjni jniInstance = new certFHEjni();
	
	@Override
	public void setup() {
		this._n = 1247;
		this._d = 64;
		this._u = 1;

		long div = this._n/64;
		long rem = this._n % 64;
		this._defLen = div;
		if ( rem != 0)
			this._defLen++;
		

	}

	@Override
	public void setup(long n, long d, long u) {
	
		this._n = n;
		this._d = d;
		this._u = u;

		long div = this._n/64;
		long rem = this._n % 64;
		this._defLen = div;
		if ( rem != 0)
			this._defLen++;
		
	}

	@Override
	public ISecretKey generateSecretKey() {
		byte[] secretkey = null;
		secretkey = jniInstance._setup(this._n,this._d,this._u);
		ISecretKey key = new certFHESecretKey(secretkey);
		return key;
	}

	@Override
	public long getN() {
		return this._n;
	}

	@Override
	public long getD() {
		return this._d;
	}

	@Override
	public long getU() {
		return this._u;
	}

	@Override
	public long getDefN() {
		return this._defLen;
	}

	@Override
	public void setN(long n) {
		this._n = n;
		
	}

	@Override
	public void setD(long d) {
		this._d = d;
		
	}

	@Override
	public void setU(long u) {
		this._u = u;
		
	}

	@Override
	public void setDefN(long defN) {
		this._defLen = defN ;
		
	}

	@Override
	public IPermutation generatePermutation() {
		IPermutation perm = new certFHEPermutation();	
		long [] _permutation =jniInstance.generatePermutation(this._n, this._d, this._u);
		perm.setPermutation(_permutation);
		
		return perm;
	}

	
	
	
}
