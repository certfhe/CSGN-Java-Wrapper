package certFHE;

public interface IPermutation {

	long[] getPermutation();
	void setPermutation(long [] perm);
	
	IPermutation getInverse(IContext context);
	IPermutation combine(IContext context,IPermutation perm);
	
	void print();
	String getStringPermutation();
	void setStringPermutation(IContext context, String permutation);
}
