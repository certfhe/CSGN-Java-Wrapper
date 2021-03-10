package certFHE;

public class certFHEjni {

	static {
		 System.loadLibrary("certFHEjni");
	}
	public native byte[] _setup();
	public native byte[] _setup(long n,long d,long u);
	public native void _multiply(internalCiphertext a,internalCiphertext b,long n,long d,long u, internalCiphertext res);
	public native void _add (internalCiphertext a,internalCiphertext b,internalCiphertext c );
	public native void _encrypt(byte bit, internalCiphertext a, long n,long d,long u, byte[] s);
	public native byte _decrypt(internalCiphertext a, long n,long d,long u, byte[] s );
	
	public native long[] generatePermutation(long n,long d,long u);
	public native void applyPermutationOverCiphertext(long n,long d,long u, long[] permutation, internalCiphertext in, internalCiphertext out);
	public native byte[] applyPermutationOverKey(long n, long d, long u, long[] permutation, byte[] secretKey);
	public native long[] combinePermutations(long n, long d, long u, long[] permutationA, long[] permutationB);
	public native long[] inverseOfPermutation(long n, long d, long u, long[] permutation);
	
	 public static void main(String[] args) {

		 int N = 1247;
		 int D = 64;
		 int U = 1;
		 System.out.print("certFHE secret key:   N= ");System.out.print(N);System.out.print("    D= ");System.out.print(D);System.out.println();
		 
		 //byte[] secretkey = new certFHEjni()._setup();
		 byte[] secretkey = new certFHEjni()._setup(N,D,1);
		 for (int i =0;i<N;i++)
		 {
		 System.out.print(secretkey[i]);
		 System.out.print(" ");
		 }
	 
	     System.out.println();
	     
	     
	     byte bit = 0x01;
	     System.out.println("Encrypting: "+ bit);
	     System.out.println();
	     internalCiphertext objctxt = new internalCiphertext();
	     internalCiphertext objctxt2 = new internalCiphertext();
	     new certFHEjni()._encrypt(bit,objctxt,N,D,U,secretkey);
	     new certFHEjni()._encrypt(bit,objctxt2,N,D,U,secretkey);
	     
		 
	     
	     
	     System.out.print("len of ciphertext: " +objctxt.v.length);System.out.println();
	     System.out.println("ciphertext in java: ");
	     StringBuilder sb = new StringBuilder();
	     for (byte b : objctxt.v) {
	         sb.append(String.format("%02X ", b));
	     }
	     System.out.println(sb.toString());
	     System.out.println();
	     
	/*     StringBuilder sb2 = new StringBuilder();
	     for (byte b : objctxt.bitlen) {
	         sb2.append(String.format("%d ", b));
	     }
	     System.out.println(sb2.toString());
	     System.out.println();
	     */
	     
	     byte dec = new certFHEjni()._decrypt(objctxt, N, D, U, secretkey);
	     System.out.println("decrypted: "+ dec);
	     System.out.println();
	     

	     internalCiphertext res = new internalCiphertext();
	     
	     new certFHEjni()._add(objctxt, objctxt2, res);
	     System.out.print("len of ciphertext after add: " +res.len);System.out.println();
	     System.out.println("ciphertext in java: ");
	     StringBuilder sb3 = new StringBuilder();
	     for (byte b : res.v) {
	         sb3.append(String.format("%02X ", b));
	     }
	     System.out.println(sb3.toString());
	     System.out.println(); 
	     
	     dec = new certFHEjni()._decrypt(res, N, D, U, secretkey);
	     System.out.println("decrypted ( " + bit +" + " + bit + ") = "+ dec);
	     System.out.println();
	     
	     internalCiphertext res2 = new internalCiphertext();
	     new certFHEjni()._multiply(objctxt, objctxt2,N,D,U, res2);
	     
	     System.out.print("len of ciphertext after multiply: " +res2.len);System.out.println();
	     System.out.println("ciphertext in java: ");
	     StringBuilder sb4 = new StringBuilder();
	     for (byte b : res2.v) {
	         sb4.append(String.format("%02X ", b));
	     }
	     System.out.println(sb4.toString());
	     System.out.println(); 
	     
	     dec = new certFHEjni()._decrypt(res2, N, D, U, secretkey);
	     System.out.println("decrypted ( " + bit +" * " + bit + ") = "+ dec);
	     System.out.println();
	     
	     
	     long[] permutation = new certFHEjni().generatePermutation(N,D,U);
	     System.out.println("permutation in java (" + permutation.length +") : ");
	     StringBuilder sb5 = new StringBuilder();
	     for (long b : permutation) {
	         sb5.append(String.format("%d ", b));
	     }
	     System.out.println(sb5.toString());
	     System.out.println(); 

	     internalCiphertext outPermuted = new internalCiphertext();
	     new certFHEjni().applyPermutationOverCiphertext(N, D, U, permutation, res2, outPermuted);
	     System.out.println();
	   
	     if ( outPermuted.v == null )
	    	 System.out.println("  v iS NULL ");
	     
	     System.out.print("len of ciphertext after permutation: " +outPermuted.len);System.out.println();
	     System.out.println("ciphertext in java: ");
	     StringBuilder sb6 = new StringBuilder();
	     for (byte b : outPermuted.v) {
	         sb6.append(String.format("%02X ", b));
	     }
	     System.out.println(sb6.toString());
	     System.out.println();   
	     
	     byte[] permutedSecretkey = new certFHEjni().applyPermutationOverKey(N, D, U, permutation, secretkey);
	     
	     System.out.println("permuted secret key in java " + permutedSecretkey.length + ": ");
	     StringBuilder sb7 = new StringBuilder();
	     for (int b : permutedSecretkey) {
	         sb7.append(String.format("%d ", b));
	     }
	     System.out.println(sb7.toString());
	     System.out.println(); 
	     
	     byte dec2 = new certFHEjni()._decrypt(outPermuted, N, D, U, permutedSecretkey);
	     System.out.println("decrypted  of permutated (should be 1): "+ dec2);
	     System.out.println();
	     
	     
	     long[] permInverse = new certFHEjni().inverseOfPermutation(N, D, U, permutation);
	     long[] combinedPerm = new certFHEjni().combinePermutations(N, D, U, permutation, permInverse);
	     
	     System.out.println("permutation o permutationInverse in java (" + permutation.length +") : ");
	     StringBuilder sb8 = new StringBuilder();
	     for (long b : combinedPerm) {
	         sb8.append(String.format("%d ", b));
	     }
	     System.out.println(sb8.toString());
	     System.out.println(); 

	     
	     
		 //byte[] a = new byte[16];
		 //byte[] b = new byte[16];
		 //byte[] res = new byte[16];
		 //new certFHEjni()._multiply(a,16,a,b,16,b,res,16,res);
		 //new certFHEjni()._add(a,16,a,b,16,b,res,16,res);
	 }


}

