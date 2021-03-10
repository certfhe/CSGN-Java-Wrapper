package certFHE;

public class certFHEPermutation implements IPermutation {

		long[] permutation;

		static certFHEjni jniInstance = new certFHEjni();
		
		
		@Override
		public long[] getPermutation() {
			return permutation;
		}

		@Override
		public void setPermutation(long[] perm) {
			this.permutation = perm;
			
		}

		@Override
		public IPermutation getInverse(IContext context) {

			long[] inv = jniInstance.inverseOfPermutation(context.getN(), context.getD(), context.getU(),this.permutation);
			IPermutation permInv = new certFHEPermutation();
			permInv.setPermutation(inv);
			
			return permInv;
			
			
		}

		@Override
		public IPermutation combine(IContext context,IPermutation perm) {
			
			 long[] combinedPerm = jniInstance.combinePermutations(context.getN(), context.getD(), context.getU(), this.permutation, perm.getPermutation());
			 IPermutation result = new certFHEPermutation();
			 result.setPermutation(combinedPerm);
			 return result;
		}

		@Override
		public void print() {
			     System.out.println("Permutation (length " + permutation.length +") : ");
			     StringBuilder sb = new StringBuilder();
			     for (long b : this.permutation) {
			         sb.append(String.format("%d ", b));
			     }
			     System.out.println(sb.toString());
			     System.out.println(); 
		}

		@Override
		public String getStringPermutation() {
		     StringBuilder sb = new StringBuilder();
		     
		     for(int i =0;i<this.permutation.length;i++)
		     {
		         sb.append(String.format("%d", this.permutation[i]));
		         if (i != this.permutation.length-1)
		        	  sb.append("-");
		     }
		    return sb.toString();
		}

		@Override
		public void setStringPermutation(IContext context, String permutation) {
			    String[] permParts = permutation.split("-");
		        long[] perm = new long [(int) context.getN()];
		        int pos =0;
		        for (String x : permParts)
		        	perm[pos++] = Long.parseLong(x);
		         
		        this.permutation = perm;
			
		}
		
		
		
}
