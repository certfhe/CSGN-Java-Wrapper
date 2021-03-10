package certFHE;

public class certFHECiphertext implements ICiphertext {

	private byte[] _values = null;
	private int _len = 0;
	private byte [] _bitlen = null;
	
	static certFHEjni jniInstance = new certFHEjni();
	
	
	@Override
	public ICiphertext multiply(ICiphertext op2,IContext context) {
		  ICiphertext res = new certFHECiphertext();
	        
	        internalCiphertext a = new internalCiphertext();
	        internalCiphertext b = new internalCiphertext();
	        internalCiphertext c = new internalCiphertext();
	        
	        a.len = this._len;
	        a.v = this._values;
	        a.bitlen = this._bitlen;
	        
	        b.len = op2.getLen();
	        b.v = op2.getValues();
	        b.bitlen = op2.getBitLen();
	        
	        
	        jniInstance._multiply(a, b, context.getN(), context.getD(), context.getU(), c);
	        
	        res.setLen( c.len);
	        res.setValues(c.v);
	        res.setBitLen(c.bitlen);
	        
			return res; 
	}

	@Override
	public ICiphertext add(ICiphertext op2) {

        ICiphertext res = new certFHECiphertext();
        
        internalCiphertext a = new internalCiphertext();
        internalCiphertext b = new internalCiphertext();
        internalCiphertext c = new internalCiphertext();
        
        a.len = this._len;
        a.v = this._values;
        a.bitlen = this._bitlen;
        
        b.len = op2.getLen();
        b.v = op2.getValues();
        b.bitlen = op2.getBitLen();
        
        
        jniInstance._add(a, b, c);
        
        res.setLen( c.len);
        res.setValues(c.v);
        res.setBitLen(c.bitlen);
        
		return res; 
	}

	@Override
	public void print() {
		  
	     System.out.print("Length of ciphertext: " +this._len + " bytes");System.out.println();
	     System.out.println("Ciphertext value : ");
	     StringBuilder sb = new StringBuilder();
	     for (byte b : this._values) {
	         sb.append(String.format("%02X ", b));
	     }
	     System.out.println(sb.toString());
	     System.out.println();

	}
	
	@Override
	public void encrypt(byte bit,IContext ctx,ISecretKey secretkey) {


		internalCiphertext ctxt = new internalCiphertext();
		jniInstance._encrypt(bit,ctxt,ctx.getN(),ctx.getD(),ctx.getU(),secretkey.getKey());
	     
		this._len = ctxt.len;
		this._values = ctxt.v;
		this._bitlen = ctxt.bitlen ;
	
	
	

	}
	
	@Override
	public byte decrypt(IContext ctx,ISecretKey secretkey) {
		
		byte dec = (byte) 0xFF;
		
		internalCiphertext ctxt = new internalCiphertext();
		ctxt.len = this._len;
		ctxt.v = this._values;
		ctxt.bitlen = this._bitlen;
		
		dec = jniInstance._decrypt(ctxt,  ctx.getN()  , ctx.getD(), ctx.getU(), secretkey.getKey());
			
		return dec;
	}

	@Override
	public byte[] getValues() {
		return this._values;
	}

	@Override
	public int getLen() {
		 return this._len;
	}

	@Override
	public byte[] getBitLen() {
		return this._bitlen;
	}

	@Override
	public void setValues(byte[] v) {
		this._values = v;
	}

	@Override
	public void setLen(int length) {
		this._len = length;
		
	}

	@Override
	public void setBitLen(byte[] bitlen) {
		this._bitlen = bitlen;
		
	}

	@Override
	public ICiphertext applyPermutation(IContext context, IPermutation perm) {
		ICiphertext permutedCiphertext = new certFHECiphertext();
		
		internalCiphertext a = new internalCiphertext();
		internalCiphertext b= new internalCiphertext();
		
		a.len = this._len;
		a.bitlen = this._bitlen;
		a.v = this._values;
		
		
		long[] nativePemr = perm.getPermutation();
		 jniInstance.applyPermutationOverCiphertext(context.getN(), context.getD(), context.getU(), nativePemr, a, b);
		 
		permutedCiphertext.setLen(b.len);
		permutedCiphertext.setBitLen(b.bitlen);
		permutedCiphertext.setValues(b.v);
		 
		 
		return permutedCiphertext;
	}

	@Override
	public String getStringCiphertext() {
		  StringBuilder sb = new StringBuilder();
		  sb.append(String.format("%d-", this._len));
		 
		  for (int i = 0; i <  this._len ; i++)
			 sb.append(String.format("%02X-", this._values[i]));     

		  for (int i = 0; i <  this._len ; i++)
		    {
			 sb.append(String.format("%02X", this._bitlen[i]));     
		     if (i !=   this._len-1)
		        	  sb.append("-");
		     }
		    return sb.toString();
	}

	@Override
	public void setStringCiphertext(IContext context, String ciphertext) {
		   String[] permParts = ciphertext.split("-");
		   int len = Integer.parseInt(permParts[0]);
		   this._len = len;
		   this._bitlen = new byte [len];
		   this._values = new byte [len];
		   for (int i = 0; i < len ; i++)
		   {
			   this._values[i] = (byte) (Integer.parseInt(permParts[1+i],16) &0xFF );
			   this._bitlen[i] = (byte) (Integer.parseInt(permParts[1+len+i],16) &0xFF );
			   //StringBuilder sb = new StringBuilder(); sb.append(String.format("%02x - %02x \n",  this._values[i], this._bitlen[i] ));
			   //System.out.print(sb.toString());
		   }
		   
	  
	}
	
	

}
