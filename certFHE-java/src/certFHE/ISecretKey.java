package certFHE;

public interface ISecretKey {

 public byte[] getKey();
 public void setKey(byte[] key);
 
 public ISecretKey applyPermutation(IContext context, IPermutation perm);
    
 String getStringSecretKey();
 
 void setStringSecretLey(IContext context, String key);
 
}
