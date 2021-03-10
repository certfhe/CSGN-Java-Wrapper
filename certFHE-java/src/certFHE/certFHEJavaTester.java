package certFHE;

public class certFHEJavaTester {

	
	 public static void main(String[] args) {
		 
		 System.out.print("Java certFHE Tester"); 
		 System.out.println();System.out.println();
		 
		 // Initialize crypto context
		 certFHEContext context = new certFHEContext();
	
		 context.setup(1247,64,1);
		 
		 //Generate secret key
		 ISecretKey secretkey = context.generateSecretKey();
		 
		 // Test the transformation of ISecretKey -> String -> ISecretKey
		 String secretkeystring = secretkey.getStringSecretKey();
		 System.out.print("secret key string: ");
		 System.out.print(secretkeystring); System.out.println();
		 ISecretKey newsecretkey = new certFHESecretKey();
		 newsecretkey.setStringSecretLey(context, secretkeystring);
		 secretkey = newsecretkey;
		 byte one = 0x01;
		 byte zero  = 0x00;
		 
		 //Instantiate certFHE ciphertexts
		 ICiphertext c1 = new certFHECiphertext();
		 ICiphertext c2 = new certFHECiphertext();
		 
		 //Encryption the bit "1" with certFHE
		 System.out.print("Encrypting " + one +" ....\n");System.out.flush();
		 c1.encrypt(one, context, secretkey);
		 c1.print();
		 
		 //Encryption the bit "0" with certFHE		 
		 System.out.print("Encrypting " + zero +" ....\n");System.out.flush();
		 c2.encrypt(zero, context, secretkey);
		 c2.print();
		 
		 //Decryption of ciphertexts
		 byte dc1 = c1.decrypt(context, secretkey);
		 byte dc2 = c2.decrypt(context, secretkey);
		 
		 System.out.print("dec ( enc("+ one + ") ) = " + dc1);  System.out.println();
		 System.out.print("dec ( enc("+ zero + ") ) = " + dc2);  System.out.println();
		 
		 
		 ICiphertext c1Addc2 = new certFHECiphertext();
		 
		 // Add two ciphertexts
		 c1Addc2 = c1.add(c2);
		 c1Addc2.print();
		 // Decrypt and check the result
		 byte dc3 = c1Addc2.decrypt(context, secretkey);
		 System.out.print("dec (enc (" +one + ") + enc("+ zero +") ) = " + dc3);  System.out.println();
		 
		 
	     ICiphertext c1Multiply2 = new certFHECiphertext();
		 
	     // Multiply two ciphertexts
	     c1Multiply2 = c1.multiply(c2,context);
	     c1Multiply2.print();
	     // Decrypt and check the result
		 byte dc4 = c1Multiply2.decrypt(context, secretkey);
		 System.out.print("dec ( enc("+one +") * enc("+zero + ") ) = " + dc4);  System.out.println();
		 System.out.println();
		 
		 // Generate a random permutation
		 IPermutation permutation = context.generatePermutation();
		 permutation.print();
		 // Test the transformation of the permutation: IPermutation->String->IPermutation	
		 String permutationString = permutation.getStringPermutation();
		 System.out.println(permutationString);
		 IPermutation recovered = new certFHEPermutation();
		 recovered.setStringPermutation(context, permutationString);
		 permutation = recovered;
	
		 
		 
		 // Get the inverse of permutation
		 IPermutation inverseOfPermutation = permutation.getInverse(context);
		 inverseOfPermutation.print();
		 
		 // Combine two permutations
		 IPermutation combinedPerm = permutation.combine(context, inverseOfPermutation);
		 combinedPerm.print();
		 
		 
		 // Apply the permutation over key
		 ISecretKey permutedKey = secretkey.applyPermutation(context, permutation);
		 // Apply the permutation over ciphertext
		 ICiphertext permutedCiphertext = c1.applyPermutation(context, permutation);
		 // Test the transformation ICiphertext-> String-> ICiphertext
		 String ciphertextstring = permutedCiphertext.getStringCiphertext();
		 System.out.println(ciphertextstring);
		 ICiphertext newpermutedCiphertext = new certFHECiphertext();
		 newpermutedCiphertext.setStringCiphertext(context, ciphertextstring);
		 permutedCiphertext = newpermutedCiphertext;
		 
		 byte dc5 = permutedCiphertext.decrypt(context, permutedKey);
		 System.out.print("Decrypting permuted ciphertext with permuted secret key: Dec ( Enc ( 1 ) ) = " + dc5 );
		 
		 
		 
		 
		 
	 }
}
