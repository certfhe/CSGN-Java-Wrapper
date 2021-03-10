#include <jni.h>
#include <stdio.h>
#include <stdint.h>

#define BOOL bool
#define FALSE false
#define TRUE true
#define byte unsigned char

#include "certFHE_certFHEjni.h"

#define certFHE_Default_N 1247
#define certFHE_Default_D 64
#define certFHE_Default_U 1


#include "../certfhe-library/src/certFHE.h"

using namespace certFHE;

/*
 * Class:     certFHE_certFHEjni
 * Method:    _setup
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_certFHE_certFHEjni__1setup__
  (JNIEnv *env, jobject obj)
  {
	jbyteArray nArray = ((JNIEnv * )env)->NewByteArray(certFHE_Default_N);
	
	certFHE::Library::initializeLibrary();
	
	certFHE::Context context(certFHE_Default_N,certFHE_Default_D);
	certFHE::SecretKey seckey(context);
		
	uint64_t* s = seckey.getKey();
	jbyte zero = 0;
	jbyte one = 1;
	for(int i=0;i<certFHE_Default_N;i++)
		{   
			((JNIEnv * )env)->SetByteArrayRegion(nArray,i,sizeof(zero),&zero);
		}
		
	for(int i=0;i<certFHE_Default_D;i++)
		{
			((JNIEnv * )env)->SetByteArrayRegion(nArray,s[i],sizeof(one),&one);
		}
			
    return nArray; 
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    _setup
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_certFHE_certFHEjni__1setup__JJJ
  (JNIEnv * env, jobject obj, jlong n, jlong d, jlong u)
  {
	jbyteArray nArray = ((JNIEnv * )env)->NewByteArray(n);;
   
	certFHE::Context context(n,d);
	certFHE::SecretKey seckey(context);
		
	uint64_t* s = seckey.getKey();
	jbyte zero = 0;
	jbyte one = 1;
	for(int i=0;i<n;i++)
		{   
			((JNIEnv * )env)->SetByteArrayRegion(nArray,i,sizeof(zero),&zero);
		}
		
	for(int i=0;i<d;i++)
		{
			((JNIEnv * )env)->SetByteArrayRegion(nArray,s[i],sizeof(one),&one);
		}
  
    return nArray; 
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    _multiply
 * Signature: (LcertFHE/internalCiphertext;LcertFHE/internalCiphertext;JJJLcertFHE/internalCiphertext;)V
 */
JNIEXPORT void JNICALL Java_certFHE_certFHEjni__1multiply
  (JNIEnv *env, jobject obj, jobject a, jobject b, jlong n, jlong d, jlong u, jobject res)
  {
	certFHE::Library::initializeLibrary();
	  
	certFHE::Ciphertext ctxtA,ctxtB,ctxtC;
		
	certFHE::Context ctx(n,d);
 	
	jclass clsA = ((JNIEnv * )env)->GetObjectClass(a);
	jclass clsB = ((JNIEnv * )env)->GetObjectClass(b);
				
	jclass clsC = ((JNIEnv * )env)->GetObjectClass(res);
	jobject res2 =  ((JNIEnv * )env)->NewGlobalRef(res);
	res = res2;
		
	jfieldID fidValuesA,fidBitlenA,fidLenA;
	jfieldID fidValuesB,fidBitlenB,fidLenB;
	jfieldID fidValuesC,fidBitlenC,fidLenC;
	jbyteArray jbArrayValuesA,jbArrayValuesB,jbArrayValuesC;
	jbyteArray jbArrayBitlenA,jbArrayBitlenB,jbArrayBitlenC;
	jint jlenA,jlenB,jlenC;

    fidValuesA = ((JNIEnv * )env)->GetFieldID( clsA, "v", "[B");
    if (fidValuesA == 0)
	  {
		printf("Error in GetFieldID for v in internalCiphertext\n");
	  }
	  
	fidValuesB = ((JNIEnv * )env)->GetFieldID( clsB, "v", "[B");
    if (fidValuesB == 0)
	  {
		printf("Error in GetFieldID for v in internalCiphertext\n");
	  }
	
	fidValuesC = ((JNIEnv * )env)->GetFieldID( clsC, "v", "[B");
     if (fidValuesC == 0)
	  {
		printf("Error in GetFieldID for v in internalCiphertext\n");
	  }

    jobject retvalA = ((JNIEnv * )env)->GetObjectField(a, fidValuesA);
	jbArrayValuesA = (jbyteArray) retvalA;
	
	jobject retvalB = ((JNIEnv * )env)->GetObjectField(b, fidValuesB);
	jbArrayValuesB = (jbyteArray) retvalB;
	
	
	fidBitlenA = ((JNIEnv * )env)->GetFieldID( clsA, "bitlen", "[B");
    if (fidBitlenA == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	fidBitlenB = ((JNIEnv * )env)->GetFieldID( clsB, "bitlen", "[B");
    if (fidBitlenB == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	fidBitlenC = ((JNIEnv * )env)->GetFieldID( clsC, "bitlen", "[B");
    if (fidBitlenC == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	
	jobject retval2A = ((JNIEnv * )env)->GetObjectField(a, fidBitlenA);
    jbArrayBitlenA = (jbyteArray) retval2A;
	
	jobject retval2B = ((JNIEnv * )env)->GetObjectField(b, fidBitlenB);
    jbArrayBitlenB = (jbyteArray) retval2B;
	 

	fidLenA = ((JNIEnv * )env)->GetFieldID( clsA, "len", "I");
    if (fidLenA == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	fidLenB = ((JNIEnv * )env)->GetFieldID( clsB, "len", "I");
    if (fidLenB == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	
	fidLenC = ((JNIEnv * )env)->GetFieldID( clsC, "len", "I");
    if (fidLenC == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	
	jlenA = ((JNIEnv * )env)->GetIntField(a, fidLenA);
	jlenB = ((JNIEnv * )env)->GetIntField(b, fidLenB);
	
	uint64_t* ctxtA_bitlen = new uint64_t [jlenA/8];  
	uint64_t* ctxtA_v = new uint64_t [jlenA/8];       
	uint64_t* ctxtB_bitlen = new uint64_t [jlenB/8];  
	uint64_t* ctxtB_v = new uint64_t [jlenB/8];       
	
	uint64_t v,vaux,vaux2;
	for (uint64_t i = 0;i<jlenA/8;i++)  
		  {
			uint64_t bits = 0;
			v = 0;
			vaux = 0x00;	vaux2 = 0x00;
			for (int k =0;k<8;k++)
				{
					jbyte bitlenvalue;
					jbyte value;
					((JNIEnv * )env)->GetByteArrayRegion(jbArrayBitlenA,i*8+k,1,(jbyte *)&bitlenvalue);
					bits+= bitlenvalue;				 
					((JNIEnv * )env)->GetByteArrayRegion(jbArrayValuesA,i*8+k,1,&value);
					vaux = (v << 8) ;
					vaux2 = value & 0x00000000000000FF;				
					v = vaux | vaux2;				 
				}

		 	ctxtA_bitlen[i] = bits;
			ctxtA_v[i] = v;
		  }

		
	for (uint64_t i = 0;i<jlenB/8;i++)  
		  {
			uint64_t bits = 0;
			v = 0;
			vaux = 0x00;	vaux2 = 0x00;
			for (int k =0;k<8;k++)
			{
				 jbyte bitlenvalue;
				 jbyte value;
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayBitlenB,i*8+k,1,(jbyte *)&bitlenvalue);
				 bits+= bitlenvalue;				 
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayValuesB,i*8+k,1,&value);
				 vaux = (v << 8) ;
				 vaux2 = value & 0x00000000000000FF;				
				 v = vaux | vaux2;				 
			}

		 	 ctxtB_bitlen[i] = bits;
			 ctxtB_v[i] = v;
		  }

	try 
		{	
			certFHE::Ciphertext ctxtA(ctxtA_v,ctxtA_bitlen,jlenA/8,ctx); 
			certFHE::Ciphertext ctxtB(ctxtB_v,ctxtB_bitlen,jlenB/8,ctx); 
			
			delete [] ctxtA_bitlen;
			delete [] ctxtA_v;
			delete [] ctxtB_bitlen;
			delete [] ctxtB_v;
			
			ctxtC = ctxtA*ctxtB;
			uint64_t ctxtC_len = ctxtC.getLen();
			
			((JNIEnv * )env)->SetIntField(res, fidLenC, ctxtC_len*8);
			
			uint64_t v, vbitlen;
			byte bv=0x00;
			jbyte jv = 0x00;
			jbyte jvBitlen = 0x00;
	
			jbArrayValuesC = ((JNIEnv * )env)->NewByteArray(ctxtC_len*8);
			jobject jbArrayValues2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayValuesC);
			jbArrayValuesC = (jbyteArray)jbArrayValues2;
		  
		    jbArrayBitlenC = ((JNIEnv * )env)->NewByteArray(ctxtC_len*8);;
		    jobject jbArrayBitlen2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayBitlenC);
		    jbArrayBitlenC = (jbyteArray)jbArrayBitlen2;
		  
		    jbyte alleight =8;
		    jbyte zero =0;
			
			uint64_t* ctxtC_v = ctxtC.getValues();
			uint64_t* ctxtC_bitlen = ctxtC.getBitlen();
			
		    for (uint64_t i = 0;i<ctxtC_len;i++)  
			  {

				  v = ctxtC_v[i];
				  vbitlen = ctxtC_bitlen[i];
				  jvBitlen= vbitlen & 0xFF;			

				  if ( jvBitlen == 64 )
				  {
					
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+1,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+2,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+3,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+4,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+5,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+6,sizeof(alleight),&alleight);
						((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+7,sizeof(alleight),&alleight);
					  
				  }
				  else
				  {
					  jbyte dec = jvBitlen / 8;
					  jbyte rest = jvBitlen - dec*8;
					
					  
					  for(int j =0 ;j<dec;j++)
						 ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+j,sizeof(alleight),&alleight);
					 
					 ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+dec,sizeof(rest),&rest);
					 
					 for(int j =dec+1 ;j<8;j++)
						 ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+j,sizeof(zero),&zero);
					 
				  }


				   jv = v & 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+7+7*i,sizeof(jv),&jv);
				   jv = (v >>8)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+6+7*i,sizeof(jv),&jv);
				   jv = (v >>16)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+5+7*i,sizeof(jv),&jv);
				   jv = (v >>24)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+4+7*i,sizeof(jv),&jv);
				   jv = (v >>32)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+3+7*i,sizeof(jv),&jv);
				   jv = (v >>40)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+2+7*i,sizeof(jv),&jv);
				   jv = (v >>48)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+1+7*i,sizeof(jv),&jv);
				   jv = (v >>56)& 0xFF;
				   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+0+7*i,sizeof(jv),&jv);
				 
			  }
		
		
		((JNIEnv * )env)->SetObjectField(res, fidBitlenC, jbArrayBitlenC);
		((JNIEnv * )env)->SetObjectField(res, fidValuesC, jbArrayValuesC);
			
			
		}
		catch (...)
		{
			printf("Exception thrown at multiply procedure ! \n");fflush(stdout);
			return;
		}		  
	
	 return ;
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    _add
 * Signature: (LcertFHE/internalCiphertext;LcertFHE/internalCiphertext;LcertFHE/internalCiphertext;)V
 */
JNIEXPORT void JNICALL Java_certFHE_certFHEjni__1add
  (JNIEnv *env, jobject obj, jobject a, jobject b, jobject res)
  {
	
	certFHE::Library::initializeLibrary();
	
	jclass clsA = ((JNIEnv * )env)->GetObjectClass(a);
	jclass clsB = ((JNIEnv * )env)->GetObjectClass(b);
			
	jclass clsC = ((JNIEnv * )env)->GetObjectClass(res);
	jobject res2 =  ((JNIEnv * )env)->NewGlobalRef(res);
	res = res2;
	
	jfieldID fidValuesA,fidBitlenA,fidLenA;
	jfieldID fidValuesB,fidBitlenB,fidLenB;
	jfieldID fidValuesC,fidBitlenC,fidLenC;
	jbyteArray jbArrayValuesA,jbArrayValuesB,jbArrayValuesC;
	jbyteArray jbArrayBitlenA,jbArrayBitlenB,jbArrayBitlenC;
	jint jlenA,jlenB,jlenC;

    fidValuesA = ((JNIEnv * )env)->GetFieldID( clsA, "v", "[B");
    if (fidValuesA == 0)
	 {
	  printf("Error in GetFieldID for v in internalCiphertext\n");
	 }
	 
	fidValuesB = ((JNIEnv * )env)->GetFieldID( clsB, "v", "[B");
    if (fidValuesB == 0)
	 {
	  printf("Error in GetFieldID for v in internalCiphertext\n");
	 }
	
	fidValuesC = ((JNIEnv * )env)->GetFieldID( clsC, "v", "[B");
     if (fidValuesC == 0)
	  {
		  printf("Error in GetFieldID for v in internalCiphertext\n");
	  }
	  
    jobject retvalA = ((JNIEnv * )env)->GetObjectField(a, fidValuesA);
	jbArrayValuesA = (jbyteArray) retvalA;
	
	jobject retvalB = ((JNIEnv * )env)->GetObjectField(b, fidValuesB);
	jbArrayValuesB = (jbyteArray) retvalB;
	
	fidBitlenA = ((JNIEnv * )env)->GetFieldID( clsA, "bitlen", "[B");
    if (fidBitlenA == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	fidBitlenB = ((JNIEnv * )env)->GetFieldID( clsB, "bitlen", "[B");
    if (fidBitlenB == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	fidBitlenC = ((JNIEnv * )env)->GetFieldID( clsC, "bitlen", "[B");
    if (fidBitlenC == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	
	jobject retval2A = ((JNIEnv * )env)->GetObjectField(a, fidBitlenA);
    jbArrayBitlenA = (jbyteArray) retval2A;
	
	jobject retval2B = ((JNIEnv * )env)->GetObjectField(b, fidBitlenB);
    jbArrayBitlenB = (jbyteArray) retval2B;
	 

	fidLenA = ((JNIEnv * )env)->GetFieldID( clsA, "len", "I");
    if (fidLenA == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	fidLenB = ((JNIEnv * )env)->GetFieldID( clsB, "len", "I");
    if (fidLenB == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	
	fidLenC = ((JNIEnv * )env)->GetFieldID( clsC, "len", "I");
    if (fidLenC == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	
	jlenA = ((JNIEnv * )env)->GetIntField(a, fidLenA);
	jlenB = ((JNIEnv * )env)->GetIntField(b, fidLenB);
	
	uint64_t* ctxtA_bitlen = new uint64_t [jlenA/8];
	uint64_t* ctxtA_v = new uint64_t [jlenA/8];
	uint64_t* ctxtB_bitlen = new uint64_t [jlenB/8];
	uint64_t* ctxtB_v = new uint64_t [jlenB/8];
	
	uint64_t v,vaux,vaux2;
	for (uint64_t i = 0;i<jlenA/8;i++)  
		  {
			uint64_t bits = 0;
			v = 0;
			vaux = 0x00;	vaux2 = 0x00;
			for (int k =0;k<8;k++)
			{
				 jbyte bitlenvalue;
				 jbyte value;
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayBitlenA,i*8+k,1,(jbyte *)&bitlenvalue);
				 bits+= bitlenvalue;				 
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayValuesA,i*8+k,1,&value);
				 vaux = (v << 8) ;
				 vaux2 = value & 0x00000000000000FF;				
				 v = vaux | vaux2;				 
			}
			
		 	 ctxtA_bitlen[i] = bits;
			 ctxtA_v[i] = v;
			
		  }
		  
	for (uint64_t i = 0;i<jlenB/8;i++)  
		  {
			uint64_t bits = 0;
			v = 0;
			vaux = 0x00;	vaux2 = 0x00;
			for (int k =0;k<8;k++)
			{
				 jbyte bitlenvalue;
				 jbyte value;
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayBitlenB,i*8+k,1,(jbyte *)&bitlenvalue);
				 bits+= bitlenvalue;				 
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayValuesB,i*8+k,1,&value);
				 vaux = (v << 8) ;
				 vaux2 = value & 0x00000000000000FF;				
				 v = vaux | vaux2;				 
			}

		 	 ctxtB_bitlen[i] = bits;
			 ctxtB_v[i] = v;
			
		  }

	try 
		{	
		  //TODO: ! change the JNI interface to pass the context
		  //No implication at the moment since the add operator does not need the context
		  certFHE::Context ctx (certFHE_Default_N,certFHE_Default_D);  

		  certFHE::Ciphertext ctxtA(ctxtA_v,ctxtA_bitlen,jlenA/8,ctx); 
		  certFHE::Ciphertext ctxtB(ctxtB_v,ctxtB_bitlen,jlenB/8,ctx); 
	 
		  delete [] ctxtA_bitlen;
		  delete [] ctxtA_v;
		  delete [] ctxtB_bitlen;
		  delete [] ctxtB_v;

		  certFHE::Ciphertext ctxtC;
		  ctxtC  = ctxtA  +  ctxtB;  
		  
		  uint64_t ctxtC_len = ctxtC.getLen();
		  
		  ((JNIEnv * )env)->SetIntField(res, fidLenC, ctxtC_len*8);
	
		  uint64_t v, vbitlen;
		  byte bv=0x00;
		  jbyte jv = 0x00;
		  jbyte jvBitlen = 0x00;

		  jbArrayValuesC = ((JNIEnv * )env)->NewByteArray(ctxtC_len*8);
		  jobject jbArrayValues2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayValuesC);
		  jbArrayValuesC = (jbyteArray)jbArrayValues2;
		  
		  jbArrayBitlenC = ((JNIEnv * )env)->NewByteArray(ctxtC_len*8);;
		  jobject jbArrayBitlen2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayBitlenC);
		  jbArrayBitlenC = (jbyteArray)jbArrayBitlen2;
		  
		  jbyte alleight =8;
		  jbyte zero =0;
		  
		  uint64_t* ctxtC_v = ctxtC.getValues();
		  uint64_t* ctxtC_bitlen = ctxtC.getBitlen();
		
		  for (uint64_t i = 0;i<ctxtC_len;i++)  
		  {
			  
			  v = ctxtC_v[i];
			  vbitlen = ctxtC_bitlen[i];
			  jvBitlen= vbitlen & 0xFF;			

              if ( jvBitlen == 64 )
			  {
				
				    ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+1,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+2,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+3,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+4,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+5,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+6,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+7,sizeof(alleight),&alleight);
				  
			  }
			  else
			  {
				  jbyte dec = jvBitlen / 8;
				  jbyte rest = jvBitlen - dec*8;
				  
				  for(int j =0 ;j<dec;j++)
				     ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+j,sizeof(alleight),&alleight);
				 
				 ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+dec,sizeof(rest),&rest);
				 
				 for(int j =dec+1 ;j<8;j++)
				     ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenC,i+7*i+j,sizeof(zero),&zero);
				 
 			  }

			  jv = v & 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+7+7*i,sizeof(jv),&jv);
			  jv = (v >>8)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+6+7*i,sizeof(jv),&jv);
			  jv = (v >>16)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+5+7*i,sizeof(jv),&jv);
			  jv = (v >>24)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+4+7*i,sizeof(jv),&jv);
			  jv = (v >>32)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+3+7*i,sizeof(jv),&jv);
			  jv = (v >>40)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+2+7*i,sizeof(jv),&jv);
			  jv = (v >>48)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+1+7*i,sizeof(jv),&jv);
			  jv = (v >>56)& 0xFF;
			  ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesC,i+0+7*i,sizeof(jv),&jv);
			 
		  }
		
		((JNIEnv * )env)->SetObjectField(res, fidBitlenC, jbArrayBitlenC);
		((JNIEnv * )env)->SetObjectField(res, fidValuesC, jbArrayValuesC);
			
			
		}
		catch (...)
		{
			printf("Exception thrown at add procedure ! \n");fflush(stdout);
			return;
		}
		
	 return ;
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    _encrypt
 * Signature: (BLcertFHE/internalCiphertext;JJJ[B)V
 */
JNIEXPORT void JNICALL Java_certFHE_certFHEjni__1encrypt
  (JNIEnv *env, jobject obj, jbyte bit, jobject res, jlong n, jlong d, jlong u, jbyteArray s)
  {
	
	certFHE::Library::initializeLibrary();
    certFHE::Ciphertext c;
	certFHE::Context ctx(n,d);
			
	int tbit = (int) bit;
	certFHE::Plaintext plain(tbit);
	
	uint64_t* ss = new uint64_t [d];
	jbyte*  buf = ((JNIEnv * )env)->GetByteArrayElements(s,NULL);
	uint64_t dd = (uint64_t) d;
	uint64_t pos = 0;
	
	for (uint64_t i = 0; i<n;i++)
	{
		if (buf[i] == 1 )
			ss[pos++] = i;
	}

	try 
	{
		certFHE::SecretKey seckey(ctx);
		seckey.setKey(ss,dd);
		c= seckey.encrypt(plain);
		
	}
	catch (...)
	{
		printf("Exception thrown at encryption procedure ! \n");
		return;
	}
		
	jclass cls = ((JNIEnv * )env)->GetObjectClass(res);
	jobject res2 =  ((JNIEnv * )env)->NewGlobalRef(res);
	res = res2;
	jfieldID fidValues,fidBitlen,fidLen;
    jbyteArray jbArrayValues;
	jbyteArray jbArrayBitlen;
	jint jlen;

  
	fidValues = ((JNIEnv * )env)->GetFieldID( cls, "v", "[B");
	if (fidValues == 0)
	{
	 printf("Error in GetFieldID for v in internalCiphertext\n");
	}
 
	fidBitlen = ((JNIEnv * )env)->GetFieldID( cls, "bitlen", "[B");
    if (fidBitlen == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }

	fidLen = ((JNIEnv * )env)->GetFieldID( cls, "len", "I");
    if (fidLen == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }

	uint64_t ctxtC_len = c.getLen();
	uint64_t* ctxtC_v = c.getValues();
	uint64_t* ctxtC_bitlen = c.getBitlen();

   ((JNIEnv * )env)->SetIntField(res, fidLen, ctxtC_len*8);
	       
	uint64_t v, vbitlen;
	byte bv=0x00;
	jbyte jv = 0x00;
	jbyte jvBitlen = 0x00;

	jbArrayValues = ((JNIEnv * )env)->NewByteArray(ctxtC_len*8);
	jobject jbArrayValues2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayValues);
	jbArrayValues = (jbyteArray)jbArrayValues2;
	
	jbArrayBitlen = ((JNIEnv * )env)->NewByteArray(ctxtC_len*8);;
	jobject jbArrayBitlen2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayBitlen);
	jbArrayBitlen = (jbyteArray)jbArrayBitlen2;
	
	jbyte alleight =8;
	jbyte zero =0;
	for (uint64_t i = 0;i<ctxtC_len;i++)  
	{
			  
		v = ctxtC_v[i];
		vbitlen = ctxtC_bitlen[i];
		jvBitlen= vbitlen & 0xFF;			

        if ( jvBitlen == 64 )
		{	
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+1,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+2,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+3,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+4,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+5,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+6,sizeof(alleight),&alleight);
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+7,sizeof(alleight),&alleight);
			 
		}
		else
		{
			 jbyte dec = jvBitlen / 8;
			 jbyte rest = jvBitlen - dec*8;
			
			 for(int j =0 ;j<dec;j++)
				((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+j,sizeof(alleight),&alleight);
			
			((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+dec,sizeof(rest),&rest);
			
			for(int j =dec+1 ;j<8;j++)
				((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlen,i+7*i+j,sizeof(zero),&zero);
		
 		}
	   
		jv = v & 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+7+7*i,sizeof(jv),&jv);
		jv = (v >>8)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+6+7*i,sizeof(jv),&jv);
		jv = (v >>16)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+5+7*i,sizeof(jv),&jv);
		jv = (v >>24)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+4+7*i,sizeof(jv),&jv);
		jv = (v >>32)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+3+7*i,sizeof(jv),&jv);
		jv = (v >>40)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+2+7*i,sizeof(jv),&jv);
		jv = (v >>48)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+1+7*i,sizeof(jv),&jv);
		jv = (v >>56)& 0xFF;
		((JNIEnv * )env)->SetByteArrayRegion(jbArrayValues,i+0+7*i,sizeof(jv),&jv);
			  
	}
		
		((JNIEnv * )env)->SetObjectField(res, fidBitlen, jbArrayBitlen);
		((JNIEnv * )env)->SetObjectField(res, fidValues, jbArrayValues);
		
	if (ss != nullptr)
		delete [] ss;
		
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    _decrypt
 * Signature: (LcertFHE/internalCiphertext;JJJ[B)B
 */
JNIEXPORT jbyte JNICALL Java_certFHE_certFHEjni__1decrypt
  (JNIEnv *env, jobject obj, jobject c, jlong n, jlong d, jlong u, jbyteArray s)
  {
	jbyte result =0xFF;
	
	certFHE::Library::initializeLibrary();
	certFHE::Ciphertext ctxt; 
	
	uint64_t* ss = new uint64_t [d];
	uint64_t dd = d;
	
	jbyte*  buf = ((JNIEnv * )env)->GetByteArrayElements(s,NULL);
	uint64_t pos = 0;
	
	for (uint64_t i = 0; i<n;i++)
	{
		if (buf[i] == 1 )
			ss[pos++] = i;
	}
	
	uint64_t bit = 0xFF;
			
	jclass cls = ((JNIEnv * )env)->GetObjectClass(c);
	jfieldID fidValues,fidBitlen,fidLen;
    jbyteArray jbArrayValues;
	jbyteArray jbArrayBitlen;
	jint jlen;


    fidValues = ((JNIEnv * )env)->GetFieldID( cls, "v", "[B");
    if (fidValues == 0)
	  {
		  printf("Error in GetFieldID for v in internalCiphertext\n");
	  }

    jobject retval = ((JNIEnv * )env)->GetObjectField(c, fidValues);
	jbArrayValues = (jbyteArray) retval;
	
	
	fidBitlen = ((JNIEnv * )env)->GetFieldID( cls, "bitlen", "[B");
    if (fidBitlen == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	jobject retval2 = ((JNIEnv * )env)->GetObjectField(c, fidBitlen);
    jbArrayBitlen = (jbyteArray) retval2;
	 

	fidLen = ((JNIEnv * )env)->GetFieldID( cls, "len", "I");
    if (fidLen == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	
	
	jlen = ((JNIEnv * )env)->GetIntField(c, fidLen);
	
	
	uint64_t ctxt_len = jlen/8;
	
	
	uint64_t* ctxt_bitlen = new uint64_t [ctxt_len];
	uint64_t* ctxt_v = new uint64_t [ctxt_len];

	uint64_t v,vaux,vaux2;
    int move = 0;
	for (uint64_t i = 0;i<ctxt_len;i++)  
		  {
			uint64_t bits = 0;
			v = 0;
			vaux = 0x00;
			move = 0;
			for (int k =0;k<8;k++)
			{
				 jbyte bitlenvalue;
				 jbyte value;
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayBitlen,i*8+k,1,(jbyte *)&bitlenvalue);
				 bits+= bitlenvalue;
				 
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayValues,i*8+k,1,&value);
			
				 move = 8;
				 vaux = (v << move) ;
				 vaux2 = value & 0x00000000000000FF;				
				 v = vaux | vaux2;
			}

		 	 ctxt_bitlen[i] = bits;
			 ctxt_v[i] = v;

		  }

	try 
	{	
		certFHE::Context ctx(n,d);
		ctxt = Ciphertext(ctxt_v,ctxt_bitlen,ctxt_len,ctx);
		delete [] ctxt_bitlen;
		delete [] ctxt_v;
		certFHE::SecretKey seckey(ctx);
		seckey.setKey(ss,dd);
		certFHE::Plaintext plain=seckey.decrypt(ctxt);
		result = (jbyte) plain.getValue();
		
	}
	catch (...)
	{
		printf("Exception thrown at decryption procedure ! \n");fflush(stdout);
		return result;
	}

		
	if ( ss != NULL)
		delete [] ss;
			 
	 return result;
  }
  
/*
 * Class:     certFHE_certFHEjni
 * Method:    generatePermutation
 * Signature: (JJJ)[J
 */
JNIEXPORT jlongArray JNICALL Java_certFHE_certFHEjni_generatePermutation
  (JNIEnv *env, jobject obj, jlong n, jlong d, jlong u)
  {
	jlongArray nArray = ((JNIEnv * )env)->NewLongArray(n);;
	
	certFHE::Library::initializeLibrary();
	certFHE::Context ctx (n,d);
	
	certFHE::Permutation perm(ctx);

	uint64_t *p = perm.getPermutation();
	
	if (p!= NULL)
	for(int i=0;i<n;i++)
		{   
			((JNIEnv * )env)->SetLongArrayRegion(nArray,i,1,(const jlong*)&p[i]);
		}
	
    return nArray; 
	  
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    applyPermutationOverCiphertext
 * Signature: (JJJ[JLcertFHE/internalCiphertext;LcertFHE/internalCiphertext;)V
 */
JNIEXPORT void JNICALL Java_certFHE_certFHEjni_applyPermutationOverCiphertext
  (JNIEnv * env, jobject obj, jlong n, jlong d, jlong u, jlongArray permutation, jobject in , jobject output)
  {
	jlongArray nArray = ((JNIEnv * )env)->NewLongArray(n);;

	certFHE::Library::initializeLibrary();	
	jlong temp;

	uint64_t * permutationNative = new uint64_t [n];
	for (int w = 0; w< n ;w++)
	{					
		((JNIEnv * )env)->GetLongArrayRegion(permutation,w,1,&temp);  
		permutationNative[w] = (uint64_t) (temp & 0x7FFFFFFFFFFFFFFF);	
	}
	
	certFHE::Context ctx(n,d);
		
	jclass cls = ((JNIEnv * )env)->GetObjectClass(in);
	jfieldID fidValues,fidBitlen,fidLen;
    jbyteArray jbArrayValues;
	jbyteArray jbArrayBitlen;
	jint jlen;

		
    fidValues = ((JNIEnv * )env)->GetFieldID( cls, "v", "[B");
    if (fidValues == 0)
	  {
		  printf("Error in GetFieldID for v in internalCiphertext\n");
	  }

    jobject retval = ((JNIEnv * )env)->GetObjectField(in, fidValues);
	jbArrayValues = (jbyteArray) retval;
	
	
	fidBitlen = ((JNIEnv * )env)->GetFieldID( cls, "bitlen", "[B");
    if (fidBitlen == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }
	jobject retval2 = ((JNIEnv * )env)->GetObjectField(in, fidBitlen);
    jbArrayBitlen = (jbyteArray) retval2;
	 

	fidLen = ((JNIEnv * )env)->GetFieldID( cls, "len", "I");
    if (fidLen == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }
	
	jlen = ((JNIEnv * )env)->GetIntField(in, fidLen);
	
	
	uint64_t inCiphertext_len = jlen/8;
	uint64_t* inCiphertext_bitlen = new uint64_t [inCiphertext_len];
	uint64_t* inCiphertext_v = new uint64_t [inCiphertext_len];

	uint64_t v,vaux,vaux2;
    int move = 0;
	for (uint64_t i = 0;i<inCiphertext_len;i++)  
		  {
			uint64_t bits = 0;
			v = 0;
			vaux = 0x00;
			move = 0;
			for (int k =0;k<8;k++)
			{
				 jbyte bitlenvalue;
				 jbyte value;
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayBitlen,i*8+k,1,(jbyte *)&bitlenvalue);
				 bits+= bitlenvalue;
				 
				 ((JNIEnv * )env)->GetByteArrayRegion(jbArrayValues,i*8+k,1,&value);
			
				move = 8;
				 vaux = (v << move) ;
				 vaux2 = value & 0x00000000000000FF;				
				 v = vaux | vaux2;

				 
			}

		 	 inCiphertext_bitlen[i] = bits;
			 inCiphertext_v[i] = v;
			
		  }
	
	certFHE::Ciphertext  inCiphertext = certFHE::Ciphertext(inCiphertext_v,inCiphertext_bitlen,inCiphertext_len,ctx);
	
	delete [] inCiphertext_v;
	delete [] inCiphertext_bitlen;
	
	Permutation perm(ctx);
	perm.setPermutation(permutationNative,n);

	delete [] permutationNative;
	
	certFHE::Ciphertext result_ctxt =  inCiphertext.applyPermutation(perm);
	
	uint64_t result_len = result_ctxt.getLen();
	uint64_t *result_bitlen = result_ctxt.getBitlen();
	uint64_t *result_v = result_ctxt.getValues();

	
	jclass clsOut = ((JNIEnv * )env)->GetObjectClass(output);
	jobject Out2 =  ((JNIEnv * )env)->NewGlobalRef(output);
	output = Out2;
	jfieldID fidValuesOut,fidBitlenOut,fidLenOut;
    jbyteArray jbArrayValuesOut;
	jbyteArray jbArrayBitlenOut;
	jint jlenOut;
  
    fidValuesOut = ((JNIEnv * )env)->GetFieldID( clsOut, "v", "[B");
    if (fidValuesOut == 0)
    {
	    printf("Error in GetFieldID for v in internalCiphertext\n");
    }

 
	fidBitlenOut = ((JNIEnv * )env)->GetFieldID( clsOut, "bitlen", "[B");
    if (fidBitlenOut == 0)
    {
	  printf("Error in GetFieldID for bitlen in internalCiphertext\n");
    }

	fidLenOut = ((JNIEnv * )env)->GetFieldID( clsOut, "len", "I");
	
    if (fidLenOut == 0)
    {
	  printf("Error in GetFieldID for len in internalCiphertext\n");
    }

   ((JNIEnv * )env)->SetIntField(output, fidLenOut, result_len*8); 

		  uint64_t vbitlen;
		  byte bv=0x00;
		  jbyte jv = 0x00;
		  jbyte jvBitlen = 0x00;

		  jbArrayValuesOut = ((JNIEnv * )env)->NewByteArray(result_len*8);
		  jobject jbArrayValues2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayValuesOut);
		  jbArrayValuesOut = (jbyteArray)jbArrayValues2;
		 
		  jbArrayBitlenOut = ((JNIEnv * )env)->NewByteArray(result_len*8);;
		  jobject jbArrayBitlen2 =  ((JNIEnv * )env)->NewGlobalRef(jbArrayBitlenOut);
		  jbArrayBitlenOut = (jbyteArray)jbArrayBitlen2;
		  
		  jbyte alleight =8;
		  jbyte zero =0;
		    
		  for (uint64_t i = 0;i<result_len;i++)  
		  {
			  v = result_v[i];
			  vbitlen = result_bitlen[i];
			  jvBitlen= vbitlen & 0xFF;			

              if ( jvBitlen == 64 )
			  {
				
				    ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+1,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+2,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+3,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+4,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+5,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+6,sizeof(alleight),&alleight);
					((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+7,sizeof(alleight),&alleight);
				  
			  }
			  else
			  {
				  jbyte dec = jvBitlen / 8;
				  jbyte rest = jvBitlen - dec*8;
				  
				  for(int j =0 ;j<dec;j++)
				     ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+j,sizeof(alleight),&alleight);
				 
				 ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+dec,sizeof(rest),&rest);
				 
				 for(int j =dec+1 ;j<8;j++)
				     ((JNIEnv * )env)->SetByteArrayRegion(jbArrayBitlenOut,i+7*i+j,sizeof(zero),&zero);

 			  }

			   jv = v & 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+7+7*i,sizeof(jv),&jv);
			   jv = (v >>8)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+6+7*i,sizeof(jv),&jv);
			   jv = (v >>16)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+5+7*i,sizeof(jv),&jv);
			   jv = (v >>24)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+4+7*i,sizeof(jv),&jv);
			   jv = (v >>32)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+3+7*i,sizeof(jv),&jv);
			   jv = (v >>40)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+2+7*i,sizeof(jv),&jv);
			   jv = (v >>48)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+1+7*i,sizeof(jv),&jv);
			   jv = (v >>56)& 0xFF;
			   ((JNIEnv * )env)->SetByteArrayRegion(jbArrayValuesOut,i+0+7*i,sizeof(jv),&jv);
			  
			  
		  }
		
		  
		((JNIEnv * )env)->SetObjectField(output, fidBitlenOut, jbArrayBitlenOut);
		((JNIEnv * )env)->SetObjectField(output, fidValuesOut, jbArrayValuesOut);
		
  }

 /*
 * Class:     certFHE_certFHEjni
 * Method:    applyPermutationOverKey
 * Signature: (JJJ[J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_certFHE_certFHEjni_applyPermutationOverKey
  (JNIEnv *env, jobject obj, jlong n, jlong d, jlong u, jlongArray permutation, jbyteArray secretkey)
  {
	jbyteArray nArray = ((JNIEnv * )env)->NewByteArray(n);
	
    certFHE::Library::initializeLibrary();   
	
	uint64_t * permutedKeyNative = NULL;
	jlong temp;
	jbyte temp2;
	
	uint64_t * secretKeyNative = new uint64_t [n];
	uint64_t * permutationNative = new uint64_t [n];
	
	for (int w = 0; w< n ;w++)
	{					
		((JNIEnv * )env)->GetLongArrayRegion(permutation,w,1,&temp);  
		permutationNative[w] = (uint64_t) (temp & 0x7FFFFFFFFFFFFFFF);	
		
		((JNIEnv * )env)->GetByteArrayRegion(secretkey,w,1,&temp2);  
		secretKeyNative[w] = (uint64_t) (temp2 & 0x7FFFFFFFFFFFFFFF);	

	}
	
	uint64_t * s = new uint64_t [d];
	uint64_t pos = 0;
	
	for (uint64_t i =0;i<n;i++)
		{
			if (secretKeyNative[i] == 1 )
			{
				s[pos++] = i;
			}
		}
		
	delete [] secretKeyNative;
	
	certFHE::Context ctx(n,d);
	certFHE::Permutation perm(ctx);
	
	perm.setPermutation(permutationNative,n);
	
	delete [] permutationNative;

	certFHE::SecretKey seckey(ctx);
	seckey.setKey(s,d);
	
	delete [] s;
	
	certFHE::SecretKey permkey = seckey.applyPermutation(perm);
	
	uint64_t* native_permuted_key  = permkey.getKey();
	uint64_t * long_permuted_key = new uint64_t [n];
	
	for (int w = 0; w< n ;w++)
	{
		long_permuted_key[w] = 0;
		
	}

	for (int w = 0; w< d ;w++)
	{
		long_permuted_key[native_permuted_key[w]] = 1;
	}
		
	for (int w = 0; w< n ;w++)
	{		
	    jbyte placeV = (jbyte) (long_permuted_key[w] & 0x00000000000000FF );
	
		((JNIEnv * )env)->SetByteArrayRegion(nArray,w,sizeof(placeV),(const jbyte*)&placeV);  		
	}

		
	delete [] long_permuted_key;
		
	
    return nArray;	
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    combinePermutations
 * Signature: (JJJ[J[J)[J
 */
JNIEXPORT jlongArray JNICALL Java_certFHE_certFHEjni_combinePermutations
  (JNIEnv *env, jobject obj, jlong n, jlong d, jlong u, jlongArray permutationA, jlongArray permutationB)
  {
	jlongArray nArray = ((JNIEnv * )env)->NewLongArray(n);
    
	certFHE::Library::initializeLibrary();   
	  
	jlong temp;
	jbyte temp2;
	
	uint64_t * permutationNativeA = new uint64_t [n];
	uint64_t * permutationNativeB = new uint64_t [n];
	for (int w = 0; w< n ;w++)
	{					
		((JNIEnv * )env)->GetLongArrayRegion(permutationA,w,1,&temp);  
		permutationNativeA[w] = (uint64_t) (temp & 0x7FFFFFFFFFFFFFFF);	
		
		((JNIEnv * )env)->GetLongArrayRegion(permutationB,w,1,&temp);  
		permutationNativeB[w] = (uint64_t) (temp & 0x7FFFFFFFFFFFFFFF);	
		
	}
	
	certFHE::Context ctx(n,d);
	certFHE::Permutation permA (ctx);
	certFHE::Permutation permB (ctx);
	certFHE::Permutation permC (ctx);
	
	permA.setPermutation(permutationNativeA,n);
	permB.setPermutation(permutationNativeB,n);
	permC = permA+permB;
	
	uint64_t* p = permC.getPermutation();
		
	
		
	for (int w = 0; w< n ;w++)
	{		
		((JNIEnv * )env)->SetLongArrayRegion(nArray,w,1,(const jlong*)&p[w]);
	}
	
	if ( permutationNativeA != NULL)
			delete [] permutationNativeA;

	if ( permutationNativeB != NULL)
			delete [] permutationNativeB;

	
    return nArray;	
  }

/*
 * Class:     certFHE_certFHEjni
 * Method:    inverseOfPermutation
 * Signature: (JJJ[J)[J
 */
JNIEXPORT jlongArray JNICALL Java_certFHE_certFHEjni_inverseOfPermutation
  (JNIEnv * env, jobject obj, jlong n, jlong d, jlong u, jlongArray permutation)
  {
	jlongArray nArray = ((JNIEnv * )env)->NewLongArray(n);

	certFHE::Library::initializeLibrary();   
	  
	 
	jlong temp;
	jbyte temp2;
	
	uint64_t * permutationNative = new uint64_t [n];
	for (int w = 0; w< n ;w++)
	{					
		((JNIEnv * )env)->GetLongArrayRegion(permutation,w,1,&temp);  
		permutationNative[w] = (uint64_t) (temp & 0x7FFFFFFFFFFFFFFF);	
		
	}

	certFHE::Context ctx(n,d);
	certFHE::Permutation permA(ctx);
	certFHE::Permutation permResult(ctx);
	
	permA.setPermutation(permutationNative,n);
	delete [] permutationNative;
	
	permResult = permA.getInverse();
	
	
	uint64_t* p = permResult.getPermutation();
		
		
	for (int w = 0; w< n ;w++)
	{		
		((JNIEnv * )env)->SetLongArrayRegion(nArray,w,1,(const jlong*)&p[w]);
	}
	 
    return nArray;	
	  
}