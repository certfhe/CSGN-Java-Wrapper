# CSGN library - JAVA wrapper

CSGN is a [homomorphic encryption (FHE)](https://en.wikipedia.org/wiki/Homomorphic_encryption) library that implements the scheme presented [here](https://certfhewiki.certsign.ro/wiki/CertSGN).

The library is a wrapper over the C++ [implementation](https://github.com/certfhe/CSGN).


## Building CSGN java wrapper

### Windows

To setup the JNI inteface for java:

1. open certFHE-java project in eclipse
2. any changes should be done if needed
3. generate headers for jni with generate_header.bat script (make sure the path to javac is set, default location on Windows is C:\Program Files\Java\jdk_version\bin)
4. you will have "certFHE_certFHEjni.h" and "certFHEjni.class" files generated
5. copy "certFHE_certFHEjni.h" in certFHE-java-jni-wrapper folder
6. make sure you have installed cygwin64/MinGW with x86_64-w64-mingw32-g++.exe installed 
7. set JAVA_HOME path to C:\Program Files\Java\jdk_version
9. run in terminal "git submodule init" and "git submodule update" in order to bring the certFHE repo
8. run compile.bat to compile the c sources 
9. copy the output (certFHEjni.dll) in  system path (or in System32/SysWOW64 or in a specific folder)
10. go back to eclipse and test it with certFHEjni class

More details about JNI interface [here](https://www3.ntu.edu.sg/home/ehchua/programming/java/JavaNativeInterface.html).
# License

This software is distributed under a proprietary license. If you have any question, please contact us at certfhe@certsign.ro.