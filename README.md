### JDK Security API
Sign and verify an arbitrary file.
JDK keytool is used to create a key store holding a private key and certificate (including public key).
The public key is extracted from the certificate.

1. Integrity - check that data has not been tampered with.
   If data has been tampered with, varification fails (VerifyHandler.java). 
2. Authenticity - Check that signature/data is sent from correct/expected user with the private key.

A key store is created using the JDK keytool.<br>

🟢 ```keytool -genkeypair -alias alias -keyalg DSA -keysize 1024 -sigalg SHA256withDSA -keypass key_password -keystore keystore -storetype JKS -storepass keystore_password```

The project contains the following two applications to run in CLI/terminal:<br>
- ```java SignHandler <keystore> <keystore_password> <alias> <key_password> <data> <certificate> <signature>```
signing the file ```<data>``` with (the private) key stored in ```<keystore>``` under the name ```<alias>```.
It saves a certificate (holding the public key) in the file ```<certificate>``` and saves the signature in the file
```<signature>``` (the sender can then send the files ```<data>, <signature>``` and ```<certificate>```
to the receiver to be verified).
- ```java VerifyHandler <data> <certificate> <signature>``` is verifying if the certificate (with the public key)
in the file ```<certificate>``` and the signature in the file ```<signature>``` verifies the file ```<data>```.

## Compile
from root:
javac src/*.java

inside where .java-files exist (/src):
javac *.java


### <u>Execute from src:</u>
Files created/existing in src.

````java KeyHandler privateKey publicKey````<br>
````java SignHandler data privateKey signature````<br>
````java VerifyHandler data publicKey signature````


### Info:
<b>privateKey, publicKey:</b> name of key files in which keys will be stored.<br>
<b>data:</b> existing file containing text to be signed.<br>
<b>signature:</b> name of the file holding the private key signed data from the file 'data'.<br>


### The keytool Command:
- https://www.youtube.com/watch?v=NH49dTEYPg0&list=PLuZW3dtq0_O57xCJ5LwEq30Bl_URhv5mH&index=2<br>
Docs:<br>
- https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html<br>
- https://docs.oracle.com/en/java/javase/25/docs/specs/man/keytool.html<br>
- https://community.cirata.com/s/article/keytool-Key-and-Certificate-Management-Tool<br>


#### <span style="color:lightgreen">Generate keypair example:</span>
```java SignHandler <keystore> <keystore_password> <alias> <key_password> <data> <certificate> <signature>```

🔴 Trying to create PKCS12 key store. Getting the notice that PKCS12 do not support different passwords for store and key.
Since  ```<keystore_password>``` and ```<key_password>``` is demanded, another store type needs to be tested.<br>
```keytool -genkeypair -alias alias -keyalg DSA -keysize 1024 -sigalg SHA256withDSA -keypass key_password -keystore keystore.p12 -storetype PKCS12 -storepass keystore_password```



#### JKS key store (deprecated/not secure enough)
🟢 ```keytool -genkeypair -alias alias -keyalg DSA -keysize 1024 -sigalg SHA256withDSA -keypass key_password -keystore keystore -storetype JKS -storepass keystore_password```
<br><b>Response:</b>
Warning:
It generated: certifikatet uses a 1024-bitars DSA-nyckel which is considered a security risk. This key size will be disabled in a future update.
Nyckellagret JKS använder ett proprietärt format. Du bör migrera till PKCS12, som är ett branschstandardformat, med "keytool -importkeystore -srckeystore keystore.jks -destkeystore keystore.jks -deststoretype pkcs12".


#### Inspect key store:
keytool -list -keystore keystore

storepass: keystore_password

#### Java KeyStore:
https://www.youtube.com/watch?v=NH49dTEYPg0&list=PLuZW3dtq0_O57xCJ5LwEq30Bl_URhv5mH&index=2<br><br>
Docs:<br>
https://docs.oracle.com/en/java/javase/26/docs/api/java.base/java/security/KeyStore.html<br><br>
https://docs.oracle.com/javase/8/docs/api/java/security/KeyStore.html<br><br>
The process:<br>
<i>https://docs.oracle.com/javase/tutorial/security/apisign/enhancements.html</i>
