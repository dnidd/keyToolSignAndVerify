import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * Handling the Key Store with its keys/certificate
 * Read/write files and extract data and keys from key store and files.
 */
public class KeyStoreHandler {

    KeyStore keyStore;

    /**
     * Fetch Key Store from file.
     * @param keystoreName = Key Store name.
     * @param storepass = Key Store password
     * @return Key Store.
     * @throws KeyStoreException e.
     * @throws IOException e.
     * @throws CertificateException e.
     * @throws NoSuchAlgorithmException e.
     */
    public KeyStore getKeyStore(String keystoreName, String storepass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance("JKS");

        try (BufferedInputStream buffIn = new BufferedInputStream(new FileInputStream(keystoreName)) ) {
            // load used to opening existing key store.
            keyStore.load(buffIn, storepass.toCharArray());
        }
        return keyStore;
    }


    /**
     * Fetch private key from key store.
     * @param keyStore = Key store.
     * @param alias = alias.
     * @param keypass = private key password.
     * @return private key.
     * @throws KeyStoreException e.
     * @throws NoSuchAlgorithmException e.
     */
    public PrivateKey getPrivateKey(KeyStore keyStore, String alias, String keypass) throws KeyStoreException, NoSuchAlgorithmException {
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, keypass.toCharArray());
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
        return privateKey;
    }


    /**
     * Generate signate with private key.
     * @param privateKey = PrivateKey.
     * @return Signature.
     */
    public Signature generateSignature(PrivateKey privateKey) {

        try {
            // Initialize Signature object with private key.
            Signature signature = Signature.getInstance("SHA256withDSA");
            signature.initSign(privateKey);

            return signature;

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Sign data in file 'data'.
     * @param data = file of data.
     * @param signature = Signature with private key.
     * @return signed data.
     * @throws SignatureException e.
     */
    public byte[] signData(String data, Signature signature) throws SignatureException {

        // Read data to be signed.
        try (BufferedInputStream buffIn = new BufferedInputStream( new FileInputStream(data) )) {
            byte[] buffer = new byte[1024];
            int len;
            // Sign data.
            while( (len = buffIn.read(buffer)) >= 0 ) {
                signature.update(buffer, 0, len);
            };
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] sign = signature.sign();

        return sign;
    }


    /**
     * Fetch (public key) certificate from key store.
     * @param keyStore = Key store.
     * @param alias = alias.
     * @return encoded certificate.
     */
    public byte[] getCertificate(KeyStore keyStore, String alias) {
        byte[] encodedCert = null;
        java.security.cert.Certificate certificate = null;

        try {
            certificate = keyStore.getCertificate(alias);
            encodedCert = certificate.getEncoded();
        } catch (KeyStoreException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        return encodedCert;
    }


    /**
     * Write certificate to file 'certificate'.
     * @param certificate = file to be created.
     * @param encodedCertificate = certificate data to be written to file.
     */
    public void writeCertificateToFile(String certificate, byte[] encodedCertificate) {
        try (FileOutputStream out = new FileOutputStream(certificate)) {
            out.write(encodedCertificate);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Write signature/signed data to file 'signature'.
     * @param signature = file to be created.
     * @param signatureData = content data to be written to file.
     */
    public void writeSignatureToFile(String signature, byte[] signatureData) {
        try (FileOutputStream out = new FileOutputStream(signature)) {
            out.write(signatureData);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Extracts public key from certificate in key store.
     * @param certificate = certificate in key store.
     * @return Public key.
     */
    public PublicKey extractPublicKeyFromCertificate(String certificate) {
        PublicKey publicKey = null;

        try {
            FileInputStream certInputStream = new FileInputStream(certificate);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(certInputStream);
            publicKey = cert.getPublicKey();
        } catch (FileNotFoundException | CertificateException e) {
            throw new RuntimeException(e);
        }
        return publicKey;
    }


    /**
     * Read signature from file.
     * @param signature = file containing signature.
     * @return signature byte[].
     */
    public byte[] readSignatureFromFile(String signature) {
        byte[] signatureBytes;
        try (FileInputStream instream = new FileInputStream(signature)) {
            signatureBytes = instream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return signatureBytes;
    }


    /**
     * VVerify the content in 'data' with the certificate/public key and the signature.
     * A boolean verifies and prints weather verified or not.
     * @param publicKey = PublicKey.
     * @param data = file containing signed data.
     * @param signatureBytes = signature in byte[].
     * @throws InvalidKeyException e.
     * @throws NoSuchAlgorithmException e.
     * @throws IOException e.
     * @throws SignatureException e.
     */
    public void verifyContent( PublicKey publicKey, String data, byte[] signatureBytes) throws InvalidKeyException, NoSuchAlgorithmException, IOException, SignatureException {

        // Initialize Signature object with public key.
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(publicKey);

        // Read file containing data.
        byte[] dataBytes;
        try (FileInputStream instream = new FileInputStream(data)){
            dataBytes = instream.readAllBytes();
        }

        // Supply the Signature Object With the Data to be Verified.
        signature.update(dataBytes);

        // Verity the signature.
        boolean verifies = signature.verify(signatureBytes);

        System.out.println("Verifies: " + verifies);
    }



}
