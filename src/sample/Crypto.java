package sample;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.util.Base64;
import java.util.Random;
import java.util.Set;


public class Crypto {

    public static final String USER_CERTS = "OpenSSL/Usercerts";
    public static final String ROOT_CA_PATH = "OpenSSL/rootca.pem";
    public static final String CA1_PATH = "OpenSSL/certs/ca1.crt";
    public static final String CA2_PATH = "OpenSSL/certs/ca2.crt";
    //PREPRAVI PRAVE NAZIVE KEYEVA
    public static final String RSA_PRIVATE_KEY1_PATH = "OpenSSL/private/c1.key";
    public static final String RSA_PRIVATE_KEY2_PATH = "OpenSSL/private/c2.key";
    public static final String RSA_PUBLIC_KEY1_PATH = "OpenSSL/private/public-ca1.pem";
    public static final String RSA_PUBLIC_KEY2_PATH = "OpenSSL/private/public-ca2.pem";
    public static final Date NOT_AFTER = Date.valueOf("3000-1-1");
    public static final Date NOT_BEFORE = Date.valueOf("2000-1-1");
    private static final String SERIAL_PATH = "OpenSSL/serial";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    public static int serialNumber = 04;
    public static String DES3 = "DESede/CBC/PKCS5Padding";
    public static final String CA_CERT1_PATH = "OpenSSL/certs/ca1.crt";
    public static final String CA_CERT2_PATH = "OpenSSL/certs/ca2.crt";
    public static final String CRL1_PATH = "OpenSSL/crl/CA1-CRL.crl";
    public static final String CRL2_PATH = "OpenSSL/crl/CA2-CRL.crl";
    public static final String SIGNING_ALGORITHM = "SHA256withRSA";
    public static final String PROVIDER = "BC";


    public static Random rand = new Random();

    public static X509Certificate generateX509Certificate(String name, String password) throws Exception{
        if(User.registeredUsersList.isEmpty()){
            serialNumber = 04;
        }else{
            serialNumber = User.registeredUsersList.get(User.numberOfRegistered-1).serialNumber;
        }
        System.out.println("aa");
        String userCertificatePath = USER_CERTS + File.separator + name + ".p12";
        X509Certificate caCert = null;
        KeyPair caKey;
        X509Certificate rootCaCert = readX509Certificate(ROOT_CA_PATH);
        if(rand.nextBoolean()){
            caCert = readX509Certificate(CA1_PATH);
            caKey = getKeyPair(1);
            //bool = false;
        }else{
            caCert = readX509Certificate(CA2_PATH);
            caKey = getKeyPair(2);
            //bool = true;
        }
        //GENERISANJE PARA KLJUCEVA ZA KORISNIKA KOJEM SE IZDAJE SERTIFIKAT
        X500Name owner = new X500Name("CN=" + name);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA","BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //Kreiranje samog zahtjeva,dodavanje ekstenzija
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(caCert,
                BigInteger.valueOf(serialNumber), NOT_BEFORE, NOT_AFTER, owner, keyPair.getPublic());

        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        //Potpisivanje zahtjeva od strane CA tijela
        X509Certificate userCertificate = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKey.getPrivate())));
        writeSerialNumber(serialNumber);
        serialNumber++;
        saveX509CertificateToKeyStore(userCertificate,name,userCertificatePath,password,rootCaCert,caCert,keyPair);
        return userCertificate;

    }

    public static X509Certificate readX509Certificate(String certificatePath) throws Exception {
        FileInputStream fis = new FileInputStream(new File(certificatePath));

        try{
            System.out.println(certificatePath);
            CertificateFactory serverfc = CertificateFactory.getInstance("X.509");
            return (X509Certificate) serverfc.generateCertificate(fis);
        }catch (CertificateException e){
            //System.out.println("greska");
            throw new RuntimeException(e);
        }finally {
            fis.close();
        }
    }

    public static KeyPair getKeyPair(int number) throws Exception{
        if(number == 1){
            return new KeyPair(readRSAPublicFromFile(RSA_PUBLIC_KEY1_PATH), readRSAPrivateFromFile(RSA_PRIVATE_KEY1_PATH));
        } else {
            return new KeyPair(readRSAPublicFromFile(RSA_PUBLIC_KEY2_PATH), readRSAPrivateFromFile(RSA_PRIVATE_KEY2_PATH));
        }
    }

    public static PrivateKey readRSAPrivateFromFile(String filename) throws Exception {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(filename)));
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
        return privKey;
    }

    public static PublicKey readRSAPublicFromFile(String filename) throws Exception {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(filename)));
        privateKeyContent = privateKeyContent.replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        // PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    public static void writeSerialNumber(Integer serial){
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(SERIAL_PATH));
            writer.write(serial.toString());
            writer.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static String saveX509CertificateToKeyStore(X509Certificate certificate, String username, String path, String password, X509Certificate root, X509Certificate caCertificate, KeyPair userKey)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        X509Certificate[] chain = {certificate, caCertificate, root};
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        FileOutputStream fos = null;
        try {
             fos = new FileOutputStream(path);
        }catch (IOException e){
            e.printStackTrace();
        }
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry(username,userKey.getPrivate(), password.toCharArray(), chain);
        keyStore.store(fos,password.toCharArray());
        fos.flush();
        fos.close();
        return path;
    }

    public static X509Certificate getX509CertificateFromKeyStore(String username, String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        String path = USER_CERTS + File.separator + username + ".p12";
        FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis,password.toCharArray());
        X509Certificate userCertificate = (X509Certificate)keyStore.getCertificate(username);
        return userCertificate;
    }

    public static void revokeCertificate(X509Certificate certificate) throws Exception {
        String crlPath = null;
        String issuer = certificate.getIssuerX500Principal().getName();
        X509Certificate caCertificate = null;
        KeyPair caKeyPair = null;
        X509CRL crl = null;
        String[] name = issuer.split(",");
        //System.out.println(issuer);
        if("CN=CA1 tijelo".equals(name[1])){
            caKeyPair = getKeyPair(1);
            caCertificate = readX509Certificate(CA_CERT1_PATH);
            crl = loadCRL(CRL1_PATH);
            crlPath = CRL1_PATH;
        } else {
            caKeyPair = getKeyPair(2);
            caCertificate = readX509Certificate(CA_CERT2_PATH);
            crl = loadCRL(CRL2_PATH);
            crlPath = CRL2_PATH;
        }
        String[] string = caCertificate.getSubjectX500Principal().getName().split(",");
        X500Name subject = new X500Name(string[1]);
        System.out.println(subject);
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(subject, new java.util.Date());
        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 86400 * 1000));

        Set<X509CRLEntry> revokedCerts = (Set<X509CRLEntry>) crl.getRevokedCertificates();
        if(revokedCerts != null){
            for(X509CRLEntry cert : revokedCerts) {
                crlBuilder.addCRLEntry(cert.getSerialNumber(), new java.util.Date(), 5);
            }
        }
        crlBuilder.addCRLEntry(certificate.getSerialNumber(), new java.util.Date(), 5);
        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SIGNING_ALGORITHM);
        jcaContentSignerBuilder.setProvider(PROVIDER);
        X509CRLHolder crlHolder = crlBuilder.build(jcaContentSignerBuilder.build(caKeyPair.getPrivate()));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(PROVIDER);
        crl = converter.getCRL(crlHolder);
        saveCRL(crl,crlPath);
    }

    public static X509CRL loadCRL(String path){
        X509CRL crl = null;
        try{
            FileInputStream fis = new FileInputStream(path);
            org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory certificateFactory = new org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory();
            crl = (X509CRL) certificateFactory.engineGenerateCRL(fis);
            fis.close();
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return crl;
    }

    public static void saveCRL(X509CRL crl, String path){
        try{
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(crl.getEncoded());
            //System.out.println("AA");
            fos.flush();
            fos.close();
        } catch(IOException | CRLException ex){
            ex.printStackTrace();
        }
    }

    public static void createCRL() throws Exception {
        //generisanje prve crl liste
        X509Certificate ca1 = readX509Certificate(CA_CERT1_PATH);
        KeyPair ca1KeyPair = getKeyPair(1);
        X500Name caName = new X500Name(ca1.getSubjectDN().getName());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caName, new java.util.Date());
        crlBuilder.setNextUpdate(NOT_AFTER);
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGNING_ALGORITHM);
        contentSignerBuilder.setProvider(PROVIDER);
        X509CRLHolder crlHolder = crlBuilder.build(contentSignerBuilder.build(ca1KeyPair.getPrivate()));
        JcaX509CRLConverter crlConverter = new JcaX509CRLConverter();
        crlConverter.setProvider(PROVIDER);
        X509CRL crl1 = crlConverter.getCRL(crlHolder);
        saveCRL(crl1,CRL1_PATH);
        //generisanje druge crl liste
        X509Certificate ca2 = readX509Certificate(CA_CERT2_PATH);
        KeyPair ca2KeyPair = getKeyPair(2);
        X500Name ca2Name = new X500Name(ca2.getSubjectDN().getName());
        X509v2CRLBuilder crl2Builder = new X509v2CRLBuilder(ca2Name, new java.util.Date());
        crl2Builder.setNextUpdate(NOT_AFTER);
        X509CRLHolder crl2Holder = crlBuilder.build(contentSignerBuilder.build(ca2KeyPair.getPrivate()));
        JcaX509CRLConverter crl2Converter = new JcaX509CRLConverter();
        crl2Converter.setProvider(PROVIDER);
        X509CRL crl2 = crl2Converter.getCRL(crl2Holder);
        saveCRL(crl2,CRL2_PATH);
    }

    public static byte[] symmetricEncryption(byte[] input, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] output = null;
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        output = cipher.doFinal(input);
        return output;
    }

    public static byte[] symmetricDecryption(byte[] input, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] output = null;
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        output = cipher.doFinal(input);
        return output;
    }

    public static byte[] encryptRSA(SecretKey secretKey, KeyPair keyPair) throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA",PROVIDER);
        cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
        byte[] encryptedData = cipher.wrap(secretKey);
        return encryptedData;
    }

    public static SecretKey decryptRSA(byte[] data, KeyPair keyPair) throws IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA",PROVIDER);
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
        SecretKey key =  (SecretKey) cipher.unwrap(data,"AES",Cipher.SECRET_KEY);
        return key;
    }

    public static byte[] getKeyFromFile(String path) {
        try {
            FileInputStream in = new FileInputStream(path);
            byte[] keyBytes = in.readAllBytes();
            return keyBytes;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static boolean isRevokedCertificate(X509Certificate certificate){
        X509CRL list1 = loadCRL(CRL1_PATH);
        X509CRL list2 = loadCRL(CRL2_PATH);
        X509CRLEntry revokedCertificateCRL1 = list1.getRevokedCertificate(certificate.getSerialNumber());
        X509CRLEntry revokedCertificateCRL2 = list2.getRevokedCertificate(certificate.getSerialNumber());
        if(revokedCertificateCRL1 != null || revokedCertificateCRL2 != null){
            return true;
        } else {
            return false;
        }
    }


   /* public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator kg = KeyGenerator.getInstance("AES",PROVIDER);
        SecretKey key = kg.generateKey();
        byte[] bytes = encryptRSA(key,getKeyPair(1));
        try(FileOutputStream fos = new FileOutputStream("aes.key")){
            fos.write(bytes);
        }

    }*/


}
