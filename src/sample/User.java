package sample;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.util.ArrayList;

public class User implements Serializable {

    public static User loggedUser;
    public static ArrayList<User> registeredUsersList = new ArrayList<>();
    public static int numberOfRegistered = 0;

    public String username;
    public String password;
    public int score;
    public int numberOfLogins;
    public String certificatePath;
    public int serialNumber;

    public static final String RESULT_PATH = "results.txt";

    public User(){

    }

    public User(String username, String password,String certificatePath){
        this.username = username;
        this.password = password;
        this.certificatePath = certificatePath;
        score = 0;
        numberOfLogins = 0;
        serialNumber = Crypto.serialNumber;
    }

    public static boolean checkIfUsernameExist(String username) {
        for (User u : registeredUsersList) {
            if (u.username.equals(username)) {
                return true;
            }
        }
        return false;
    }

    public static boolean register(String username,String password) throws Exception {
        if(!checkIfUsernameExist(username)){
            try {
                Crypto.generateX509Certificate(username, password);
            }catch(Exception e){
                throw new RuntimeException();
            }
            File file = null;
            try{
                file = new File("OpenSSL" + File.separator + "Usercerts" + File.separator + username + ".p12");
            }catch (Exception e){
                throw new Exception();
            }
            registeredUsersList.add(new User(username, password, file.getAbsolutePath() ));
            numberOfRegistered++;
            FileOutputStream fos = new FileOutputStream("korisnici.ser");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(registeredUsersList);
            oos.flush();
            oos.close();
            return true;
        }
        return false;
    }

    public static boolean login(String username, String password) throws IOException {
        for (User user : registeredUsersList){
            if(user.username.equals(username) && user.password.equals(password)){
                loggedUser = user;
                loggedUser.numberOfLogins++;
                Quiz.questionNumber = 0;
                loggedUser.score = 0;
                System.out.println(loggedUser.numberOfLogins);
                if(loggedUser.numberOfLogins > 3){
                    try {
                        X509Certificate userCertificate = Crypto.getX509CertificateFromKeyStore(username,password);
                        if(!Crypto.isRevokedCertificate(userCertificate)) {
                            Crypto.revokeCertificate(userCertificate);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    //kada se povuce sertifikat
                    //sta ako ne postoji korisnik sa tim username i pass
                }
                FileOutputStream fos = new FileOutputStream("korisnici.ser");
                ObjectOutputStream oos = new ObjectOutputStream(fos);
                oos.writeObject(registeredUsersList);
                oos.flush();
                oos.close();
                return true;
            }
        }
        return false;
    }

    public static void writeResults(User user)  {
        try {
            SecretKey key = Crypto.decryptRSA(Crypto.getKeyFromFile("aes.key"),Crypto.getKeyPair(1));
            byte[] data = readResults();
            String allResults = new String(Crypto.symmetricDecryption(data,key));
            allResults += user.username + " - " + LocalTime.now().toString() + " - " + user.score + "\n";
            //System.out.println(allResults);
            byte[] encryptedData = Crypto.symmetricEncryption(allResults.getBytes(StandardCharsets.UTF_8),key);
            FileOutputStream os = new FileOutputStream(RESULT_PATH);
            os.write(encryptedData);
            os.flush();
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] readResults(){
        try{
            FileInputStream fis = new FileInputStream(RESULT_PATH);
            byte[] allBytes = fis.readAllBytes();
            fis.close();
            return allBytes;
        } catch (Exception ex){
            ex.printStackTrace();
        }
        return null;
    }

    public static String getAllResults(){
        try {
            SecretKey key = Crypto.decryptRSA(Crypto.getKeyFromFile("aes.key"),Crypto.getKeyPair(1));
            byte[] data = readResults();
            String allResults = new String(Crypto.symmetricDecryption(data,key));
            return allResults;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }

}
