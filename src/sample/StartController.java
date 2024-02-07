package sample;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import sample.Question;
import sample.Quiz;
import sample.SuggestedAnswersQuestion;

import javax.swing.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.Set;

public class StartController {
    public Button startQuizButton;
    public Label infoLabel;
    public Button addCertificateButton;

    public boolean start = false;
    public Button logoutButton;

    public void initialize(){
        X509CRL crl1;
        crl1 = Crypto.loadCRL(Crypto.CRL1_PATH);
        crl1.getRevokedCertificates();
        Set<X509CRLEntry> revokedCerts = (Set<X509CRLEntry>) crl1.getRevokedCertificates();
        if(revokedCerts != null) {
            for (X509CRLEntry cert : revokedCerts) {
                System.out.println(cert);
            }
        }else{
            System.out.println("Nema ih");
        }
        System.out.println("---------------------------------");
        X509CRL crl2;
        crl2 = Crypto.loadCRL(Crypto.CRL2_PATH);
        crl2.getRevokedCertificates();
        Set<X509CRLEntry> revokedCerts2 = (Set<X509CRLEntry>) crl2.getRevokedCertificates();
        if(revokedCerts2 != null) {
            for (X509CRLEntry cert : revokedCerts2) {
                System.out.println(cert);
            }
        }else{
            System.out.println("Nema ih");
        }
    }

    public void startQuizButtonClicked(MouseEvent mouseEvent) throws IOException {
        if(start == true) {
            //Quiz.getAllQuestions();
            Quiz.getRandomQuestions();
            Question q = Quiz.randomQuestions.get(Quiz.questionNumber);
            if (q instanceof SuggestedAnswersQuestion) {
                Stage questionStage = (Stage) ((Node) mouseEvent.getSource()).getScene().getWindow();
                Parent question = FXMLLoader.load(getClass().getResource("resources/question-answers-view.fxml"));
                questionStage.setScene(new Scene(question));
                questionStage.show();
            } else {
                Stage questionStage = (Stage) ((Node) mouseEvent.getSource()).getScene().getWindow();
                Parent question = FXMLLoader.load(getClass().getResource("resources/question-view.fxml"));
                questionStage.setScene(new Scene(question));
                questionStage.show();

            }
            Quiz.questionNumber++;
        }
    }

    public void addCertificateButtonClicked(ActionEvent actionEvent) throws Exception {
        final JFrame frame = new JFrame("Centered");
        JFileChooser jf = new JFileChooser(Crypto.USER_CERTS);
        jf.showOpenDialog(frame);
        if(jf.getSelectedFile() != null) {
            //System.out.println(jf.getSelectedFile().getAbsolutePath());
            //System.out.println(User.loggedUser.certificatePath);
            if (jf.getSelectedFile().getAbsolutePath().equals(User.loggedUser.certificatePath)) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                FileInputStream fis = null;
                try {
                    fis = new FileInputStream(jf.getSelectedFile());
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }
                keyStore.load(fis, User.loggedUser.password.toCharArray());
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(User.loggedUser.username);
                try {
                    cert.checkValidity();
                    if (!Crypto.isRevokedCertificate(cert)) {
                        infoLabel.setText("Uspjesno ste predali svoj sertifikat. Mozete zapoceti kviz.");
                        start = true;
                    } else {
                        infoLabel.setText("Vas sertifikat je povucen iz upotrebe.");
                    }
                } catch (CertificateExpiredException ex) {
                    infoLabel.setText("Vas sertifikat je istekao. ");
                } catch (CertificateNotYetValidException ex) {
                    infoLabel.setText("Vas sertifikat jos uvije nije validan.");
                }

            } else {
                infoLabel.setText("Niste predali odgovarajuci sertifikat. Pokusajte ponovo.");
                start = false;
            }
        }
    }

    public void logoutButtonClicked(ActionEvent actionEvent) throws IOException {
        Stage oldStage = (Stage)((Node)actionEvent.getSource()).getScene().getWindow();
        oldStage.close();
        Stage primaryStage = new Stage();
        Parent root = FXMLLoader.load(getClass().getResource("resources/login-view.fxml"));
        primaryStage.setTitle("Hello World");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();
    }
}
