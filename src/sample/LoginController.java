package sample;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import sample.User;

import java.io.*;
import java.util.ArrayList;

public class LoginController {


    public Button registrationButton;
    public Button loginButton;
    public Label startTitle;
    public PasswordField passwordField;
    public TextField usernameField;
    public Label infoText;
    public Button confirmButton;

    public void initialize(){
        try {
            FileInputStream fis = new FileInputStream("korisnici.ser");
            ObjectInputStream oos = new ObjectInputStream(fis);
            User.registeredUsersList = (ArrayList<User>) oos.readObject();
            User.numberOfRegistered = User.registeredUsersList.size();
        }catch (IOException e){
            System.out.println("Prva inicijalizacija");
        }catch (ClassNotFoundException e){
            System.out.println("Pogresno kastovanje.");
        }
    }

    public void registrationButtonClicked(MouseEvent mouseEvent) {
        startTitle.setText("Registracija na kviz");
        infoText.setText("");
    }

    public void loginButtonClicked(MouseEvent mouseEvent) {
        startTitle.setText("Prijava na kviz");
        infoText.setText("");
    }

    public void confirmButtonClicked(MouseEvent mouseEvent) throws Exception {
        if(startTitle.getText().equals("Prijava na kviz")){
            if(!usernameField.getText().equals("") && !passwordField.getText().equals("")){
                if(User.login(usernameField.getText(),passwordField.getText())){
                    Stage stage = new Stage();
                    stage.setTitle("Dobrodosli!");
                    FXMLLoader loader = new FXMLLoader(getClass().getResource( "resources/start-quiz-view.fxml"));
                    Parent welcome = loader.load();
                    stage.setScene(new Scene(welcome));
                    Stage closingStage = (Stage) confirmButton.getScene().getWindow();
                    closingStage.close();
                    stage.show();
                }
                else{
                   infoText.setText("Prijava nije uspjesna.");
                }
            }else{
                infoText.setText("Prijava nije uspjesna. Popunite sva polja da bi se prijavili.");
            }
        }else{
            if(!usernameField.getText().equals("") && !passwordField.getText().equals("")){
                if(User.register(usernameField.getText(),passwordField.getText())){
                    infoText.setText("Uspjesno ste se registrovali! Vas sertifikat se nalazi na sledecoj putanji:  " +
                            User.registeredUsersList.get(User.numberOfRegistered-1).certificatePath);
                }else{
                    infoText.setText("Registracija nije uspjesna. Birani username vec postoji.");
                }
            }else{
                infoText.setText("Registracija nije uspjesna. Popunite sva polja da bi ste se registrovali.");
            }
        }
    }
}
