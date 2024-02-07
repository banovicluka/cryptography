package sample;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.Stage;

import java.io.IOException;

public class QuizEndController {

    public Label scoreLabel;
    public Button logoutButton;

    public void initialize(){
        scoreLabel.setText(String.valueOf(User.loggedUser.score));
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

    public void resultsButtonClicked(ActionEvent actionEvent) throws IOException {
        Stage stage = new Stage();
        Parent root = FXMLLoader.load(getClass().getResource("resources/results-view.fxml"));
        stage.setTitle("Rezultati");
        stage.setScene(new Scene(root));
        stage.show();
    }
}
