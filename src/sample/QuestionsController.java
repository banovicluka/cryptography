package sample;

import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import sample.Question;
import sample.Quiz;
import sample.SuggestedAnswersQuestion;
import sample.User;

import java.io.IOException;

public class QuestionsController {

    public Button nextButton;
    public Label questionLabel;
    public TextField answerField;

    public void initialize(){
        Question q = Quiz.randomQuestions.get(Quiz.questionNumber);
        questionLabel.setText(q.question);
    }



    public void nextButtonClicked(MouseEvent mouseEvent) throws IOException {
        Question pq = Quiz.randomQuestions.get(Quiz.questionNumber-1);
        if(pq.answer.equals(answerField.getText()))
            User.loggedUser.score++;
        if(Quiz.questionNumber<5) {
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
        }else{
            User.writeResults(User.loggedUser);
            Stage endStage = (Stage) ((Node) mouseEvent.getSource()).getScene().getWindow();
            Parent endScene = FXMLLoader.load(getClass().getResource("resources/quiz-end-view.fxml"));
            endStage.setScene(new Scene(endScene));
            endStage.show();
        }
    }
}
