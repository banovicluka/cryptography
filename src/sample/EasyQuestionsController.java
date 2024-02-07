package sample;

import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import sample.Question;
import sample.Quiz;
import sample.SuggestedAnswersQuestion;
import sample.User;

import java.io.IOException;

public class EasyQuestionsController {

    public Button nextButton;
    public CheckBox answerOne;
    public CheckBox answerTwo;
    public CheckBox answerThree;
    public CheckBox answerFour;
    public Label questionLabel;

    public void initialize(){
        Question q = Quiz.randomQuestions.get(Quiz.questionNumber);
        answerOne.setText(((SuggestedAnswersQuestion) q).suggestedAnswers.get(0));
        answerTwo.setText(((SuggestedAnswersQuestion) q).suggestedAnswers.get(1));
        answerThree.setText(((SuggestedAnswersQuestion) q).suggestedAnswers.get(2));
        answerFour.setText(((SuggestedAnswersQuestion) q).suggestedAnswers.get(3));
        questionLabel.setText(q.question);
    }

    public void nextButtonClicked(MouseEvent mouseEvent) throws IOException {
        SuggestedAnswersQuestion sq = (SuggestedAnswersQuestion) Quiz.randomQuestions.get(Quiz.questionNumber - 1);
        int correctAnswer = sq.whichAnswerIsCorrect();
        if(correctAnswer == 0){
            if(answerOne.isSelected() && !answerTwo.isSelected() && !answerThree.isSelected() && !answerFour.isSelected()){
                User.loggedUser.score++;
            }
        }else if(correctAnswer == 1){
            if(!answerOne.isSelected() && answerTwo.isSelected() && !answerThree.isSelected() && !answerFour.isSelected()){
                User.loggedUser.score++;
            }
        }else if(correctAnswer == 2){
            if(!answerOne.isSelected() && !answerTwo.isSelected() && answerThree.isSelected() && !answerFour.isSelected()){
                User.loggedUser.score++;
            }
        }else if(correctAnswer == 3){
            if(!answerOne.isSelected() && !answerTwo.isSelected() && !answerThree.isSelected() && answerFour.isSelected()){
                User.loggedUser.score++;
            }
        }else{
            System.out.println("Greska");
        }
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
            //System.out.println(User.loggedUser.score);
        }else{
            User.writeResults(User.loggedUser);
            Stage endStage = (Stage) ((Node) mouseEvent.getSource()).getScene().getWindow();
            Parent endScene = FXMLLoader.load(getClass().getResource("resources/quiz-end-view.fxml"));
            endStage.setScene(new Scene(endScene));
            endStage.show();
        }

    }
}
