package sample;

import sample.Question;

import java.util.ArrayList;

public class SuggestedAnswersQuestion extends Question {

    public ArrayList<String> suggestedAnswers = new ArrayList<String>();


    public SuggestedAnswersQuestion(String question, String correctAnswer, String answer1, String answer2,
                                    String answer3, String answer4) {
        super(question, correctAnswer);
        suggestedAnswers.add(answer1);
        suggestedAnswers.add(answer2);
        suggestedAnswers.add(answer3);
        suggestedAnswers.add(answer4);

    }

    public int whichAnswerIsCorrect(){
        for(String answer: suggestedAnswers){
            if(answer.equals(this.answer)){
                return suggestedAnswers.indexOf(answer);
            }
        }
        return -1;
    }
}
