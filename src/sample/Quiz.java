package sample;

import java.io.File;
import java.util.ArrayList;
import java.util.Random;

public class Quiz {

    public static ArrayList<Question> allQuestions = new ArrayList<>();
    public static ArrayList<Question> randomQuestions = new ArrayList<>();
    public static int questionNumber;
    public static Random rand = new Random();

    public static void getAllQuestions() {
        for (int i=1;i<21;i++){
            String string = Steganography.decode(new File( i + "_stego.bmp"));
            String[] params = string.split("#");
            if( params.length > 2){
                //System.out.println(params[0]);
               // System.out.println(params[1]);
                SuggestedAnswersQuestion question = new SuggestedAnswersQuestion(params[0],params[5],params[1],params[2],
                        params[3],params[4]);
                Quiz.allQuestions.add(question);
            }else {
               // System.out.println(params[0]);
                //System.out.println(params[1]);
                Question question = new Question(params[0],params[1]);
                Quiz.allQuestions.add(question);
            }
        }
    }

    public static void getRandomQuestions(){
        randomQuestions.clear();
        int i=0, j=0;
        ArrayList<Integer> randNums = new ArrayList<>();
        while(i<5){
            int number = rand.nextInt(20);
            //System.out.println(number);
            for(Integer num: randNums){
                if(num == number)
                    j++;
            }
            if(j==0){
                randNums.add(number);
                i++;
            }
            j=0;
        }
        for(int y = 0 ; y<5;y++)
            randomQuestions.add(allQuestions.get(randNums.get(y)));
    }

}
