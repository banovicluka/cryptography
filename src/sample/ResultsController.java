package sample;

import javafx.scene.control.TextArea;

public class ResultsController {

    public void initialize(){
        text.setText(User.getAllResults());
    }

    public TextArea text;

}
