package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.security.Security;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        Parent root = FXMLLoader.load(getClass().getResource("resources/login-view.fxml"));
        primaryStage.setTitle("Hello World");
        primaryStage.setScene(new Scene(root));
        Quiz.getAllQuestions();
        //Crypto.createCRL();
        Steganography.encode(new File("1.bmp"), "Za koji sport je vezan Tour de France?#Biciklizam");
        Steganography.encode(new File("2.bmp"), "Gdje trenutno nastupa Robert Lewandowski?#" +
                "Barcelona#Bayern#Valencia#Manchester City#Barcelona");
        Steganography.encode(new File("3.bmp"), "Koji igrac je dio najskupljeg transfera u istoriji Fudbala?#Mbappe");
        Steganography.encode(new File("4.bmp"), "Koja je najtrofejnija kosarkaska reprezentacija na Olimpijskim igrama?#SAD");
        Steganography.encode(new File("5.png"), "Gdje su odrzane prve Olimpijske igre?#Italija#Grcka#Egipat#Kina#Grcka");
        Steganography.encode(new File("6.png"), "Kako se preziva najbrzi atleticar na 100m?#Bolt");
        Steganography.encode(new File("7.png"), "Koji od navedenih sportova zahtjeva najmanju loptu?#Fudbal#Tenis#Ragbi#Golf#Golf");
        Steganography.encode(new File("8.png"), "Koji od navedenih nije ekipni sport?#Odbojka na pijesku#Tenis#Snuker#Kosarka#Snuker");
        Steganography.encode(new File("9.png"), "Koja zemlja ima najvise ucesca na Olimpijskim igrama a da jos uvijek nije osvojila " +
                "zlatnu medalju?#Costa Rica#Indonezija#Filipini#Juzna Afrika#Filipini");
        Steganography.encode(new File("10.png"), "Ko je osvojio vise Gren Slem titula, Serena Viliams ili Venus Viliams?#Serena Viliams");
        Steganography.encode(new File("11.png"), "Koja zemlja ima najvise ucesca na Olimpijskim igrama bez osvojene medalje?#Lihtenstajn");
        Steganography.encode(new File("12.png"), "NBA je skracenica za?#National Basketball Association");
        Steganography.encode(new File("13.png"), "Koliko je dugacak bazen za plivanje prema propisima Olimpijskih igara?#42 m#" +
                "30 m#45 m#50 m#50 m");
        Steganography.encode(new File("14.png"), "U kom od navedenih sportova se ne koristi lopta?#Hokej#Polo#Tenis#Golf#Hokej");
        Steganography.encode(new File("15.png"), "Koliko je igraca u jednom bejzbol timu?#9");
        Steganography.encode(new File("16.png"), "Koliko je Olimpijskih igara odrzano u zemljama koje vise ne postoje?#3");
        Steganography.encode(new File("17.png"), "Koji tim drzi rekord najduzeg niza pobjeda u NBA istoriji?#Los Angeles Lakers");
        Steganography.encode(new File("18.png"), "Koji je rekord datih crvenih kartona na jednoj utakmici?#36#22#21#11#36");
        Steganography.encode(new File("19.png"), "Olimpijske igre su odrzavane svakih?#3 godine#2 godine#4 godine#8 godina#4 godine");
        Steganography.encode(new File("20.png"), "Koliko medalja je Kina osvojila na Olimpijskim igrama u Pekingu 2008 godine?#87#50#120#100#100");
        //System.out.println(Steganography.decode(new File("1_stego.bmp")));
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
