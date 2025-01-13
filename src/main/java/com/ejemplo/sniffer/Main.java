package com.ejemplo.sniffer;

import com.ejemplo.sniffer.controller.SnifferController;
import javafx.application.Application;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) {
        try {
            SnifferController controller = new SnifferController();
            controller.start(primaryStage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
