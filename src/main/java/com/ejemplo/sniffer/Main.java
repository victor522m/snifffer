package com.ejemplo.sniffer;


import com.ejemplo.sniffer.controller.SnifferController;
import com.ejemplo.sniffer.view.SnifferView;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        SnifferView view = new SnifferView();
        SnifferController controller = new SnifferController();

        try {
            // Listar interfaces
            List<PcapNetworkInterface> interfaces = controller.getInterfaces();
            view.showInterfaces(interfaces);

            // Seleccionar una interfaz
            
            @SuppressWarnings("resource")
            Scanner scanner = new Scanner(System.in);
            System.out.print("Selecciona una interfaz (número): ");
            int choice = scanner.nextInt();

            PcapNetworkInterface selectedInterface = interfaces.get(choice);
            controller.startSniffing(selectedInterface, 65536, 10);

            // Capturar paquetes indefinidamente
            System.out.println("Capturando paquetes... Presiona Ctrl+C para detener.");
            try {
                while (true) {
                    Packet packet = controller.capturePacket();
                    if (packet != null) {
                        view.showPacket(packet);
                    }
                }
            } finally {
                controller.stopSniffing();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
