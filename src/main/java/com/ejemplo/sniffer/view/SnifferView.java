package com.ejemplo.sniffer.view;

import com.ejemplo.sniffer.controller.SnifferController;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.*;

import java.util.List;

public class SnifferView {
    private final SnifferController controller;
    private TextArea outputArea;
    private List<PcapNetworkInterface> interfaces;
    private Thread sniffingThread;

    public SnifferView(SnifferController controller) {
        this.controller = controller;
    }

    public void start(Stage primaryStage) {
        primaryStage.setTitle("Sniffer Application");

        ListView<String> interfaceList = new ListView<>();
        outputArea = new TextArea();
        outputArea.setEditable(false); // Hacer que el área de texto sea no editable
        Button btnStart = new Button("Start Sniffing");
        Button btnPause = new Button("Pause");
        Button btnExit = new Button("Exit");

        // Cargar las interfaces de red disponibles
        try {
            interfaces = controller.getInterfaces();
            for (PcapNetworkInterface nif : interfaces) {
                interfaceList.getItems().add(nif.getName() + " (" + nif.getDescription() + ")");
            }
        } catch (Exception e) {
            showSniffingStatus("Error: " + e.getMessage());
        }

        // Acción al hacer clic en el botón "Start Sniffing"
        btnStart.setOnAction(event -> {
            int selectedIndex = interfaceList.getSelectionModel().getSelectedIndex();
            if (selectedIndex >= 0) {
                PcapNetworkInterface selectedInterface = interfaces.get(selectedIndex);
                startSniffing(selectedInterface);
            } else {
                showSniffingStatus("Por favor, selecciona una interfaz de red.");
            }
        });

        // Acción al hacer clic en el botón "Pause"
        btnPause.setOnAction(event -> {
            if (sniffingThread != null && sniffingThread.isAlive()) {
                sniffingThread.interrupt();
                showSniffingStatus("Sniffing pausado.");
            }
        });

        // Acción al hacer clic en el botón "Exit"
        btnExit.setOnAction(event -> {
            if (sniffingThread != null && sniffingThread.isAlive()) {
                sniffingThread.interrupt();
            }
            Platform.exit();
        });

        HBox buttonBox = new HBox(btnStart, btnPause, btnExit);
        VBox vbox = new VBox(interfaceList, buttonBox, outputArea);
        Scene scene = new Scene(vbox, 600, 400); // Ajustar el tamaño de la interfaz
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void startSniffing(PcapNetworkInterface nif) {
        try {
            controller.startSniffing(nif, 65536, 10);
            showSniffingStatus("Capturando paquetes...");

            // Capturar paquetes en un nuevo hilo para no bloquear la UI
            sniffingThread = new Thread(() -> {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        Packet packet = controller.capturePacket();
                        if (packet != null) {
                            Platform.runLater(() -> showPacket(packet));
                        }
                    }
                } catch (Exception e) {
                    Platform.runLater(() -> showSniffingStatus("Error: " + e.getMessage()));
                }
            });
            sniffingThread.start();
        } catch (Exception e) {
            showSniffingStatus("Error: " + e.getMessage());
        }
    }

    public void showSniffingStatus(String status) {
        Platform.runLater(() -> outputArea.appendText(status + "\n"));
    }

    public void showPacket(Packet packet) {
        StringBuilder packetInfo = new StringBuilder();
        packetInfo.append("Paquete capturado: ").append(packet.getClass().getSimpleName()).append("\n");

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            IpV4Packet.IpV4Header ipHeader = ipPacket.getHeader();
            packetInfo.append("  IP de origen: ").append(ipHeader.getSrcAddr()).append("\n");
            packetInfo.append("  IP de destino: ").append(ipHeader.getDstAddr()).append("\n");

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                packetInfo.append("  Puerto de origen: ").append(tcpHeader.getSrcPort()).append("\n");
                packetInfo.append("  Puerto de destino: ").append(tcpHeader.getDstPort()).append("\n");

                if (tcpPacket.getPayload() != null) {
                    packetInfo.append("  Contenido: ").append(new String(tcpPacket.getPayload().getRawData())).append("\n");
                }
            }

            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                packetInfo.append("  Puerto de origen: ").append(udpHeader.getSrcPort()).append("\n");
                packetInfo.append("  Puerto de destino: ").append(udpHeader.getDstPort()).append("\n");

                if (udpPacket.getPayload() != null) {
                    packetInfo.append("  Contenido: ").append(new String(udpPacket.getPayload().getRawData())).append("\n");
                }
            }

            if (packet.contains(IcmpV4CommonPacket.class)) {
                IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
                packetInfo.append("  Paquete ICMP detectado.\n");

                if (icmpPacket.getPayload() != null) {
                    packetInfo.append("  Contenido: ").append(new String(icmpPacket.getPayload().getRawData())).append("\n");
                }
            }
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipPacket = packet.get(IpV6Packet.class);
            IpV6Packet.IpV6Header ipHeader = ipPacket.getHeader();
            packetInfo.append("  IP de origen: ").append(ipHeader.getSrcAddr()).append("\n");
            packetInfo.append("  IP de destino: ").append(ipHeader.getDstAddr()).append("\n");

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                packetInfo.append("  Puerto de origen: ").append(tcpHeader.getSrcPort()).append("\n");
                packetInfo.append("  Puerto de destino: ").append(tcpHeader.getDstPort()).append("\n");

                if (tcpPacket.getPayload() != null) {
                    packetInfo.append("  Contenido: ").append(new String(tcpPacket.getPayload().getRawData())).append("\n");
                }
            }

            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                packetInfo.append("  Puerto de origen: ").append(udpHeader.getSrcPort()).append("\n");
                packetInfo.append("  Puerto de destino: ").append(udpHeader.getDstPort()).append("\n");

                if (udpPacket.getPayload() != null) {
                    packetInfo.append("  Contenido: ").append(new String(udpPacket.getPayload().getRawData())).append("\n");
                }
            }

            if (packet.contains(IcmpV6CommonPacket.class)) {
                IcmpV6CommonPacket icmpPacket = packet.get(IcmpV6CommonPacket.class);
                packetInfo.append("  Paquete ICMP detectado.\n");

                if (icmpPacket.getPayload() != null) {
                    packetInfo.append("  Contenido: ").append(new String(icmpPacket.getPayload().getRawData())).append("\n");
                }
            }
        } else if (packet.contains(ArpPacket.class)) {
            packetInfo.append("Paquete ARP capturado.\n");
        } else {
            packetInfo.append("Tipo de paquete desconocido.\n");
        }

        packetInfo.append("  Hex stream: ").append(packet).append("\n");
        Platform.runLater(() -> outputArea.setText(packetInfo.toString()));
    }
}
