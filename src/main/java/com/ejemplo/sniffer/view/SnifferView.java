package com.ejemplo.sniffer.view;

import org.pcap4j.packet.*;


public class SnifferView {
    public void showSniffingStatus(String status) {
        System.out.println(status);
    }

    public void showInterfaces(java.util.List<org.pcap4j.core.PcapNetworkInterface> interfaces) {
        System.out.println("Interfaces de red disponibles:");
        for (int i = 0; i < interfaces.size(); i++) {
            System.out.println(i + ": " + interfaces.get(i).getName() + " (" + interfaces.get(i).getDescription() + ")");
        }
    }

    public void showPacket(Packet packet) {
        System.out.println("Paquete capturado: " + packet.getClass().getSimpleName());

        if (packet.contains(IpV4Packet.class)) {
            System.out.println("Paquete capturado IPV4:");
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            IpV4Packet.IpV4Header ipHeader = ipPacket.getHeader();
            System.out.println("  IP de origen: " + ipHeader.getSrcAddr());
            System.out.println("  IP de destino: " + ipHeader.getDstAddr());

            // Análisis de paquetes TCP
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                System.out.println("  Puerto de origen: " + tcpHeader.getSrcPort());
                System.out.println("  Puerto de destino: " + tcpHeader.getDstPort());

                // Mostrar contenido en formato humano
                if (tcpPacket.getPayload() != null) {
                    System.out.println("  Contenido: " + new String(tcpPacket.getPayload().getRawData()));
                }
            }

            // Análisis de paquetes UDP
            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                System.out.println("  Puerto de origen: " + udpHeader.getSrcPort());
                System.out.println("  Puerto de destino: " + udpHeader.getDstPort());

                // Mostrar contenido en formato humano
                if (udpPacket.getPayload() != null) {
                    System.out.println("  Contenido: " + new String(udpPacket.getPayload().getRawData()));
                }
            }

            // Análisis de paquetes ICMP
            if (packet.contains(IcmpV4CommonPacket.class)) {
                System.out.println("  Paquete ICMP detectado.");
                IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);

                // Mostrar contenido en formato humano
                if (icmpPacket.getPayload() != null) {
                    System.out.println("  Contenido: " + new String(icmpPacket.getPayload().getRawData()));
                }
            }
        } else if (packet.contains(IpV6Packet.class)) {
            System.out.println("Paquete capturado IPV6:");
            IpV6Packet ipPacket = packet.get(IpV6Packet.class);
            IpV6Packet.IpV6Header ipHeader = ipPacket.getHeader();
            System.out.println("  IP de origen: " + ipHeader.getSrcAddr());
            System.out.println("  IP de destino: " + ipHeader.getDstAddr());

            // Análisis de paquetes TCP
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                System.out.println("  Puerto de origen: " + tcpHeader.getSrcPort());
                System.out.println("  Puerto de destino: " + tcpHeader.getDstPort());

                // Mostrar contenido en formato humano
                if (tcpPacket.getPayload() != null) {
                    System.out.println("  Contenido: " + new String(tcpPacket.getPayload().getRawData()));
                }
            }

            // Análisis de paquetes UDP
            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                System.out.println("  Puerto de origen: " + udpHeader.getSrcPort());
                System.out.println("  Puerto de destino: " + udpHeader.getDstPort());

                // Mostrar contenido en formato humano
                if (udpPacket.getPayload() != null) {
                    System.out.println("  Contenido: " + new String(udpPacket.getPayload().getRawData()));
                }
            }

            // Análisis de paquetes ICMP
            if (packet.contains(IcmpV6CommonPacket.class)) {
                System.out.println("  Paquete ICMP detectado.");
                IcmpV6CommonPacket icmpPacket = packet.get(IcmpV6CommonPacket.class);

                // Mostrar contenido en formato humano
                if (icmpPacket.getPayload() != null) {
                    System.out.println("  Contenido: " + new String(icmpPacket.getPayload().getRawData()));
                }
            }
        } else if (packet.contains(ArpPacket.class)) {
            System.out.println("Paquete ARP capturado.");
        } else {
            System.out.println("Tipo de paquete desconocido.");
        }

        // Mostrar el contenido en formato hexadecimal
        System.out.println("  Hex stream: " + packet);
    }
}
