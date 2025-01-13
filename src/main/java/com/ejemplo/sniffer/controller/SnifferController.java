package com.ejemplo.sniffer.controller;

import com.ejemplo.sniffer.model.NetworkInterfaceModel;
import com.ejemplo.sniffer.model.PacketModel;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.List;

public class SnifferController {
    private final NetworkInterfaceModel networkModel;
    private final PacketModel packetModel;

    public SnifferController() {
        this.networkModel = new NetworkInterfaceModel();
        this.packetModel = new PacketModel();
    }

    public List<PcapNetworkInterface> getInterfaces() throws Exception {
        return networkModel.getNetworkInterfaces();
    }

    public void startSniffing(PcapNetworkInterface nif, int snapLen, int timeout) throws Exception {
        packetModel.openInterface(nif, snapLen, timeout);
    }

    public Packet capturePacket() throws Exception {
        return packetModel.capturePacket();
    }

    public void stopSniffing() {
        packetModel.closeInterface();
    }
}
