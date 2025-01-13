package com.ejemplo.sniffer.model;



import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

public class PacketModel {
    private PcapHandle handle;

    public void openInterface(PcapNetworkInterface nif, int snapLen, int timeout) throws Exception {
        handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
    }

    public Packet capturePacket() throws Exception {
        return handle.getNextPacket();
    }

    public void closeInterface() {
        if (handle != null) {
            handle.close();
        }
    }
}

