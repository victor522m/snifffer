package com.ejemplo.sniffer.model;



import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

public class NetworkInterfaceModel {
    public List<PcapNetworkInterface> getNetworkInterfaces() throws Exception {
        return Pcaps.findAllDevs();
    }
}

