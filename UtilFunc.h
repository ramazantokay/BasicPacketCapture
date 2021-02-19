#include <stdlib.h>
#include <getopt.h>
#include "Packet.h"
#include "TcpLayer.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "PcapFileDevice.h"
#include "TablePrinter.h"

using namespace std;

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

bool keepRunning = true;

static struct option long_options[] =
    {
        {"interface-name", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"list", no_argument, NULL, 'l'},
        {0, 0, 0, 0}};

struct PacketStats
{
    int ethPacketCount;
    int ipv4PacketCount;
    int ipv6PacketCount;
    int tcpPacketCount;
    int udpPacketCount;
    int dnsPacketCount;
    int httpPacketCount;
    int sslPacketCount;

    void clear()
    {
        ethPacketCount = 0;
        ipv4PacketCount = 0;
        ipv6PacketCount = 0;
        tcpPacketCount = 0;
        udpPacketCount = 0;
        tcpPacketCount = 0;
        dnsPacketCount = 0;
        httpPacketCount = 0;
        sslPacketCount = 0;
    }

    PacketStats() { clear(); }

    void consumePacket(pcpp::Packet &packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
			dnsPacketCount++;
    }

    void printToConsole()
    {
        printf(ANSI_COLOR_CYAN "Packets Count\n" ANSI_COLOR_RESET);
        vector<string> columnNames{"Ethernet", "IPv4", "IPv6", "TCP", "UDP", "DNS", "HTTP", "SSL"};
        vector<int> width(8, 11);
        vector<string> values;

        values.push_back(to_string(ethPacketCount));
        values.push_back(to_string(ipv4PacketCount));
        values.push_back(to_string(ipv6PacketCount));
        values.push_back(to_string(tcpPacketCount));
        values.push_back(to_string(udpPacketCount));
        values.push_back(to_string(dnsPacketCount));
        values.push_back(to_string(httpPacketCount));
        values.push_back(to_string(sslPacketCount));

        pcpp::TablePrinter table(columnNames, width);
        table.printRow(values);
        table.closeTable();
    }
};

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::TCP:
        return "TCP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

std::string printTcpFlags(pcpp::TcpLayer *tcpLayer)
{
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}

void onApplicationInterrupted(void *cookie)
{
    keepRunning = false;
    printf(ANSI_COLOR_RED "\n Stopping packet capturing... \n" ANSI_COLOR_RESET);
}

void printHelp()
{
    printf("\n");
    printf("\nUsage:\n"
           "------\n"
           "%s -n INTERFACE_NAME\n"
           "\nOptions:\n\n"
           "    -h|--help                                  : Displays this help message and exits\n"
           "    -v|--version                               : Displays the current version and exits\n"
           "    -l|--list                                  : Print the list of current interfaces and exits\n"
           "    -n|--interface-name       INTERFACE_NAME   : interface name that will be tracked\n",
           pcpp::AppName::get().c_str());
}

void printVers()
{
    printf("\n");
    printf("%s %s\n", pcpp::AppName::get().c_str(), pcpp::getPcapPlusPlusVersionFull().c_str());
    printf("Built: %s\n", pcpp::getBuildDateTime().c_str());
    printf("Built from: %s\n", pcpp::getGitInfo().c_str());
    exit(0);
}

void listInterfaces()
{
    printf("\n");
    printf(ANSI_COLOR_BLUE "Available Interfaces" ANSI_COLOR_RESET);
    printf("\n");

    const std::vector<pcpp::PcapLiveDevice *> &deviceList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    vector<string> columnNames{"Name", "MAC", "IP"};
    vector<int> width(3,25);
    vector<vector<string>> values(deviceList.size());
    int device_number = 0;

    for (std::vector<pcpp::PcapLiveDevice *>::const_iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
    {
        values[device_number].push_back((*iter)->getName());
        values[device_number].push_back((*iter)->getMacAddress() == pcpp::MacAddress::Zero ? "N/A" : (*iter)->getMacAddress().toString());
        values[device_number++].push_back((*iter)->getIPv4Address().toString());        
    }

    pcpp::TablePrinter table_interface(columnNames, width);
    for (int x = 0; x < device_number; x++)
    {
        table_interface.printRow(values[x]);
        if (x != (device_number - 1))
            table_interface.printSeparator();
    }
}
