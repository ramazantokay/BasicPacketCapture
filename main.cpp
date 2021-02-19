#include <getopt.h>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include "Packet.h"
#include "IPv4Layer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "UtilFunc.h"

using namespace std;

static bool onPacketsArrive(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
    static int counter = 1;
    PacketStats *stats = (PacketStats *)cookie;
    pcpp::Packet parsedPacket(packet);
    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    printf("\n");
    printf(ANSI_COLOR_BLUE "========================= #%d# PACKET START =========================" ANSI_COLOR_RESET, counter);
    printf("\n");
    printf("\n");
    (ipv4Layer->getSrcIPAddress() == dev->getIPv4Address()) ? printf(ANSI_COLOR_RED "OUTGOING PACKET" ANSI_COLOR_RESET) : printf(ANSI_COLOR_GREEN "INCOMING PACKET" ANSI_COLOR_RESET);
    printf("\n");
    cout << parsedPacket.toString() << endl;
    printf(ANSI_COLOR_BLUE "========================= #%d# PACKET END =========================" ANSI_COLOR_RESET, counter++);
    printf("\n");
    printf("\n");

    stats->consumePacket(parsedPacket); 

    return !keepRunning;
}

int main(int argc, char *argv[])
{
    pcpp::AppName::init(argc, argv);
    pcpp::PcapLiveDevice *device = NULL;
    string interfaceName = "";
    char opt = 0;
    int opt_index = 0;

    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, NULL);

    while ((opt = getopt_long(argc, argv, "n:hvl", long_options, &opt_index)) != -1)
    {
        switch (opt)
        {
            case 0:
            {
                break;
            }
            case 'n':
            {
                interfaceName = string(optarg);
                device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceName.c_str());
                if (device == NULL)
                {
                    printf("\n");
                    printf(ANSI_COLOR_RED "Cannot find the interfaceName %s\n" ANSI_COLOR_RESET, interfaceName.c_str());
                    exit(1);
                }
                break;
            }
            case 'h':
            {
                printHelp();
                exit(0);
            }
            case 'v':
            {
                printVers();
                break;
            }
            case 'l':
            {
                listInterfaces();
                exit(0);
            }
            default:
            {
                printHelp();
                exit(0);
            }
        }
    }

    if (device == NULL)
    {
        printf("\n");
        printf(ANSI_COLOR_RED "Cannot find interface name, please provide interface name " ANSI_COLOR_RESET);
        printHelp();
        exit(1);
    }
    printf("\n");

    printf("Interface info:\n");
    printf("\n");

    printf("Interface name: %s\n", device->getName().c_str());
    printf("Interface description: %s\n", device->getDesc().c_str());
    printf("MAC Address: %s\n", device->getMacAddress().toString().c_str());
    printf("Default Gateway: %s\n", device->getDefaultGateway().toString().c_str());
    printf("Interface MTU: %d\n", device->getMtu());

    if (device->getDnsServers().size() > 0)
        printf("DNS Server: %s\n", device->getDnsServers().at(0).toString().c_str());

    if (!device->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

    PacketStats stats;
    
    //@TODO: Will be implemented filtering feature

    // printf(ANSI_COLOR_GREEN "\nFiltering packets...\n" ANSI_COLOR_RESET);
    
    // pcpp::IPFilter ip1("ip_address", pcpp::SRC);
    // pcpp::IPFilter ip2("ip_address", pcpp::SRC_OR_DST);
    // pcpp::IPFilter ip3("ip_address", pcpp::SRC);

    // pcpp::PortFilter portfilter(443, pcpp::SRC_OR_DST);
    // pcpp::ProtoFilter protocolFilter(pcpp::UDP);

    // pcpp::NotFilter notfilter(&ip1);
    // pcpp::NotFilter notfilter2(&ip2);


    // pcpp::AndFilter andFilter;

    // andFilter.addFilter(&notfilter);
    // andFilter.addFilter(&notfilter2);
    
    // andFilter.addFilter(&portfilter);
    // andFilter.addFilter(&protocolFilter);

    // pcpp::NotFilter noFilter(&andFilter);

    // device->setFilter(andFilter);
    printf(ANSI_COLOR_GREEN "\nStarting capture packets...\n" ANSI_COLOR_RESET);

    device->startCaptureBlockingMode(onPacketsArrive, &stats, 0);

    while (keepRunning)
        sleep(3);

    stats.printToConsole();
    stats.clear();
}
