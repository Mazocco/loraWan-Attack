/*
 * Cenário de Flooding Attack em rede LoRaWAN.
 * 30 dispositivos legítimos (Classe A, ABP) + 10 nós maliciosos.
 * Legítimos transmitem a cada 60s com offset aleatório.
 * Maliciosos transmitem a cada 1s iniciando entre 1 e 20s.
 */

#include "ns3/core-module.h"
#include "ns3/lorawan-module.h"
#include "ns3/mobility-helper.h"
#include "ns3/point-to-point-helper.h"
#include <fstream>
#include <map>

using namespace ns3;
using namespace lorawan;

NS_LOG_COMPONENT_DEFINE("FloodingAttack");

int packetsSent        = 0;
int packetsReceived    = 0;
int legitimateSent     = 0;
int legitimateReceived = 0;
uint64_t totalBytesReceived = 0;
double lastDelay   = -1;
double totalJitter = 0;
int jitterCount    = 0;

const uint32_t NUM_MALICIOUS  = 10;
const uint32_t NUM_LEGITIMATE = 30;
const uint32_t TOTAL_DEVICES  = NUM_MALICIOUS + NUM_LEGITIMATE;

NodeContainer gatewaysGlobal;
std::ofstream outFile;
std::map<uint64_t, std::pair<double, uint32_t>> sendTimes;
double floodInterval = 1.0;

void ScheduleMaliciousTransmission(Ptr<Node> node, double interval, double stopTime)
{
    Ptr<LoraNetDevice> dev = DynamicCast<LoraNetDevice>(node->GetDevice(0));
    if (!dev) return;
    Ptr<LorawanMac> mac = dev->GetMac();
    Ptr<ClassAEndDeviceLorawanMac> edMac = DynamicCast<ClassAEndDeviceLorawanMac>(mac);
    if (!edMac) return;
    Ptr<Packet> pkt = Create<Packet>(10);
    edMac->Send(pkt);
    double nextTime = Simulator::Now().GetSeconds() + interval;
    if (nextTime < stopTime)
        Simulator::Schedule(Seconds(interval), &ScheduleMaliciousTransmission, node, interval, stopTime);
}

void TxCallback(Ptr<Node> node, Ptr<const Packet> packet, uint32_t sf)
{
    packetsSent++;
    uint32_t nodeId      = node->GetId();
    bool     isMalicious = (nodeId < NUM_MALICIOUS);
    if (!isMalicious) legitimateSent++;
    Ptr<MobilityModel> mobEd = node->GetObject<MobilityModel>();
    Ptr<MobilityModel> mobGw = gatewaysGlobal.Get(0)->GetObject<MobilityModel>();
    double distance = mobEd->GetDistanceFrom(mobGw);
    uint64_t id   = packet->GetUid();
    double   time = Simulator::Now().GetSeconds();
    sendTimes[id] = {time, nodeId};
    outFile << time << ",TX," << id << ",,," << distance << "," << nodeId << ","
            << (isMalicious ? "malicious" : "legitimate") << std::endl;
}

void RxCallback(Ptr<const Packet> packet, uint32_t sf)
{
    packetsReceived++;
    totalBytesReceived += packet->GetSize();
    uint64_t id   = packet->GetUid();
    double   time = Simulator::Now().GetSeconds();
    double   delay       = 0;
    uint32_t nodeId      = 9999;
    bool     isMalicious = false;
    if (sendTimes.find(id) != sendTimes.end())
    {
        auto [sendTime, nId] = sendTimes[id];
        delay       = time - sendTime;
        nodeId      = nId;
        isMalicious = (nodeId < NUM_MALICIOUS);
    }
    if (!isMalicious) legitimateReceived++;
    if (lastDelay >= 0)
    {
        double jitter = std::abs(delay - lastDelay);
        totalJitter += jitter;
        jitterCount++;
        outFile << time << ",RX," << id << "," << delay << "," << jitter
                << ",," << nodeId << "," << (isMalicious ? "malicious" : "legitimate") << std::endl;
    }
    else
    {
        outFile << time << ",RX," << id << "," << delay << ",0"
                << ",," << nodeId << "," << (isMalicious ? "malicious" : "legitimate") << std::endl;
    }
    lastDelay = delay;
}

int main(int argc, char* argv[])
{
    bool   verbose = false;
    double simTime = 800.0;
    CommandLine cmd(__FILE__);
    cmd.AddValue("verbose",       "Ativar logs detalhados",            verbose);
    cmd.AddValue("simTime",       "Duração da simulação em segundos",  simTime);
    cmd.AddValue("floodInterval", "Intervalo de flooding em segundos", floodInterval);
    cmd.Parse(argc, argv);

    LogComponentEnable("FloodingAttack",             LOG_LEVEL_ALL);
    LogComponentEnable("NetworkServer",              LOG_LEVEL_ALL);
    LogComponentEnable("GatewayLorawanMac",          LOG_LEVEL_ALL);
    LogComponentEnable("EndDeviceLorawanMac",        LOG_LEVEL_ALL);
    LogComponentEnable("ClassAEndDeviceLorawanMac",  LOG_LEVEL_ALL);
    LogComponentEnableAll(LOG_PREFIX_FUNC);
    LogComponentEnableAll(LOG_PREFIX_NODE);
    LogComponentEnableAll(LOG_PREFIX_TIME);

    Ptr<LogDistancePropagationLossModel> loss = CreateObject<LogDistancePropagationLossModel>();
    loss->SetPathLossExponent(3.76);
    loss->SetReference(1, 7.7);
    Ptr<PropagationDelayModel> propDelay = CreateObject<ConstantSpeedPropagationDelayModel>();
    Ptr<LoraChannel> channel = CreateObject<LoraChannel>(loss, propDelay);

    MobilityHelper mobilityEd;
    Ptr<UniformDiscPositionAllocator> posAllocEd = CreateObject<UniformDiscPositionAllocator>();
    posAllocEd->SetX(0.0);
    posAllocEd->SetY(0.0);
    posAllocEd->SetRho(5000.0);
    mobilityEd.SetPositionAllocator(posAllocEd);
    mobilityEd.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    MobilityHelper mobilityGw;
    Ptr<ListPositionAllocator> posAllocGw = CreateObject<ListPositionAllocator>();
    posAllocGw->Add(Vector(0.0, 0.0, 0.0));
    mobilityGw.SetPositionAllocator(posAllocGw);
    mobilityGw.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    LoraPhyHelper    phyHelper;
    LorawanMacHelper macHelper;
    LoraHelper       helper;
    phyHelper.SetChannel(channel);

    // nodeId 0..9  → maliciosos
    // nodeId 10..39 → legítimos
    NodeContainer endDevices;
    endDevices.Create(TOTAL_DEVICES);
    mobilityEd.Install(endDevices);

    uint8_t  nwkId   = 54;
    uint32_t nwkAddr = 1864;
    Ptr<LoraDeviceAddressGenerator> addrGen =
        CreateObject<LoraDeviceAddressGenerator>(nwkId, nwkAddr);
    phyHelper.SetDeviceType(LoraPhyHelper::ED);
    macHelper.SetDeviceType(LorawanMacHelper::ED_A);
    macHelper.SetAddressGenerator(addrGen);
    macHelper.SetRegion(LorawanMacHelper::EU);
    helper.Install(phyHelper, macHelper, endDevices);

    // PeriodicSender nos legítimos — igual ao cenário base
    PeriodicSenderHelper periodicHelper;
    periodicHelper.SetPeriod(Seconds(60));
    Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable>();
    for (uint32_t i = NUM_MALICIOUS; i < TOTAL_DEVICES; i++)
    {
        double offset = rand->GetValue(0, 60);
        auto app = periodicHelper.Install(endDevices.Get(i));
        app.Start(Seconds(offset));
        app.Stop(Seconds(simTime));
    }

    // Maliciosos — transmissão periódica a cada 1s, início entre 1 e 20s
    for (uint32_t i = 0; i < NUM_MALICIOUS; i++)
    {
        double startTime = rand->GetValue(1, 20);
        Simulator::Schedule(Seconds(startTime), &ScheduleMaliciousTransmission,
                            endDevices.Get(i), floodInterval, simTime);
    }

    for (NodeContainer::Iterator i = endDevices.Begin(); i != endDevices.End(); ++i)
    {
        Ptr<Node> node = *i;
        Ptr<LoraNetDevice> dev = DynamicCast<LoraNetDevice>(node->GetDevice(0));
        Ptr<LoraPhy> phy = dev->GetPhy();
        phy->TraceConnectWithoutContext("StartSending", MakeBoundCallback(&TxCallback, node));
    }

    NodeContainer gateways;
    gateways.Create(1);
    mobilityGw.Install(gateways);
    gatewaysGlobal = gateways;
    phyHelper.SetDeviceType(LoraPhyHelper::GW);
    macHelper.SetDeviceType(LorawanMacHelper::GW);
    helper.Install(phyHelper, macHelper, gateways);
    LorawanMacHelper::SetSpreadingFactorsUp(endDevices, gateways, channel);

    for (NodeContainer::Iterator i = gateways.Begin(); i != gateways.End(); ++i)
    {
        Ptr<Node> node = *i;
        Ptr<LoraNetDevice> dev = DynamicCast<LoraNetDevice>(node->GetDevice(0));
        Ptr<LoraPhy> phy = dev->GetPhy();
        phy->TraceConnectWithoutContext("ReceivedPacket", MakeCallback(&RxCallback));
    }

    Ptr<Node> networkServer = CreateObject<Node>();
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate",  StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay",    StringValue("2ms"));
    P2PGwRegistration_t gwRegistration;
    for (auto gw = gateways.Begin(); gw != gateways.End(); ++gw)
    {
        auto container       = p2p.Install(networkServer, *gw);
        auto serverP2PNetDev = DynamicCast<PointToPointNetDevice>(container.Get(0));
        gwRegistration.emplace_back(serverP2PNetDev, *gw);
    }
    NetworkServerHelper networkServerHelper;
    networkServerHelper.SetGatewaysP2P(gwRegistration);
    networkServerHelper.SetEndDevices(endDevices);
    networkServerHelper.Install(networkServer);
    ForwarderHelper forwarderHelper;
    forwarderHelper.Install(gateways);

    Simulator::Stop(Seconds(simTime));
    outFile.open("flooding_results.csv");
    outFile << "time,event,packetId,delay,jitter,distance,nodeId,type" << std::endl;
    Simulator::Run();
    outFile.close();

    int    collisions    = packetsSent - packetsReceived;
    int    legCollisions = legitimateSent - legitimateReceived;
    double pdrAll        = (packetsSent > 0)     ? (double)packetsReceived    / packetsSent    : 0;
    double pdrLegitimate = (legitimateSent > 0)  ? (double)legitimateReceived / legitimateSent : 0;
    double throughput    = (totalBytesReceived * 8.0) / simTime;
    double collisionRate = (packetsSent > 0)     ? (double)collisions / packetsSent            : 0;
    double avgJitter     = (jitterCount > 0)     ? totalJitter / jitterCount                   : 0;

    std::cout << "=== Flooding Attack — Resultados ===" << std::endl;
    std::cout << "Dispositivos legítimos : " << NUM_LEGITIMATE  << std::endl;
    std::cout << "Nós maliciosos         : " << NUM_MALICIOUS   << std::endl;
    std::cout << "Intervalo de flooding  : " << floodInterval   << " s" << std::endl;
    std::cout << "Período legítimos      : 60 s" << std::endl;
    std::cout << "---" << std::endl;
    std::cout << "Pacotes enviados (total)      : " << packetsSent        << std::endl;
    std::cout << "Pacotes recebidos (total)     : " << packetsReceived    << std::endl;
    std::cout << "Pacotes enviados (legítimos)  : " << legitimateSent     << std::endl;
    std::cout << "Pacotes recebidos (legítimos) : " << legitimateReceived << std::endl;
    std::cout << "---" << std::endl;
    std::cout << "PDR geral             : " << pdrAll        << std::endl;
    std::cout << "PDR legítimos         : " << pdrLegitimate << std::endl;
    std::cout << "Colisões (total)      : " << collisions    << std::endl;
    std::cout << "Colisões (legítimos)  : " << legCollisions << std::endl;
    std::cout << "Taxa de colisão       : " << collisionRate << std::endl;
    std::cout << "Throughput            : " << throughput    << " bps" << std::endl;
    std::cout << "Jitter médio          : " << avgJitter     << " s"   << std::endl;

    Simulator::Destroy();
    return 0;
}
