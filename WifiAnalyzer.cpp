// ===========================================================
//  WifiAnalyzer.cpp  -  v2.0
//  New features:
//    [S] Network scan  (ping sweep + port scan)
//    [T] Speed test    (download / upload / ping via Cloudflare)
//    [D] DNS & gateway analysis + leak detection
//    [R] PCAP packet capture  (unchanged)
//        Channel congestion map  (always on)
//        Advanced threat detection: ARP spoofing + deauth tracking
// ===========================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Winsock headers must come before <windows.h>
#include <winsock2.h>
#include <windows.h>
#include <wlanapi.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <icmpapi.h>
#include <winhttp.h>

// STL
#include <iostream>
#include <vector>
#include <map>
#include <numeric>
#include <string>
#include <atomic>
#include <algorithm>
#include <thread>
#include <mutex>

// libpcap (Npcap)
#define HAVE_REMOTE
#include <pcap.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "pcap.lib")
#pragma comment(lib, "winhttp.lib")

// ============================================================
//  STRUCTURES
// ============================================================

struct TrafficStats {
    unsigned long long inPkts,  outPkts;
    unsigned long long inBytes, outBytes;
    unsigned long long inErrors, outErrors;
    unsigned long long inDiscards, outDiscards;
};

struct BssEntry {
    std::string ssid;
    int         rssi;
    ULONG       channel;
};

// NEW --------------------------------------------------------

struct ScanHost {
    std::string      ip;
    std::string      hostname;
    std::vector<int> openPorts;
};

struct DnsGatewayInfo {
    std::string              gatewayIp;
    std::string              gatewayMac;
    std::vector<std::string> dnsServers;
    bool                     leakSuspected = false;
};

struct SpeedResult {
    double downloadMbps = 0.0;
    double uploadMbps   = 0.0;
    double pingMs       = -1.0;
};

// ============================================================
//  GLOBALS
// ============================================================

std::atomic<bool> g_Running(true);

// --- PCAP ---
std::atomic<bool>      g_PcapRecording(false);
std::atomic<long long> g_PcapPacketsSaved(0);
std::string            g_PcapStatusMsg = "READY (Press 'R' to Start)";

// --- Network scan ---
std::atomic<bool>  g_ScanRunning(false);
std::vector<ScanHost> g_ScanResults;
std::mutex         g_ScanMutex;
std::string        g_ScanStatus = "IDLE (Press 'S' to Scan)";

// --- DNS / ARP ---
DnsGatewayInfo g_DnsInfo;
std::mutex     g_DnsMutex;
std::string    g_ArpStatus      = "PENDING";
std::string    g_LastGatewayMac;          // used for change-detection

// --- Speed test ---
std::atomic<bool> g_SpeedRunning(false);
SpeedResult       g_SpeedResult;
std::string       g_SpeedStatus = "IDLE (Press 'T' to Test)";

// --- Threat counters ---
std::atomic<int> g_DeauthEvents(0);

// --- Key edge-detection ---
bool g_rPressed = false, g_sPressed = false;
bool g_tPressed = false, g_dPressed = false;

// ============================================================
//  CONSOLE HELPERS  (unchanged from v1)
// ============================================================

BOOL WINAPI ConsoleHandler(DWORD sig) {
    if (sig == CTRL_C_EVENT) {
        g_Running      = false;
        g_PcapRecording = false;
        g_ScanRunning  = false;
        g_SpeedRunning = false;
        return TRUE;
    }
    return FALSE;
}

void SetCursorPosition(int x, int y) {
    static const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    std::cout.flush();
    COORD c = { (SHORT)x, (SHORT)y };
    SetConsoleCursorPosition(hOut, c);
}

void HideCursor() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci; GetConsoleCursorInfo(hOut, &ci);
    ci.bVisible = FALSE; SetConsoleCursorInfo(hOut, &ci);
}

void ShowCursor() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci; GetConsoleCursorInfo(hOut, &ci);
    ci.bVisible = TRUE; SetConsoleCursorInfo(hOut, &ci);
}

// ============================================================
//  WLAN / STATS HELPERS  (unchanged from v1)
// ============================================================

std::string GuidToString(GUID g) {
    char s[40];
    snprintf(s, sizeof(s),
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return s;
}

DWORD GetFrequencyFromChannel(DWORD ch) {
    if (ch == 0)  return 0;
    if (ch == 14) return 2484;
    if (ch <= 13) return 2407 + ch * 5;
    if (ch >= 32 && ch <= 173) return 5000 + ch * 5;
    return 5950 + ch * 5;
}

TrafficStats GetStats(NET_LUID luid) {
    MIB_IF_ROW2 row; ZeroMemory(&row, sizeof(row));
    row.InterfaceLuid = luid;
    if (GetIfEntry2(&row) == NO_ERROR)
        return { row.InUcastPkts  + row.InNUcastPkts,
                 row.OutUcastPkts + row.OutNUcastPkts,
                 row.InOctets, row.OutOctets,
                 row.InErrors, row.OutErrors,
                 row.InDiscards, row.OutDiscards };
    return { 0,0,0,0,0,0,0,0 };
}

const char* GetPhyTypeString(DOT11_PHY_TYPE t) {
    switch (t) {
    case dot11_phy_type_erp: return "802.11g";
    case dot11_phy_type_ht:  return "802.11n (Wi-Fi 4)";
    case dot11_phy_type_vht: return "802.11ac (Wi-Fi 5)";
    case dot11_phy_type_he:  return "802.11ax (Wi-Fi 6)";
    default:                 return "Legacy/Other";
    }
}

const char* GetAuthAlgoString(DOT11_AUTH_ALGORITHM a) {
    switch (a) {
    case DOT11_AUTH_ALGO_80211_OPEN:       return "OPEN";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY: return "WEP";
    case DOT11_AUTH_ALGO_WPA:              return "WPA";
    case DOT11_AUTH_ALGO_WPA_PSK:          return "WPA-PSK";
    case DOT11_AUTH_ALGO_RSNA:             return "WPA2/WPA3-ENT";
    case DOT11_AUTH_ALGO_RSNA_PSK:         return "WPA2-PSK";
#ifdef DOT11_AUTH_ALGO_WPA3_SAE
    case DOT11_AUTH_ALGO_WPA3_SAE:         return "WPA3-SAE";
#endif
#ifdef DOT11_AUTH_ALGO_OWE
    case DOT11_AUTH_ALGO_OWE:              return "OWE";
#endif
    default: return "UNKNOWN";
    }
}

std::string GetRssiGraphAndStability(int rssi, std::vector<int>& hist, int& score) {
    hist.push_back(rssi);
    if (hist.size() > 10) hist.erase(hist.begin());
    int mn = *std::min_element(hist.begin(), hist.end());
    int mx = *std::max_element(hist.begin(), hist.end());
    score = std::max(0, std::min(100, 100 - (mx - mn) * 6));
    int bars = std::max(0, std::min(10, (rssi + 100) / 6));
    return "[" + std::string(bars, '|') + std::string(10 - bars, ' ') + "]";
}

// ============================================================
//  PCAP WORKER  (unchanged from v1)
// ============================================================

void PcapWorker(std::string deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* fp = pcap_open_live(deviceName.c_str(), 65536, 1, 1000, errbuf);
    if (!fp) {
        g_PcapStatusMsg = "ERROR: Npcap driver not found or access denied!";
        g_PcapRecording = false; return;
    }
    pcap_dumper_t* dp = pcap_dump_open(fp, "wifi_dump.pcap");
    if (!dp) {
        g_PcapStatusMsg = "ERROR: Cannot create wifi_dump.pcap!";
        pcap_close(fp); g_PcapRecording = false; return;
    }
    g_PcapStatusMsg = "RECORDING to wifi_dump.pcap...";
    struct pcap_pkthdr* hdr; const u_char* data;
    while (g_PcapRecording && g_Running) {
        if (pcap_next_ex(fp, &hdr, &data) == 1) {
            pcap_dump((u_char*)dp, hdr, data);
            g_PcapPacketsSaved++;
        }
    }
    pcap_dump_close(dp); pcap_close(fp);
    g_PcapStatusMsg = "STOPPED. Saved to wifi_dump.pcap.";
}

// ============================================================
//  NEW: PING HOST  (ICMP via IcmpSendEcho)
// ============================================================

bool PingHost(const std::string& ip, DWORD& rttMs) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return false;

    IPAddr dest = inet_addr(ip.c_str());
    char   sendData[] = "WifiAnalyzer";
    DWORD  repSize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
    std::vector<BYTE> repBuf(repSize);

    DWORD res = IcmpSendEcho(hIcmp, dest, sendData, (WORD)sizeof(sendData),
                             NULL, repBuf.data(), repSize, 300);
    IcmpCloseHandle(hIcmp);

    if (res > 0) {
        auto* rep = (PICMP_ECHO_REPLY)repBuf.data();
        rttMs = rep->RoundTripTime;
        return rep->Status == IP_SUCCESS;
    }
    return false;
}

// ============================================================
//  NEW: PORT SCANNER  (non-blocking TCP connect)
// ============================================================

std::vector<int> ScanPorts(const std::string& ip) {
    static const int kPorts[] = {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080
    };
    std::vector<int> open;

    for (int port : kPorts) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;

        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);

        sockaddr_in addr = {};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons((u_short)port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        connect(s, (sockaddr*)&addr, sizeof(addr));

        fd_set ws; FD_ZERO(&ws); FD_SET(s, &ws);
        timeval tv = { 0, 150'000 };   // 150 ms
        if (select(0, NULL, &ws, NULL, &tv) > 0)
            open.push_back(port);
        closesocket(s);
    }
    return open;
}

// ============================================================
//  NEW: NETWORK SCAN WORKER  (ping sweep + port scan)
// ============================================================

bool GetLocalSubnet(const NET_LUID& luid, std::string& subnetBase, std::string& localIp) {
    // First call to get required buffer size
    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = (PIP_ADAPTER_ADDRESSES)buf.data();

    DWORD ret = GetAdaptersAddresses(AF_INET, 0, NULL, pAddrs, &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = (PIP_ADAPTER_ADDRESSES)buf.data();
        ret    = GetAdaptersAddresses(AF_INET, 0, NULL, pAddrs, &bufLen);
    }
    if (ret != NO_ERROR) return false;

    for (auto* p = pAddrs; p; p = p->Next) {
        if (p->Luid.Value != luid.Value) continue;
        for (auto* ua = p->FirstUnicastAddress; ua; ua = ua->Next) {
            auto* sa = (sockaddr_in*)ua->Address.lpSockaddr;
            if (sa->sin_family != AF_INET) continue;
            char ipBuf[20];
            inet_ntop(AF_INET, &sa->sin_addr, ipBuf, sizeof(ipBuf));
            localIp = ipBuf;
            size_t dot = localIp.rfind('.');
            if (dot != std::string::npos)
                subnetBase = localIp.substr(0, dot + 1);   // "192.168.1."
            return true;
        }
    }
    return false;
}

void PingSweepWorker(std::string subnetBase) {
    g_ScanStatus = "SCANNING " + subnetBase + "0/24 ...";
    std::vector<ScanHost> found;

    for (int i = 1; i <= 254 && g_ScanRunning && g_Running; i++) {
        std::string ip = subnetBase + std::to_string(i);
        DWORD rtt = 0;

        if (PingHost(ip, rtt)) {
            ScanHost h;
            h.ip = ip;

            // Reverse-DNS lookup
            sockaddr_in sa = {}; sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = inet_addr(ip.c_str());
            char hostname[NI_MAXHOST] = {};
            if (getnameinfo((sockaddr*)&sa, sizeof(sa), hostname,
                            NI_MAXHOST, NULL, 0, NI_NOFQDN) != 0)
                strcpy_s(hostname, "N/A");
            h.hostname = hostname;

            // Port scan only on live hosts
            h.openPorts = ScanPorts(ip);

            found.push_back(h);
            std::lock_guard<std::mutex> lk(g_ScanMutex);
            g_ScanResults = found;
        }

        if (i % 20 == 0)
            g_ScanStatus = "SCANNING " + ip + " (" + std::to_string(i) + "/254)...";
    }

    { std::lock_guard<std::mutex> lk(g_ScanMutex); g_ScanResults = found; }
    g_ScanStatus = "DONE - " + std::to_string(found.size()) +
                   " host(s) found. Press 'S' to rescan.";
    g_ScanRunning = false;
}

// ============================================================
//  NEW: ARP SPOOFING DETECTION
// ============================================================

// Returns "OK" or a description of the anomaly detected.
// Also fills outGwMac with the current gateway MAC.
std::string CheckArpSpoofing(const std::string& gatewayIp, std::string& outGwMac) {
    // Allocate a generous fixed buffer; most home LANs have < 255 ARP entries.
    DWORD   dwSize = 65536;
    std::vector<BYTE> buf(dwSize);
    auto* table = (MIB_IPNETTABLE*)buf.data();

    if (GetIpNetTable(table, &dwSize, FALSE) != NO_ERROR)
        return "ARP: READ_ERROR";

    // Map IP -> list of MACs seen in ARP cache
    std::map<std::string, std::vector<std::string>> ipToMacs;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto& row = table->table[i];
        if (row.dwType == MIB_IPNET_TYPE_INVALID) continue;

        char ipStr[20], macStr[20];
        in_addr addr; addr.s_addr = row.dwAddr;
        inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
            row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
            row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);

        std::string ip  = ipStr;
        std::string mac = macStr;
        ipToMacs[ip].push_back(mac);
        if (ip == gatewayIp) outGwMac = mac;
    }

    // Deduplicate MAC lists and look for conflicts
    for (auto& [ip, macs] : ipToMacs) {
        std::sort(macs.begin(), macs.end());
        macs.erase(std::unique(macs.begin(), macs.end()), macs.end());
        if (macs.size() > 1)
            return "SPOOF DETECTED: " + ip +
                   " has " + std::to_string(macs.size()) + " MACs!";
    }

    // Detect gateway MAC change between calls
    if (!g_LastGatewayMac.empty() && !outGwMac.empty() &&
        g_LastGatewayMac != outGwMac)
        return "ALERT: GW MAC CHANGED " + g_LastGatewayMac +
               " -> " + outGwMac;

    if (!outGwMac.empty()) g_LastGatewayMac = outGwMac;
    return "OK";
}

// ============================================================
//  NEW: DNS & GATEWAY ANALYSIS  (+leak detection)
// ============================================================

DnsGatewayInfo GetDnsAndGatewayInfo() {
    DnsGatewayInfo info;

    // --- 1. DNS servers via GetNetworkParams ---
    ULONG fiLen = sizeof(FIXED_INFO);
    std::vector<BYTE> fiBuf(fiLen);
    if (GetNetworkParams((FIXED_INFO*)fiBuf.data(), &fiLen)
            == ERROR_BUFFER_OVERFLOW) {
        fiBuf.resize(fiLen);
    }
    if (GetNetworkParams((FIXED_INFO*)fiBuf.data(), &fiLen) == NO_ERROR) {
        auto* fi = (FIXED_INFO*)fiBuf.data();
        for (auto* d = &fi->DnsServerList; d; d = d->Next) {
            std::string s = d->IpAddress.String;
            if (!s.empty() && s != "0.0.0.0")
                info.dnsServers.push_back(s);
        }
    }

    // --- 2. Default gateway via GetIpForwardTable ---
    DWORD fwLen = 0;
    GetIpForwardTable(NULL, &fwLen, FALSE);
    std::vector<BYTE> fwBuf(fwLen + 1024);
    auto* fwTable = (MIB_IPFORWARDTABLE*)fwBuf.data();
    DWORD fwLen2 = (DWORD)fwBuf.size();
    if (GetIpForwardTable(fwTable, &fwLen2, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < fwTable->dwNumEntries; i++) {
            if (fwTable->table[i].dwForwardDest == 0) {   // default route
                in_addr gw; gw.s_addr = fwTable->table[i].dwForwardNextHop;
                char gwStr[20]; inet_ntop(AF_INET, &gw, gwStr, sizeof(gwStr));
                info.gatewayIp = gwStr;
                break;
            }
        }
    }

    // --- 3. Gateway MAC from ARP table ---
    if (!info.gatewayIp.empty())
        CheckArpSpoofing(info.gatewayIp, info.gatewayMac);

    // --- 4. DNS leak heuristic ---
    // Known trustworthy public resolvers
    static const std::vector<std::string> knownDns = {
        "8.8.8.8","8.8.4.4",                          // Google
        "1.1.1.1","1.0.0.1",                          // Cloudflare
        "9.9.9.9","149.112.112.112",                   // Quad9
        "208.67.222.222","208.67.220.220",             // OpenDNS
        "4.2.2.1","4.2.2.2","4.2.2.3","4.2.2.4"      // Level3
    };

    for (auto& dns : info.dnsServers) {
        bool isKnown   = false;
        for (auto& k : knownDns) if (dns == k) { isKnown = true; break; }
        bool isPrivate = (dns.substr(0,3)  == "10."  ||
                          dns.substr(0,4)  == "172." ||
                          dns.substr(0,8)  == "192.168." ||
                          dns.substr(0,3)  == "127");
        // Suspicious: not private AND not a known public resolver
        if (!isKnown && !isPrivate)
            info.leakSuspected = true;
    }

    return info;
}

void DnsAnalysisWorker() {
    DnsGatewayInfo info = GetDnsAndGatewayInfo();
    {
        std::lock_guard<std::mutex> lk(g_DnsMutex);
        g_DnsInfo = info;
    }
    std::string gwMac;
    g_ArpStatus = CheckArpSpoofing(info.gatewayIp, gwMac);
    if (!gwMac.empty()) {
        std::lock_guard<std::mutex> lk(g_DnsMutex);
        g_DnsInfo.gatewayMac = gwMac;
    }
}

// ============================================================
//  NEW: SPEED TEST  (Cloudflare speed.cloudflare.com)
// ============================================================

void SpeedTestWorker() {
    g_SpeedRunning = true;
    g_SpeedResult  = {};
    g_SpeedStatus  = "PINGING 1.1.1.1 ...";

    // 1. Ping
    DWORD rtt = 0;
    if (PingHost("1.1.1.1", rtt))
        g_SpeedResult.pingMs = (double)rtt;

    HINTERNET hSess = WinHttpOpen(L"WifiAnalyzer/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSess) { g_SpeedStatus = "ERROR: WinHTTP init failed"; g_SpeedRunning = false; return; }

    // 2. Download  (5 MB from Cloudflare speed test CDN)
    g_SpeedStatus = "DOWNLOAD TEST (5 MB) ...";
    {
        HINTERNET hConn = WinHttpConnect(hSess, L"speed.cloudflare.com",
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hConn) {
            HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET",
                L"/__down?bytes=5000000", NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (hReq) {
                if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS,
                        0, NULL, 0, 0, 0) &&
                    WinHttpReceiveResponse(hReq, NULL)) {
                    DWORD t0 = GetTickCount();
                    long long total = 0; DWORD rd = 0;
                    std::vector<char> dlBuf(65536);
                    while (WinHttpReadData(hReq, dlBuf.data(),
                                          (DWORD)dlBuf.size(), &rd) &&
                           rd > 0 && g_SpeedRunning)
                        total += rd;
                    DWORD elapsed = GetTickCount() - t0;
                    if (elapsed > 100 && total > 0)
                        g_SpeedResult.downloadMbps =
                            (total * 8.0) / (elapsed / 1000.0) / 1e6;
                }
                WinHttpCloseHandle(hReq);
            }
            WinHttpCloseHandle(hConn);
        }
    }

    // 3. Upload  (2 MB POST to Cloudflare speed test CDN)
    g_SpeedStatus = "UPLOAD TEST (2 MB) ...";
    {
        HINTERNET hConn = WinHttpConnect(hSess, L"speed.cloudflare.com",
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hConn) {
            HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", L"/__up",
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (hReq) {
                const DWORD upSize = 2 * 1024 * 1024;
                std::vector<char> upData(upSize, 0x41);   // 'A'
                DWORD t0 = GetTickCount();
                if (WinHttpSendRequest(hReq,
                        L"Content-Type: application/octet-stream\r\n",
                        (DWORD)-1, upData.data(), upSize, upSize, 0) &&
                    WinHttpReceiveResponse(hReq, NULL)) {
                    DWORD elapsed = GetTickCount() - t0;
                    if (elapsed > 0)
                        g_SpeedResult.uploadMbps =
                            (upSize * 8.0) / (elapsed / 1000.0) / 1e6;
                }
                WinHttpCloseHandle(hReq);
            }
            WinHttpCloseHandle(hConn);
        }
    }

    WinHttpCloseHandle(hSess);

    char buf[128];
    snprintf(buf, sizeof(buf), "DL: %.1f Mbps | UL: %.1f Mbps | Ping: %.0f ms",
        g_SpeedResult.downloadMbps,
        g_SpeedResult.uploadMbps,
        g_SpeedResult.pingMs < 0 ? 0 : g_SpeedResult.pingMs);
    g_SpeedStatus  = buf;
    g_SpeedRunning = false;
}

// ============================================================
//  NEW: CHANNEL CONGESTION MAP
// ============================================================

// Returns a compact string like:  2.4G:[*Ch6:1* Ch1:2 Ch11:3]  5G:[Ch36:2]
std::string BuildChannelMap(const std::vector<BssEntry>& bssEntries,
                             int currentChannel) {
    std::map<int,int> ch24, ch5;
    for (auto& e : bssEntries) {
        int ch = (int)e.channel;
        if (ch <= 0) continue;
        (ch <= 14 ? ch24 : ch5)[ch]++;
    }

    auto buildSeg = [&](std::map<int,int>& m) -> std::string {
        std::string s;
        int cnt = 0;
        for (auto& [ch, n] : m) {
            if (cnt++ > 6) { s += ".."; break; }
            bool cur = (ch == currentChannel);
            s += (cur ? "*" : "");
            s += "Ch" + std::to_string(ch) + ":" + std::to_string(n);
            s += (cur ? "* " : " ");
        }
        return s.empty() ? "-" : s;
    };

    std::string r = "2.4G:[" + buildSeg(ch24) + "] 5G:[" + buildSeg(ch5) + "]";
    if (r.size() > 62) r = r.substr(0, 59) + "...";
    return r;
}

// ============================================================
//  MAIN
// ============================================================

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    system("chcp 65001 > nul");
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // --- Open WLAN handle ---
    HANDLE hClient = NULL; DWORD dwV = 0;
    if (WlanOpenHandle(2, NULL, &dwV, &hClient) != ERROR_SUCCESS) return 1;

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS ||
        !pIfList || pIfList->dwNumberOfItems == 0) {
        std::cerr << "No Wi-Fi adapters found.\n";
        WlanCloseHandle(hClient, NULL); return 1;
    }

    // --- Adapter selection ---
    DWORD adapterIndex = 0;
    if (pIfList->dwNumberOfItems > 1) {
        std::cout << "Found multiple adapters:\n";
        for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++)
            std::wcout << L" [" << i+1 << L"] "
                       << pIfList->InterfaceInfo[i].strInterfaceDescription
                       << L"\n";
        std::cout << "Select (1-" << pIfList->dwNumberOfItems << "): ";
        int ch;
        if (std::cin >> ch && ch >= 1 && ch <= (int)pIfList->dwNumberOfItems)
            adapterIndex = ch - 1;
    }

    GUID    ifGuid = pIfList->InterfaceInfo[adapterIndex].InterfaceGuid;
    NET_LUID luid;
    ConvertInterfaceGuidToLuid(&ifGuid, &luid);
    std::string pcapDev = "\\Device\\NPF_" + GuidToString(ifGuid);

    // --- Initial background tasks ---
    std::thread(DnsAnalysisWorker).detach();   // DNS + ARP on startup

    // --- Traffic baselines ---
    TrafficStats startStats = GetStats(luid), last = startStats;
    std::vector<long long> rxHist, txHist;
    std::vector<int>       rssiHistory;
    const size_t           maxHist = 6;

    // --- Console setup ---
    HideCursor(); system("cls");
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    short startY = csbi.dwCursorPosition.Y;

    // Reserve dashboard height  (34 lines)
    for (int i = 0; i < 34; i++) std::cout << std::string(80, ' ') << "\n";

    // --- State tracking ---
    char   lastBssid[20]  = {};
    DWORD  lastChannel    = 0;
    DOT11_AUTH_ALGORITHM lastAuth = DOT11_AUTH_ALGO_80211_OPEN;
    int    lastRssi       = -100;
    int    disconnectCount = 0;
    bool   wasConnected   = true;
    int    loopCount      = 0;
    std::string subnetBase, localIp;

    // ============================================================
    //  MAIN LOOP  (500 ms tick)
    // ============================================================
    while (g_Running) {
        loopCount++;

        // ---- KEY HANDLING ----

        // [R]  PCAP record / stop
        if (GetAsyncKeyState('R') & 0x8000) {
            if (!g_rPressed) {
                g_rPressed = true;
                if (g_PcapRecording) g_PcapRecording = false;
                else {
                    g_PcapRecording = true; g_PcapPacketsSaved = 0;
                    std::thread(PcapWorker, pcapDev).detach();
                }
            }
        } else g_rPressed = false;

        // [S]  Network scan
        if (GetAsyncKeyState('S') & 0x8000) {
            if (!g_sPressed) {
                g_sPressed = true;
                if (!g_ScanRunning) {
                    if (subnetBase.empty())
                        GetLocalSubnet(luid, subnetBase, localIp);
                    if (!subnetBase.empty()) {
                        g_ScanRunning = true;
                        { std::lock_guard<std::mutex> lk(g_ScanMutex);
                          g_ScanResults.clear(); }
                        std::thread(PingSweepWorker, subnetBase).detach();
                    } else {
                        g_ScanStatus = "ERROR: Cannot determine local subnet";
                    }
                }
            }
        } else g_sPressed = false;

        // [T]  Speed test
        if (GetAsyncKeyState('T') & 0x8000) {
            if (!g_tPressed) {
                g_tPressed = true;
                if (!g_SpeedRunning) {
                    g_SpeedStatus = "STARTING...";
                    std::thread(SpeedTestWorker).detach();
                }
            }
        } else g_tPressed = false;

        // [D]  Re-run DNS / ARP analysis
        if (GetAsyncKeyState('D') & 0x8000) {
            if (!g_dPressed) {
                g_dPressed = true;
                std::thread(DnsAnalysisWorker).detach();
            }
        } else g_dPressed = false;

        // ---- WLAN CONNECTION QUERY ----
        bool connected = false;
        int  rssi = -100, rxRate = 0, txRate = 0, stability = 0;
        char currentBssid[20] = "00:00:00:00:00:00";
        DWORD channel = 0;
        const char* phyType  = "N/A";
        const char* authStr  = "N/A";
        DOT11_AUTH_ALGORITHM currentAuth = DOT11_AUTH_ALGO_80211_OPEN;

        PWLAN_CONNECTION_ATTRIBUTES pConn = NULL;
        DWORD connSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
        if (WlanQueryInterface(hClient, &ifGuid,
                wlan_intf_opcode_current_connection, NULL,
                &connSize, (PVOID*)&pConn, NULL) == ERROR_SUCCESS) {
            rssi      = (int)(pConn->wlanAssociationAttributes.wlanSignalQuality / 2) - 100;
            rxRate    = pConn->wlanAssociationAttributes.ulRxRate / 1000;
            txRate    = pConn->wlanAssociationAttributes.ulTxRate / 1000;
            phyType   = GetPhyTypeString(pConn->wlanAssociationAttributes.dot11PhyType);
            currentAuth = pConn->wlanSecurityAttributes.dot11AuthAlgorithm;
            authStr   = GetAuthAlgoString(currentAuth);
            auto* b   = pConn->wlanAssociationAttributes.dot11Bssid;
            sprintf_s(currentBssid,
                "%02X:%02X:%02X:%02X:%02X:%02X", b[0],b[1],b[2],b[3],b[4],b[5]);
            connected = true;
            WlanFreeMemory(pConn);
        }

        PULONG pChan = NULL; DWORD chanSize = sizeof(ULONG);
        if (WlanQueryInterface(hClient, &ifGuid,
                wlan_intf_opcode_channel_number, NULL,
                &chanSize, (PVOID*)&pChan, NULL) == ERROR_SUCCESS) {
            if (pChan) { channel = *pChan; WlanFreeMemory(pChan); }
        }
        DWORD freq = GetFrequencyFromChannel(channel);

        // ---- BSS LIST (neighbors + channel data) ----
        std::vector<BssEntry> allBss, neighbors;
        PWLAN_BSS_LIST pBss = NULL;
        if (WlanGetNetworkBssList(hClient, &ifGuid, NULL,
                dot11_BSS_type_infrastructure, FALSE, NULL, &pBss) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < pBss->dwNumberOfItems; i++) {
                auto& e = pBss->wlanBssEntries[i];
                char bssidStr[20];
                sprintf_s(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                    e.dot11Bssid[0],e.dot11Bssid[1],e.dot11Bssid[2],
                    e.dot11Bssid[3],e.dot11Bssid[4],e.dot11Bssid[5]);
                std::string ssid = "<Hidden>";
                if (e.dot11Ssid.uSSIDLength > 0)
                    ssid = std::string((char*)e.dot11Ssid.ucSSID,
                                       e.dot11Ssid.uSSIDLength);
                ULONG nCh   = e.ulChCenterFrequency / 1000;
                int   nRssi = e.lRssi;
                allBss.push_back({ ssid, nRssi, nCh });
                if (!connected || strcmp(bssidStr, currentBssid) != 0)
                    neighbors.push_back({ ssid, nRssi, nCh });
            }
            WlanFreeMemory(pBss);
        }
        std::sort(neighbors.begin(), neighbors.end(),
            [](const BssEntry& a, const BssEntry& b){ return a.rssi > b.rssi; });

        // ---- TRAFFIC STATS ----
        TrafficStats curr = GetStats(luid);
        long long instRxPPS   = (curr.inPkts  - last.inPkts)  * 2;
        long long instTxPPS   = (curr.outPkts - last.outPkts) * 2;
        double    rxMbps      = (curr.inBytes  - last.inBytes)  * 16.0 / 1e6;
        double    txMbps      = (curr.outBytes - last.outBytes) * 16.0 / 1e6;
        double    totalMbRx   = (curr.inBytes  - startStats.inBytes)  / 1048576.0;
        double    totalMbTx   = (curr.outBytes - startStats.outBytes) / 1048576.0;
        long long instErrors  = (long long)((curr.inErrors   - last.inErrors)   +
                                             (curr.outErrors  - last.outErrors));
        long long instDrops   = (long long)((curr.inDiscards - last.inDiscards) +
                                             (curr.outDiscards- last.outDiscards));
        long long totErrors   = (long long)((curr.inErrors   + curr.outErrors)  -
                                             (startStats.inErrors + startStats.outErrors));
        long long totDrops    = (long long)((curr.inDiscards + curr.outDiscards)-
                                             (startStats.inDiscards+startStats.outDiscards));
        last = curr;

        rxHist.push_back(std::max(0LL, instRxPPS));
        txHist.push_back(std::max(0LL, instTxPPS));
        if (rxHist.size() > maxHist) rxHist.erase(rxHist.begin());
        if (txHist.size() > maxHist) txHist.erase(txHist.begin());

        // ---- RSSI GRAPH & STABILITY ----
        std::string graph = connected
            ? GetRssiGraphAndStability(rssi, rssiHistory, stability)
            : "[   DISCONNECTED   ]";

        // ---- CHANNEL MAP STRING ----
        std::string chMap = BuildChannelMap(allBss, (int)channel);

        // ---- DEAUTH HEURISTIC ----
        // Spike in errors while connected = likely deauth storm
        if (connected && instErrors > 10) g_DeauthEvents++;
        if (!connected && wasConnected)   { disconnectCount++; g_DeauthEvents++; }
        wasConnected = connected;

        // ---- PERIODIC ARP CHECK  (every 8 loops = 4 s) ----
        if (loopCount % 8 == 0) {
            DnsGatewayInfo snap;
            { std::lock_guard<std::mutex> lk(g_DnsMutex); snap = g_DnsInfo; }
            if (!snap.gatewayIp.empty()) {
                std::string gwMac;
                g_ArpStatus = CheckArpSpoofing(snap.gatewayIp, gwMac);
                if (!gwMac.empty()) {
                    std::lock_guard<std::mutex> lk(g_DnsMutex);
                    g_DnsInfo.gatewayMac = gwMac;
                }
            }
        }

        // ---- THREAT STATUS ----
        std::string status = "OK - SECURE";
        std::string color  = "\x1B[32m";
        bool alert = false; int beepFreq = 1000;

        if (!connected) {
            status = "DISCONNECTED"; color = "\x1B[31m";
        } else {
            if (lastAuth != DOT11_AUTH_ALGO_80211_OPEN && currentAuth < lastAuth) {
                status = "CRITICAL: ENCRYPTION DOWNGRADE DETECTED!";
                color = "\x1B[31m"; alert = true; beepFreq = 2000;
            } else if (lastBssid[0] && strcmp(lastBssid, currentBssid) != 0) {
                status = "CRITICAL: BSSID CHANGE (EVIL TWIN?)";
                color = "\x1B[31m"; alert = true; beepFreq = 2000;
            } else if (lastRssi != -100 && abs(rssi - lastRssi) > 20) {
                status = "CRITICAL: SIGNAL ANOMALY (CLONED AP?)";
                color = "\x1B[31m"; alert = true;
            } else if (lastChannel && channel && channel != lastChannel) {
                status = "WARNING: FORCED CHANNEL SWITCH";
                color = "\x1B[33m"; alert = true;
            } else if (instDrops > 50 || instErrors > 15) {
                status = "CRITICAL: DEAUTH STORM / INTERFERENCE";
                color = "\x1B[31m"; alert = true; beepFreq = 1500;
            } else if (g_ArpStatus.find("SPOOF") != std::string::npos ||
                       g_ArpStatus.find("ALERT") != std::string::npos) {
                status = "CRITICAL: ARP SPOOFING DETECTED!";
                color = "\x1B[31m"; alert = true; beepFreq = 2000;
            } else if (g_DnsInfo.leakSuspected) {
                status = "WARNING: POSSIBLE DNS LEAK DETECTED";
                color = "\x1B[33m";
            } else if (stability < 40 && rssi > -70) {
                status = "WARNING: EXTREME SIGNAL JITTER (JAMMING?)";
                color = "\x1B[33m";
            }
        }

        if (connected) {
            strcpy_s(lastBssid, currentBssid);
            if (channel) lastChannel = channel;
            lastRssi = rssi; lastAuth = currentAuth;
        }
        if (alert) Beep(beepFreq, 150);

        // ---- SNAPSHOT SCAN RESULTS ----
        std::vector<ScanHost> scanSnap;
        { std::lock_guard<std::mutex> lk(g_ScanMutex); scanSnap = g_ScanResults; }

        // ---- SNAPSHOT DNS INFO ----
        DnsGatewayInfo dnsSnap;
        { std::lock_guard<std::mutex> lk(g_DnsMutex); dnsSnap = g_DnsInfo; }

        // ============================================================
        //  DASHBOARD RENDER
        // ============================================================
        SetCursorPosition(0, startY);

        printf("=================== Wi-Fi Analyzer v2.0 ===================\n");
        std::wcout << L" [+] Adapter: "
                   << pIfList->InterfaceInfo[adapterIndex].strInterfaceDescription
                   << L"          \n";
        printf(" [+] BSSID:   %-17s | Channel: %-3lu (%4lu MHz)    \n",
               connected ? currentBssid : "N/A", channel, freq);
        printf(" [+] Signal:  %-4d dBm %s | Sec: %-17s\n",
               connected ? rssi : 0, graph.c_str(), authStr);
        printf(" [+] Link Rx: %-4d Mbps           | PHY: %-17s  \n",
               connected ? rxRate : 0, phyType);
        printf(" [+] Stability: %-3d %%            | Link Tx: %-4d Mbps    \n",
               stability, connected ? txRate : 0);

        printf("-------------------------- Traffic -------------------------\n");
        printf(" [+] Speed  Rx: %-7.2f Mbps    | Tx: %-7.2f Mbps        \n",
               rxMbps, txMbps);
        printf(" [+] Sess.  Rx: %-7.2f MB      | Tx: %-7.2f MB          \n",
               totalMbRx, totalMbTx);
        printf(" [+] Drops: %-5lld/s (Tot:%-5lld)| Errors: %-4lld/s (Tot:%-5lld)\n",
               instDrops, totDrops, instErrors, totErrors);

        printf("-------------------- Channel Congestion -------------------\n");
        printf(" [+] %-58s\n", chMap.c_str());

        printf("--------------------- Threat Detection --------------------\n");
        {
            bool arpOk = (g_ArpStatus == "OK" || g_ArpStatus == "PENDING");
            printf(" [+] ARP: %s%-28s\x1B[0m | Deauth events: %-4d    \n",
                   arpOk ? "\x1B[32m" : "\x1B[31m",
                   g_ArpStatus.c_str(),
                   (int)g_DeauthEvents);
        }

        printf("----------------------- DNS & Gateway ----------------------\n");
        printf(" [+] Gateway: %-15s | MAC: %-17s         \n",
               dnsSnap.gatewayIp.empty()  ? "N/A" : dnsSnap.gatewayIp.c_str(),
               dnsSnap.gatewayMac.empty() ? "N/A" : dnsSnap.gatewayMac.c_str());
        {
            std::string dnsStr;
            for (size_t i = 0; i < dnsSnap.dnsServers.size() && i < 2; i++)
                dnsStr += (i ? ", " : "") + dnsSnap.dnsServers[i];
            if (dnsStr.empty()) dnsStr = "N/A";
            const char* leakCol = dnsSnap.leakSuspected ? "\x1B[31m" : "\x1B[32m";
            const char* leakTxt = dnsSnap.leakSuspected ? "SUSPECTED!" : "NONE";
            printf(" [+] DNS: %-24s | Leak: %s%-10s\x1B[0m       \n",
                   dnsStr.c_str(), leakCol, leakTxt);
        }

        printf("----------------------- Network Scan ----------------------\n");
        printf(" [%c] %-55s\n",
               g_ScanRunning ? '!' : '+', g_ScanStatus.c_str());
        for (int i = 0; i < 3; i++) {
            if (i < (int)scanSnap.size()) {
                auto& h = scanSnap[i];
                std::string ports;
                for (int p : h.openPorts) ports += std::to_string(p) + " ";
                if (ports.empty()) ports = "none";
                printf("  %d. %-15s %-15s  open: %-16s\n",
                       i+1,
                       h.ip.c_str(),
                       h.hostname.size() > 15 ? h.hostname.substr(0,15).c_str()
                                              : h.hostname.c_str(),
                       ports.size() > 16 ? ports.substr(0,16).c_str()
                                         : ports.c_str());
            } else {
                printf("                                                            \n");
            }
        }

        printf("------------------------ Speed Test -----------------------\n");
        if (g_SpeedRunning)
            printf(" [!] \x1B[33m%-55s\x1B[0m\n", g_SpeedStatus.c_str());
        else
            printf(" [+] %-55s\n", g_SpeedStatus.c_str());

        printf("----------------------- Top Neighbors ---------------------\n");
        for (int i = 0; i < 3; i++) {
            if (i < (int)neighbors.size())
                printf("  %d. %-4d dBm | Ch: %-4lu | %-30s\n",
                       i+1, neighbors[i].rssi, neighbors[i].channel,
                       neighbors[i].ssid.c_str());
            else
                printf("                                                            \n");
        }

        printf("------------------------- PCAP Dumper ----------------------\n");
        if (g_PcapRecording)
            printf(" [!] PCAP: \x1B[31m%-35s\x1B[0m [Pkts: %lld]    \n",
                   g_PcapStatusMsg.c_str(), (long long)g_PcapPacketsSaved);
        else
            printf(" [!] PCAP: \x1B[33m%-48s\x1B[0m\n", g_PcapStatusMsg.c_str());

        printf("------------------------------------------------------------\n");
        if (disconnectCount > 0)
            printf(" [*] STATUS: %s%-34s\x1B[0m [Drops: %d]   \n",
                   color.c_str(), status.c_str(), disconnectCount);
        else
            printf(" [*] STATUS: %s%-48s\x1B[0m\n", color.c_str(), status.c_str());

        printf(" Keys: [R] PCAP  [S] Scan  [T] SpeedTest  [D] DNS  [Ctrl+C] Quit\n");

        fflush(stdout);
        Sleep(500);
    }

    // ---- Cleanup ----
    g_PcapRecording = false;
    g_ScanRunning   = false;
    g_SpeedRunning  = false;
    Sleep(600);   // give threads time to exit cleanly

    SetCursorPosition(0, startY + 35);
    ShowCursor();
    std::cout << "\nCleaning up resources...\n";
    if (pIfList) WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    return 0;
}
