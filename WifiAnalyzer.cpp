#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <wlanapi.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <iostream>
#include <vector>
#include <numeric>
#include <string>
#include <atomic>
#include <iomanip>
#include <algorithm>
#include <thread>

// Подключаем libpcap
#define HAVE_REMOTE
#include <pcap.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
// Подключаем либы pcap (vcpkg обычно использует pcap.lib или wpcap.lib)
#pragma comment(lib, "pcap.lib")

// Глобальные флаги
std::atomic<bool> g_Running(true);
std::atomic<bool> g_PcapRecording(false);
std::atomic<long long> g_PcapPacketsSaved(0);
std::string g_PcapStatusMsg = "READY (Press 'R' to Start)";

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        g_Running = false;
        g_PcapRecording = false; // Останавливаем запись при выходе
        return TRUE;
    }
    return FALSE;
}

void SetCursorPosition(int x, int y) {
    static const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    std::cout.flush();
    COORD coord = { (SHORT)x, (SHORT)y };
    SetConsoleCursorPosition(hOut, coord);
}

void HideCursor() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hOut, &cursorInfo);
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(hOut, &cursorInfo);
}

void ShowCursor() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hOut, &cursorInfo);
    cursorInfo.bVisible = TRUE;
    SetConsoleCursorInfo(hOut, &cursorInfo);
}

// Конвертация GUID в строку для PCAP
std::string GuidToString(GUID guid) {
    char guidStr[40];
    snprintf(guidStr, sizeof(guidStr),
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(guidStr);
}

// Фоновый поток для перехвата пакетов и записи в файл
void PcapWorker(std::string deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* fp = pcap_open_live(deviceName.c_str(), 65536, 1, 1000, errbuf);

    if (!fp) {
        g_PcapStatusMsg = "ERROR: Npcap driver not found or access denied!";
        g_PcapRecording = false;
        return;
    }

    pcap_dumper_t* dumpfp = pcap_dump_open(fp, "wifi_dump.pcap");
    if (!dumpfp) {
        g_PcapStatusMsg = "ERROR: Cannot create wifi_dump.pcap file!";
        pcap_close(fp);
        g_PcapRecording = false;
        return;
    }

    g_PcapStatusMsg = "RECORDING to wifi_dump.pcap...";
    struct pcap_pkthdr* header;
    const u_char* pkt_data;

    while (g_PcapRecording && g_Running) {
        int res = pcap_next_ex(fp, &header, &pkt_data);
        if (res == 1) { // Пакет успешно пойман
            pcap_dump((u_char*)dumpfp, header, pkt_data);
            g_PcapPacketsSaved++;
        }
    }

    pcap_dump_close(dumpfp);
    pcap_close(fp);
    g_PcapStatusMsg = "STOPPED. Saved to wifi_dump.pcap.";
}

DWORD GetFrequencyFromChannel(DWORD channel) {
    if (channel == 0) return 0;
    if (channel == 14) return 2484;
    if (channel > 0 && channel <= 13) return 2407 + (channel * 5);
    if (channel >= 32 && channel <= 173) return 5000 + (channel * 5);
    if (channel >= 1 && channel <= 233) return 5950 + (channel * 5);
    return 0;
}

struct TrafficStats {
    unsigned long long inPkts, outPkts;
    unsigned long long inBytes, outBytes;
    unsigned long long inErrors, outErrors;
    unsigned long long inDiscards, outDiscards;
};

TrafficStats GetStats(NET_LUID luid) {
    MIB_IF_ROW2 row;
    ZeroMemory(&row, sizeof(MIB_IF_ROW2));
    row.InterfaceLuid = luid;
    if (GetIfEntry2(&row) == NO_ERROR) {
        return {
            row.InUcastPkts + row.InNUcastPkts, row.OutUcastPkts + row.OutNUcastPkts,
            row.InOctets, row.OutOctets,
            row.InErrors, row.OutErrors,
            row.InDiscards, row.OutDiscards
        };
    }
    return { 0, 0, 0, 0, 0, 0, 0, 0 };
}

const char* GetPhyTypeString(DOT11_PHY_TYPE type) {
    switch (type) {
    case dot11_phy_type_erp: return "802.11g";
    case dot11_phy_type_ht:  return "802.11n (Wi-Fi 4)";
    case dot11_phy_type_vht: return "802.11ac (Wi-Fi 5)";
    case dot11_phy_type_he:  return "802.11ax (Wi-Fi 6)";
    default: return "Legacy/Other";
    }
}

// ИСПРАВЛЕННАЯ ФУНКЦИЯ (убрана ошибка case 3)
const char* GetAuthAlgoString(DOT11_AUTH_ALGORITHM algo) {
    switch (algo) {
    case DOT11_AUTH_ALGO_80211_OPEN: return "OPEN";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY: return "WEP";
    case DOT11_AUTH_ALGO_WPA: return "WPA";
    case DOT11_AUTH_ALGO_WPA_PSK: return "WPA-PSK";
    case DOT11_AUTH_ALGO_RSNA: return "WPA2/WPA3-ENT";
    case DOT11_AUTH_ALGO_RSNA_PSK: return "WPA2-PSK";
        // Безопасная проверка макросов из новых SDK
#ifdef DOT11_AUTH_ALGO_WPA3_SAE
    case DOT11_AUTH_ALGO_WPA3_SAE: return "WPA3-SAE";
#endif
#ifdef DOT11_AUTH_ALGO_OWE
    case DOT11_AUTH_ALGO_OWE: return "OWE";
#endif
    default: return "UNKNOWN";
    }
}

std::string GetRssiGraphAndStability(int rssi, std::vector<int>& history, int& stabilityScore) {
    history.push_back(rssi);
    if (history.size() > 10) history.erase(history.begin());

    int minRssi = *std::min_element(history.begin(), history.end());
    int maxRssi = *std::max_element(history.begin(), history.end());

    int diff = maxRssi - minRssi;
    stabilityScore = 100 - (diff * 6);
    if (stabilityScore < 0) stabilityScore = 0;
    if (stabilityScore > 100) stabilityScore = 100;

    int bars = (rssi + 100) / 6;
    if (bars < 0) bars = 0;
    if (bars > 10) bars = 10;

    return "[" + std::string(bars, '|') + std::string(10 - bars, ' ') + "]";
}

struct BssEntry {
    std::string ssid;
    int rssi;
    ULONG channel;
};

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    system("chcp 65001 > nul");
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    HANDLE hClient = NULL;
    DWORD dwV = 0;
    if (WlanOpenHandle(2, NULL, &dwV, &hClient) != ERROR_SUCCESS) return 1;

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS || !pIfList || pIfList->dwNumberOfItems == 0) {
        std::cerr << "Wi-Fi адаптеры не найдены.\n";
        WlanCloseHandle(hClient, NULL);
        return 1;
    }

    DWORD adapterIndex = 0;
    if (pIfList->dwNumberOfItems > 1) {
        std::cout << "Найдены несколько адаптеров:\n";
        for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
            std::wcout << L" [" << i + 1 << L"] " << pIfList->InterfaceInfo[i].strInterfaceDescription << L"\n";
        }
        std::cout << "Выберите (1-" << pIfList->dwNumberOfItems << "): ";
        int choice;
        if (std::cin >> choice && choice >= 1 && choice <= (int)pIfList->dwNumberOfItems) adapterIndex = choice - 1;
    }

    GUID interfaceGuid = pIfList->InterfaceInfo[adapterIndex].InterfaceGuid;
    NET_LUID luid;
    ConvertInterfaceGuidToLuid(&interfaceGuid, &luid);

    // Формируем имя устройства для PCAP (Npcap формат: \Device\NPF_{GUID})
    std::string pcapDeviceName = "\\Device\\NPF_" + GuidToString(interfaceGuid);

    TrafficStats startStats = GetStats(luid);
    TrafficStats last = startStats;

    std::vector<long long> rxPpsHistory, txPpsHistory;
    std::vector<int> rssiHistory;
    const size_t maxHistory = 6;

    HideCursor();
    system("cls");
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    short startY = csbi.dwCursorPosition.Y;

    // Резервируем место под расширенный дашборд
    for (int i = 0; i < 22; i++) std::cout << std::string(80, ' ') << "\n";

    char lastBssid[20] = { 0 };
    DWORD lastChannel = 0;
    DOT11_AUTH_ALGORITHM lastAuth = DOT11_AUTH_ALGO_80211_OPEN;
    int lastRssiForJumpCheck = -100;
    int disconnectCount = 0;
    bool wasConnected = true;
    bool r_key_pressed = false;

    while (g_Running) {
        // УПРАВЛЕНИЕ: Отслеживание нажатия клавиши 'R' для записи PCAP
        if (GetAsyncKeyState('R') & 0x8000) {
            if (!r_key_pressed) {
                r_key_pressed = true;
                if (g_PcapRecording) {
                    g_PcapRecording = false; // Останавливаем поток
                }
                else {
                    g_PcapRecording = true;
                    g_PcapPacketsSaved = 0;
                    std::thread(PcapWorker, pcapDeviceName).detach();
                }
            }
        }
        else {
            r_key_pressed = false;
        }

        bool connected = false;
        int rssi = -100, rxRate = 0, txRate = 0, stability = 0;
        char currentBssid[20] = "00:00:00:00:00:00";
        DWORD channel = 0;
        const char* phyType = "N/A";
        const char* authStr = "N/A";
        DOT11_AUTH_ALGORITHM currentAuth = DOT11_AUTH_ALGO_80211_OPEN;

        PWLAN_CONNECTION_ATTRIBUTES pConn = NULL;
        DWORD connSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
        if (WlanQueryInterface(hClient, &interfaceGuid, wlan_intf_opcode_current_connection, NULL, &connSize, (PVOID*)&pConn, NULL) == ERROR_SUCCESS) {
            rssi = (int)(pConn->wlanAssociationAttributes.wlanSignalQuality / 2) - 100;
            rxRate = pConn->wlanAssociationAttributes.ulRxRate / 1000;
            txRate = pConn->wlanAssociationAttributes.ulTxRate / 1000;
            phyType = GetPhyTypeString(pConn->wlanAssociationAttributes.dot11PhyType);
            currentAuth = pConn->wlanSecurityAttributes.dot11AuthAlgorithm;
            authStr = GetAuthAlgoString(currentAuth);

            sprintf_s(currentBssid, "%02X:%02X:%02X:%02X:%02X:%02X",
                pConn->wlanAssociationAttributes.dot11Bssid[0], pConn->wlanAssociationAttributes.dot11Bssid[1],
                pConn->wlanAssociationAttributes.dot11Bssid[2], pConn->wlanAssociationAttributes.dot11Bssid[3],
                pConn->wlanAssociationAttributes.dot11Bssid[4], pConn->wlanAssociationAttributes.dot11Bssid[5]);
            connected = true;
            WlanFreeMemory(pConn);
        }

        PULONG pChannel = NULL;
        DWORD chanSize = sizeof(ULONG);
        if (WlanQueryInterface(hClient, &interfaceGuid, wlan_intf_opcode_channel_number, NULL, &chanSize, (PVOID*)&pChannel, NULL) == ERROR_SUCCESS) {
            if (pChannel) { channel = *pChannel; WlanFreeMemory(pChannel); }
        }
        DWORD frequency = GetFrequencyFromChannel(channel);

        std::vector<BssEntry> topNeighbors;
        PWLAN_BSS_LIST pBssList = NULL;
        if (WlanGetNetworkBssList(hClient, &interfaceGuid, NULL, dot11_BSS_type_infrastructure, FALSE, NULL, &pBssList) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < pBssList->dwNumberOfItems; i++) {
                char bssidStr[20];
                sprintf_s(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                    pBssList->wlanBssEntries[i].dot11Bssid[0], pBssList->wlanBssEntries[i].dot11Bssid[1],
                    pBssList->wlanBssEntries[i].dot11Bssid[2], pBssList->wlanBssEntries[i].dot11Bssid[3],
                    pBssList->wlanBssEntries[i].dot11Bssid[4], pBssList->wlanBssEntries[i].dot11Bssid[5]);

                if (connected && strcmp(bssidStr, currentBssid) == 0) continue;

                std::string ssidName = "<Hidden>";
                if (pBssList->wlanBssEntries[i].dot11Ssid.uSSIDLength > 0) {
                    ssidName = std::string((char*)pBssList->wlanBssEntries[i].dot11Ssid.ucSSID, pBssList->wlanBssEntries[i].dot11Ssid.uSSIDLength);
                }

                ULONG nCh = pBssList->wlanBssEntries[i].ulChCenterFrequency / 1000;
                int nRssi = pBssList->wlanBssEntries[i].lRssi;
                topNeighbors.push_back({ ssidName, nRssi, nCh });
            }
            WlanFreeMemory(pBssList);
        }
        std::sort(topNeighbors.begin(), topNeighbors.end(), [](const BssEntry& a, const BssEntry& b) { return a.rssi > b.rssi; });

        TrafficStats current = GetStats(luid);
        long long instRxPPS = (current.inPkts - last.inPkts) * 2;
        long long instTxPPS = (current.outPkts - last.outPkts) * 2;
        double rxMbps = (current.inBytes - last.inBytes) * 16.0 / 1000000.0;
        double txMbps = (current.outBytes - last.outBytes) * 16.0 / 1000000.0;

        double totalMbRx = (current.inBytes - startStats.inBytes) / 1048576.0;
        double totalMbTx = (current.outBytes - startStats.outBytes) / 1048576.0;

        long long instErrors = (current.inErrors - last.inErrors) + (current.outErrors - last.outErrors);
        long long instDiscards = (current.inDiscards - last.inDiscards) + (current.outDiscards - last.outDiscards);
        long long totalErrors = (current.inErrors + current.outErrors) - (startStats.inErrors + startStats.outErrors);
        long long totalDiscards = (current.inDiscards + current.outDiscards) - (startStats.inDiscards + startStats.outDiscards);
        last = current;

        rxPpsHistory.push_back(instRxPPS > 0 ? instRxPPS : 0);
        txPpsHistory.push_back(instTxPPS > 0 ? instTxPPS : 0);
        if (rxPpsHistory.size() > maxHistory) rxPpsHistory.erase(rxPpsHistory.begin());
        if (txPpsHistory.size() > maxHistory) txPpsHistory.erase(txPpsHistory.begin());
        long long avgRxPPS = std::accumulate(rxPpsHistory.begin(), rxPpsHistory.end(), 0LL) / rxPpsHistory.size();
        long long avgTxPPS = std::accumulate(txPpsHistory.begin(), txPpsHistory.end(), 0LL) / txPpsHistory.size();

        std::string graphStr = connected ? GetRssiGraphAndStability(rssi, rssiHistory, stability) : "[   DISCONNECTED   ]";

        std::string status = "OK - SECURE";
        std::string color = "\x1B[32m";
        bool alert = false;
        int beepFreq = 1000;

        if (!connected && wasConnected) disconnectCount++;
        wasConnected = connected;

        if (!connected) {
            status = "DISCONNECTED"; color = "\x1B[31m";
        }
        else {
            if (lastAuth != DOT11_AUTH_ALGO_80211_OPEN && currentAuth < lastAuth) {
                status = "CRITICAL: ENCRYPTION DOWNGRADE DETECTED!"; color = "\x1B[31m"; alert = true; beepFreq = 2000;
            }
            else if (lastBssid[0] != '\0' && strcmp(lastBssid, currentBssid) != 0) {
                status = "CRITICAL: BSSID SPOOFING (EVIL TWIN)"; color = "\x1B[31m"; alert = true; beepFreq = 2000;
            }
            else if (lastRssiForJumpCheck != -100 && abs(rssi - lastRssiForJumpCheck) > 20) {
                status = "CRITICAL: SIGNAL ANOMALY (CLONED AP?)"; color = "\x1B[31m"; alert = true;
            }
            else if (lastChannel != 0 && channel != 0 && channel != lastChannel) {
                status = "WARNING: FORCED CHANNEL SWITCH"; color = "\x1B[33m"; alert = true;
            }
            else if (instDiscards > 50 || instErrors > 15) {
                status = "CRITICAL: DEAUTH STORM / INTERFERENCE"; color = "\x1B[31m"; alert = true; beepFreq = 1500;
            }
            else if (rssi > -65 && avgTxPPS > 5 && avgRxPPS <= 1) {
                status = "CRITICAL: RF JAMMING / DEAD LINK"; color = "\x1B[31m"; alert = true;
            }
            else if (stability < 40 && rssi > -70) {
                status = "WARNING: EXTREME SIGNAL JITTER (JAMMING?)"; color = "\x1B[33m";
            }
        }

        if (connected) {
            strcpy_s(lastBssid, currentBssid);
            if (channel != 0) lastChannel = channel;
            lastRssiForJumpCheck = rssi;
            lastAuth = currentAuth;
        }
        if (alert) Beep(beepFreq, 150);

        // ОТРИСОВКА ДАШБОРДА
        SetCursorPosition(0, startY);

        printf("====================== Wi-Fi Analyzer ======================\n");
        std::wcout << L" [+] Adapter: " << pIfList->InterfaceInfo[adapterIndex].strInterfaceDescription << L"          \n";
        printf(" [+] BSSID:   %-17s | Channel: %-3lu (%4lu MHz)    \n", connected ? currentBssid : "N/A", channel, frequency);
        printf(" [+] Signal:  %-4d dBm %-10s | Sec:     %-15s \n", connected ? rssi : 0, graphStr.c_str(), authStr);
        printf(" [+] Link Rx: %-4d Mbps           | PHY:     %-15s \n", connected ? rxRate : 0, phyType);
        printf(" [+] Stability: %-3d %%            | Link Tx: %-4d Mbps      \n", stability, connected ? txRate : 0);
        printf("--------------------------- Traffic ------------------------\n");
        printf(" [+] Speed  Rx: %-7.2f Mbps    | Tx:      %-7.2f Mbps    \n", rxMbps, txMbps);
        printf(" [+] Sess.  Rx: %-7.2f MB      | Tx:      %-7.2f MB      \n", totalMbRx, totalMbTx);
        printf(" [+] Drops: %-4lld/s (Tot: %-5lld) | Errors: %-4lld/s (Tot: %-5lld)\n", instDiscards, totalDiscards, instErrors, totalErrors);
        printf("------------------------ Top Neighbors ---------------------\n");

        for (int i = 0; i < 3; i++) {
            if (i < topNeighbors.size()) {
                printf("  %d. %-4d dBm | Ch: %-4lu | %-30s\n", i + 1, topNeighbors[i].rssi, topNeighbors[i].channel, topNeighbors[i].ssid.c_str());
            }
            else {
                printf("                                                            \n");
            }
        }

        // ВЫВОД СТАТУСА СНИФФЕРА PCAP
        printf("------------------------- PCAP Dumper ----------------------\n");
        if (g_PcapRecording) {
            printf(" [!] PCAP: \x1B[31m%-35s\x1B[0m [Pkts: %lld]\n", g_PcapStatusMsg.c_str(), (long long)g_PcapPacketsSaved);
        }
        else {
            printf(" [!] PCAP: \x1B[33m%-48s\x1B[0m\n", g_PcapStatusMsg.c_str());
        }

        printf("------------------------------------------------------------\n");
        if (disconnectCount > 0) {
            printf(" [*] STATUS: %s%-35s\x1B[0m[Drops: %d]\n", color.c_str(), status.c_str(), disconnectCount);
        }
        else {
            printf(" [*] STATUS: %s%-48s\x1B[0m\n", color.c_str(), status.c_str());
        }

        fflush(stdout);
        Sleep(500);
    }

    // Завершение работы
    g_PcapRecording = false; // Сообщаем потоку pcap завершиться
    Sleep(500); // Даем потоку время закрыть файл

    SetCursorPosition(0, startY + 23);
    ShowCursor();
    std::cout << "\nОчистка ресурсов...\n";

    if (pIfList) WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    return 0;
}