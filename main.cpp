#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <thread>
#include <conio.h>
#include <fstream>
#include <codecvt>
#include <locale>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#define SIO_RCVALL 0x98000001

//Структура заголовка IP-пакета
typedef struct IPHeader {
    UCHAR   iph_verlen;   // версия и длина заголовка
    UCHAR   iph_tos;      // тип сервиса
    USHORT  iph_length;   // длина всего пакета
    USHORT  iph_id;       // Идентификация
    USHORT  iph_offset;   // флаги и смещения
    UCHAR   iph_ttl;      // время жизни пакета
    UCHAR   iph_protocol; // протокол
    USHORT  iph_xsum;     // контрольная сумма
    ULONG   iph_src;      // IP-адрес отправителя
    ULONG   iph_dest;     // IP-адрес назначения
}IPHeader;

void start_sniffer(IPHeader *pHeader, WORD size);

std::string get_protocol_name(UCHAR aProtocol);

void save_in_file(std::ostream &logfile, IPHeader *pHeader, WORD size, char buffer[65536]);

void select_content_and_push(std::ostream &ostream, const char *buf, int size);

int main(int argc, char* argv[]) {
    /*init*/
    WSADATA wsadata;
    SOCKET sniffer;
    struct in_addr addr{};
    char btBuffer[65536]; //буфер на 64кб
    char file_name[1024];
    strcpy(file_name, "log.txt");
    bool status_file = false;
    if (argc == 2) {
        if (strcmp(argv[1],"-f") == 0)
            status_file = true;
        else{
            std::cout << "The parameter is missing" << std::endl;
        }
    } else if (argc == 3) {
        if (strcmp(argv[1],"-f") == 0) {
            status_file = true;
            memcpy(&file_name, argv[2], strlen(argv[2]));
        } else {
            std::cout << "The parameter is missing" << std::endl;
        }
    }

    //Инициализация сокетов
    if(WSAStartup (MAKEWORD(2, 2), &wsadata) != 0) {
        std::cout << "ERROR. Sockets are not initialized" << std::endl;
    } else {
        std::cout << "Sockets are initialized" << std::endl;
    }

    //Создание сокета
    sniffer = socket (AF_INET, SOCK_RAW, IPPROTO_IP);
    if(sniffer == INVALID_SOCKET) {
        std::cout << "ERROR. Socket not created" << std::endl;
    } else {
        std::cout << "Socket created" << std::endl;
    }

    CHAR szHostName[16];

    std::ofstream logfile(file_name);
    if (status_file) {
        if(!logfile.is_open()) {
            printf("ERROR. Unable to create file.");
        }
    }

    //const std::locale utf8_locale = std::locale(std::locale(), new std::codecvt_utf8<char16_t>);
    //logfile.imbue(utf8_locale);



    //Получение имени локального хоста
    if(gethostname(szHostName, sizeof(szHostName)) != 0) {
        std::cout << "ERROR. Hostname not received" << std::endl;
    } else {
        std::cout << "Hostname received" << std::endl;
    }

    //Получение информаций о локальном хосте
    HOSTENT *phe = gethostbyname(szHostName);

    if(phe == nullptr) {
        std::cout << "ERROR. Host description not received" << std::endl;
    } else {
        std::cout << "Host description received" << std::endl;

        int i = 0;
        for (i = 0; phe->h_addr_list[i] != nullptr; ++i) {
            memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
            printf("Interface Number : %d Address : %s\n",i,inet_ntoa(addr));
        }

        std::cout << "Select network interface: ";
        int index_select_in = -1;
        std::cin >> index_select_in;
        if (index_select_in == -1 || index_select_in > i) {
            return -1;
        }

        //Структура с адресом выбранного сетевого интерфейса
        SOCKADDR_IN sa; //Адрес хоста
        ZeroMemory(&sa, sizeof (sa));
        sa.sin_port = 0;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = ((struct in_addr *) phe->h_addr_list[index_select_in])->s_addr;


        //Связывание локального адреса и сокета
        if(bind(sniffer, (SOCKADDR *)&sa, sizeof(SOCKADDR)) != 0) {
            std::cout << "ERROR. The socket is not bind" << std::endl;
        } else {
            std::cout << "The socket is bind" << std::endl;

            //Включение promiscuous mode
            DWORD flag = TRUE;     //Флаг PROMISC Вкл/Выкл

            if(ioctlsocket(sniffer, SIO_RCVALL, &flag) == SOCKET_ERROR) {
                std::cout << "ERROR. Promiscuous mode is not enabled" << std::endl;
            } else {
                std::cout << "Promiscuous mode is enabled" << std::endl;
            }
        }

       while(!kbhit()) {
           if (recv(sniffer, btBuffer, sizeof(btBuffer), 0) >= sizeof(IPHeader)) {
               auto *hdr = (IPHeader *) btBuffer;

               WORD size = (hdr->iph_length << 8) + (hdr->iph_length >> 8);

               //Получен пакет?
               if (size >= 60 && size <= 1500) {
                   start_sniffer (hdr, size);
                   if (status_file)
                       save_in_file(logfile, hdr, size, btBuffer);
               }
           }
       }
    }

    closesocket(sniffer);
    WSACleanup();
    return 0;
}

void save_in_file(std::ostream &logfile, IPHeader *pHeader, WORD size, char buffer[65536]) {
    IN_ADDR ia;

    logfile << "--Packet begin--\r\n";
    logfile << "From ";
    ia.s_addr = pHeader->iph_src;
    logfile << inet_ntoa(ia) << "\n";

    logfile << "To ";
    ia.s_addr = pHeader->iph_dest;
    logfile << inet_ntoa(ia) << "\n";

    logfile << "ID: ";
    logfile << pHeader->iph_id << "\n";

    logfile << "Protocol: ";
    logfile << get_protocol_name(pHeader->iph_protocol) << "\n";

    logfile << "Packet length: ";
    logfile << size << "\n";
    logfile << "\n";

    char contents_buf[size - sizeof(IPHeader) * 2];
    logfile << "Contents:\r\n\r\n";
    memcpy(&contents_buf, &buffer[sizeof(IPHeader) * 2], size - sizeof(IPHeader) * 2);

    logfile << (std::string)contents_buf;

    logfile << "\n\r--Packet end--\r\n";
}

void start_sniffer(IPHeader *pHeader, WORD size) {
    IN_ADDR ia;
    std::cout << "From ";
    ia.s_addr = pHeader->iph_src;
    std::cout << inet_ntoa(ia) << "\t";

    std::cout << "To ";
    ia.s_addr = pHeader->iph_dest;
    std::cout << inet_ntoa(ia) << "\t";

    std::cout << "ID: ";
    std::cout << pHeader->iph_id << "\t";

    std::cout << "Protocol: ";
    std::cout << get_protocol_name(pHeader->iph_protocol) << "\t";

    std::cout << "Packet length: ";
    printf("%d\t", size);
    std::cout << std::endl;
}

std::string get_protocol_name(UCHAR aProtocol) {
    switch (aProtocol) {
        case IPPROTO_IP:
            return "IP";

        case IPPROTO_ICMP:
            return "ICMP";

        case IPPROTO_IGMP:
            return "IGMP";

        case IPPROTO_GGP:
            return "GGP";

        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_PUP:
            return "PUP";

        case IPPROTO_UDP:
            return "UDP";

        case IPPROTO_IDP:
            return "IDP";

        case IPPROTO_IPV6:
            return "IPv6";

        case IPPROTO_ND:
            return "ND";

        case IPPROTO_ICLFXBM:
            return "ICLFXBM";

        case IPPROTO_ICMPV6:
            return "ICMPv6";
        default:
            return "";
    }
}
