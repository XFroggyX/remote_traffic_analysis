#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <thread>
#include <conio.h>


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

void print_stat(IPHeader *pHeader, WORD size, char string[65536]);

std::string get_protocol_name(UCHAR aProtocol);

int main() {
    /*init*/
    WSADATA wsadata;
    SOCKET s;
    char btBuffer[65536]; //буфер на 64кб

    //Инициализация сокетов
    if(WSAStartup (MAKEWORD(2, 2), &wsadata) != 0) {
        std::cout << "ERROR. Sockets are not initialized" << std::endl;
    } else {
        std::cout << "Sockets are initialized" << std::endl;
    }

    //Создание сокета
    s = socket (AF_INET, SOCK_RAW, IPPROTO_IP);
    if(s == INVALID_SOCKET) {
        std::cout << "ERROR. Socket not created" << std::endl;
    } else {
        std::cout << "Socket created" << std::endl;
    }

    CHAR szHostName[16];

    //Получение имени локального хоста
    if(gethostname (szHostName, sizeof szHostName) != 0) {
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

        SOCKADDR_IN sa; //Адрес хоста

        ZeroMemory(&sa, sizeof (sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = ((struct in_addr *) phe->h_addr_list[0])->s_addr;

        //Связывание локального адреса и сокета
        if(bind (s, (SOCKADDR *) &sa, sizeof (SOCKADDR)) != 0) {
            std::cout << "ERROR. The socket is not bind" << std::endl;
        } else {
            std::cout << "The socket is bind" << std::endl;

            //Включение promiscuous mode
            DWORD flag = TRUE;     //Флаг PROMISC Вкл/Выкл

            if(ioctlsocket (s, SIO_RCVALL, &flag) == SOCKET_ERROR) {
                std::cout << "ERRPR. Promiscuous mode is not enabled" << std::endl;
            } else {
                std::cout << "Promiscuous mode is enabled" << std::endl;
            }
        }
       while(!kbhit()) {
           if (recv(s, btBuffer, sizeof(btBuffer), 0) >= sizeof(IPHeader)) {
               IPHeader *hdr = (IPHeader *) btBuffer;

               WORD size = (hdr->iph_length << 8) + (hdr->iph_length >> 8);

               //Получен пакет?
               //if (size >= 60 && size <= 1500) {
               print_stat (hdr, size, btBuffer);
               //}
           }
       }
    }


    return 0;
}

void print_stat(IPHeader *pHeader, WORD size, char btBuffer[65536]) {
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


    std::cout << std::endl << std::endl;
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
