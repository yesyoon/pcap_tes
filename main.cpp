#include <pcap.h>
#include <stdio.h>

#define ETHER_ADDR_LEN 6
#define ETHER_SIZE 14

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char *);
void print_ip(const u_char *);
void print_port_data(const u_char *);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_char* TCP_HEADER;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if ((packet[12] << 8) | packet [13] == 0x0800) { // IP CHECK //printf("IP : 0x0%x\n",(packet[12] << 8) | packet [13]);
        if (packet[23] == 0x06) { //TCP CHECK //printf("TCP : %x\n", packet[23]);
            print_mac(packet);
            print_ip(packet);
            print_port_data(packet);
            //printf("%u bytes cpatured\n",(header->caplen));
            //printf("TCP_HEADER : %d \n", (packet[46] >> 4) * 4);
            printf("==============================================\n");
            }
       }
  }
  pcap_close(handle);
  return 0;

}
void print_port_data(const u_char *port_packet){
    u_int8_t IP_HL= (u_int8_t(port_packet[14]) & 0x0F)*4;//IP HEADER LENGTH
    u_int8_t TCP_HL = (port_packet[46] >> 4) * 4;
    u_int8_t total_L = (port_packet[16] << 8) | port_packet[17];


    for (int i = 0; i < 3; i+=2){
        if(i == 0) printf("Sport : ");
        if(i == 2) printf("Dport : ");
        printf("%d\n",(port_packet[ETHER_SIZE + IP_HL + i] << 8) | (port_packet[ETHER_SIZE + IP_HL + i + 1]));
    }



    printf("TCP DATA : ");
    for (int k = 0; k < 10 ; k++) {
        if (ETHER_SIZE + IP_HL + TCP_HL + k > total_L){
            printf("NULL");
            break;
        }

        printf("%x ", port_packet[ETHER_SIZE + IP_HL + TCP_HL + k]);
        //printf("%c", port_packet[ETHER_SIZE + IP_HL + TCP_HL + k]);
    }
    printf("\n");
    //printf("Data Length : %d\n",total_L - (ETHER_SIZE + IP_HL + TCP_HL));
    if (ETHER_SIZE + IP_HL + TCP_HL < total_L){
        printf("Data Length : %d\n", ((port_packet[ETHER_SIZE + IP_HL + TCP_HL + 3] << 8) | port_packet[ETHER_SIZE + IP_HL + TCP_HL + 4]) + 5);
    }


}
void print_mac(const u_char *mac_packet){
    printf("SMAC : ");
    for(int i = 6; i < ETHER_ADDR_LEN + 6; i++){
            printf("%02x", mac_packet[i]);
                if (i < ETHER_ADDR_LEN + 5) printf(":");
                if (i == ETHER_ADDR_LEN + 5) printf("\n");
    }
    printf("DMAC : ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++){
            printf("%02x", mac_packet[i]);
                if (i < ETHER_ADDR_LEN - 1) printf(":");
                if (i == ETHER_ADDR_LEN-1) printf("\n");
    }

}

void print_ip(const u_char *ip_packet){
    for (int i = 26; i < 34; i++){
        if (i == 26) printf("SIP: ");
        if (i == 30) printf("DIP: ");
            printf("%d", ip_packet[i]);
                if(i < 29 || (i >= 30 && i < 33)) printf(".");
                if (i == 29 || i == 33) printf("\n");

    }
}


