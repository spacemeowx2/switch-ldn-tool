#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
#include <unistd.h>

int main(int arg, const char** argv) {
    if (arg != 3) {
        printf("usage:\n  %s interface filename\n", argv[0]);
        return 1;
    }
    int rc;
    pcap_t *dev;
    char err_buf[PCAP_ERRBUF_SIZE];
    uint8_t *buf;
    size_t file_size;

    FILE* file = fopen(argv[2], "rb");
    if (!file) {
        printf("Error: open file\n");
        return 1;
    }

    fseek(file, 0L, SEEK_END);
    file_size = ftell(file);
    rewind(file);
    printf("filesize: %ld\n", file_size);

    buf = malloc(file_size);
    fread(buf, file_size, 1, file);
    dev = pcap_create(argv[1], err_buf);
    if (!dev) {
        printf("Error pcap_create: %s\n", err_buf);
        return 1;
    }

    pcap_set_snaplen(dev, 65535);
    pcap_set_promisc(dev, 1);
    pcap_set_timeout(dev, 500);
    pcap_set_buffer_size(dev, 1024 * 1024);
    rc = pcap_set_rfmon(dev, 1);
    if (rc != 0) {
        printf("Error pcap_set_rfmon: %d\n", rc);
        return 1;
    }
    rc = pcap_activate(dev);
    if (rc != 0) {
        printf("Error pcap_activate: %d\n", rc);
        if (rc == -1) {
            printf("  %s\n", pcap_geterr(dev));
        }
    }

    unsigned char datalink = pcap_datalink(dev);
    printf("datalink: %u\n", datalink);

    puts("Begin sending");
    while (1) {
        rc = pcap_sendpacket(dev, buf, file_size);
        if (rc != 0) {
            printf("rc: %d\n", rc);
        }
        // 100ms
        usleep(1000000 / 10);
    }
    puts("Stop sending");

    pcap_close(dev);
    return 0;
}
