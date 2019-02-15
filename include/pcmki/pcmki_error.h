#ifndef PCMKI_ERROR__H
#  define PCMKI_ERROR__H

#define CMD_ERR(fmt, args...) do {              \
            crm_warn(fmt, ##args);              \
            fprintf(stderr, fmt "\n", ##args);  \
        } while(0)

#endif
