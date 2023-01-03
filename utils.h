#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

void fill_ip_table(void);
char *get_ip_protocol(uint8_t);
void print_data(uint8_t*, ssize_t);
void str_to_mac(const char *, uint8_t*);

#endif

