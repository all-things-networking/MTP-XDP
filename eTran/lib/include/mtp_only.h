#ifndef MTP_ONLY_H
#define MTP_ONLY_H

#include <cstdint>

struct app_event {
    unsigned int data_size;
};

extern uint32_t stream_id_bitmap[256];

#endif