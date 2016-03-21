#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct _RingBuffer {
    uint8_t *mem;

    size_t length;
    int32_t read_pos;
    int32_t write_pos;
} RingBuffer;

RingBuffer *CreateRingBuffer(size_t length)
{
    RingBuffer *ring;
    if (length & (length - 1)) return NULL; // length *MUST* be a power of 2!
    ring = malloc(sizeof(*ring) + (length * sizeof(float)));
    if(ring) { 
        ring->mem = (uint8_t*)(ring+1);
        ring->length = length;
        ring->read_pos = 0;
        ring->write_pos = 0;
    }
    return ring;
}

void DestroyRingBuffer(RingBuffer *ring)
{
    if(ring) {
        free(ring);
    }
}

size_t RingBufferSize(RingBuffer *ring)
{
    return ((ring->write_pos-ring->read_pos+ring->length) & (ring->length - 1));
}

void WriteRingBuffer(RingBuffer *ring, const uint8_t *data, size_t len)
{
    int32_t remain = (ring->read_pos-ring->write_pos-1+ring->length) & (ring->length - 1);
    if(remain < len) len = remain;

    if(len > 0) {
        remain = ring->length - ring->write_pos;
        if(remain < len) {
            memcpy(ring->mem+(ring->write_pos*sizeof(float)), data,
                   remain*sizeof(float));
            memcpy(ring->mem, data+(remain*sizeof(float)),
                   (len-remain)*sizeof(float));
        } else {
            memcpy(ring->mem+(ring->write_pos*sizeof(float)), data,
                   len*sizeof(float));
        }

        ring->write_pos += len;
        ring->write_pos &= (ring->length - 1);
    }
}

void ReadRingBuffer(RingBuffer *ring, uint8_t *data, size_t len)
{
    int32_t remain = ring->length - ring->read_pos;
    if(remain < len) {
        memcpy(data, ring->mem+(ring->read_pos*sizeof(float)), remain*sizeof(float));
        memcpy(data+(remain*sizeof(float)), ring->mem, (len-remain)*sizeof(float));
    } else {
        memcpy(data, ring->mem+(ring->read_pos*sizeof(float)), len*sizeof(float));
    }

    ring->read_pos += len;
    ring->read_pos &= (ring->length - 1);
}

