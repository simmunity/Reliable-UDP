#define VS_MINLEN    4
#define VS_FILENAMELENGTH 128
#define VS_MAXDATA    128

#define VS_TYPE_BEGIN    1
#define VS_TYPE_DATA    2
#define VS_TYPE_END     3

typedef struct vsftp_t {
  uint32_t vs_type;
  union {
    char vs_filename[VS_FILENAMELENGTH];
    uint8_t vs_data[VS_MAXDATA];
  } vs_info;
}vsftp;
