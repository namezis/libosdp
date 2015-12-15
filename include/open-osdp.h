/*
  open-osdp.h - definitions for open osdp

  (C)Copyright 2014-2015 Smithee,Spelvin,Agnew & Plinge, Inc.

  Support provided by the Security Industry Association
  http://www.securityindustry.org

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0
 
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


#include <termios.h>


#define EQUALS ==


#define C_FALSE (0)
#define C_TRUE (1)
#define C_STRING_MX (1024)


// OSDP defined constants
#define C_SOM (0x53)

#define OSDP_DEST_CP (0x00)

#define OSDP_KEY_SCBK_D (0)
#define OSDP_SEC_SCS_11 (0x11)
#define OSDP_SEC_SCS_12 (0x12)
#define OSDP_SEC_SCS_13 (0x13)

// OSDP commands
// 0x6c - 0x 6f
// 0x70 - 0x79
// 0x80
// 0xA0 - 0xA1
// replies 0x40 41 45 46 48-4B 50-58 76 78 90 79 b1
#define OSDP_POLL     (0x60)
#define OSDP_ID       (0x61)
#define OSDP_CAP      (0x62)
#define OSDP_DIAG     (0x63)
#define OSDP_LSTAT    (0x64)
#define OSDP_ISTAT    (0x65)
#define OSDP_OSTAT    (0x66)
#define OSDP_RSTAT    (0x67)
#define OSDP_OUT      (0x68)
#define OSDP_LED      (0x69)
#define OSDP_BUZ      (0x6A)
#define OSDP_TEXT     (0x6B)
#define OSDP_TDSET    (0x6D)
#define OSDP_COMSET   (0x6E)
#define OSDP_DATA     (0x6F)
#define OSDP_PROMPT   (0x71)
#define OSDP_BIOREAD  (0x73)
#define OSDP_KEYSET   (0x75)
#define OSDP_CHLNG    (0x76)
#define OSDP_MFG      (0x80)

#define OSDP_ACK      (0x40)
#define OSDP_NAK      (0x41)
#define OSDP_PDID     (0x45)
#define OSDP_PDCAP    (0x46)
#define OSDP_LSTATR   (0x48)
#define OSDP_RSTATR   (0x4b)
#define OSDP_RAW      (0x50)
#define OSDP_KEYPAD   (0x53)
#define OSDP_COM      (0x54)
#define OSDP_CCRYPT   (0x76)
#define OSDP_SCRYPT   (0x77)
#define OSDP_BUSY     (0x79) // yes it's a reply
#define OSDP_MFGREP   (0x90)

#define OSDP_MENU_TOP     (0x0000)
#define OSDP_MENU_CP_DIAG (0x0100)
#define OSDP_MENU_PD_DIAG (0x0200)
#define OSDP_MENU_SETUP   (0x0800)


#define OSDP_CMD_NOOP         (0)
#define OSDP_CMD_CP_DIAG      (1)
#define OSDP_CMD_PD_DIAG      (2)

#define OSDP_CMD_IDENT        (2)
#define OSDP_CMD_CAP          (3)
#define OSDP_CMD_COMSET       (4)
#define OSDP_CMD_LCL_STAT     (5)
#define OSDP_CMD_RDR_STAT     (6)
#define OSDP_CMD_INIT_SECURE  (7)
#define OSDP_CMD_GET_CREDS_A  (8)

// PD Diags
#define OSDP_CMD_PD_POWER     (1)
#define OSDP_CMD_PD_CARD_PRESENT (2)

#define OSDP_CMD_DUMP_STATUS  (7)
#define OSDP_CMD_SETUP        (8)
#define OSDP_CMD_EXIT         (9)

#define OSDP_CMD_CP_SEND_POLL (1)

#define OSDP_CMD_SET_CP       (81)
#define OSDP_CMD_SET_PD       (82)

#define OSDP_OPT_CP (101)
#define OSDP_OPT_PD (102)
#define OSDP_OPT_DEVICE (103)
#define OSDP_OPT_DEBUG  (104)
#define OSDP_OPT_CHECKSUM (105)
#define OSDP_OPT_CRC      (106)
#define OSDP_OPT_HELP     (107)
#define OSDP_OPT_PDADDR   (108)
#define OSDP_OPT_NOPOLL   (109)
#define OSDP_OPT_INIT     (110)
#define OSDP_OPT_MONITOR  (111)
#define OSDP_OPT_SPECIAL  (112)


typedef struct osdp_context
{
//  int mode;
  int
    current_menu;
  int
    next_sequence;
  int
    fd;
  struct termios
    tio;
  int
    role;
  FILE
    *log;
  int
    idle_time;
  int
    tamper;
  int
    power_report;
  int
    card_data_valid;
  int
    creds_a_avail;
  int
    packets_received;
  int
    cp_polls;
  int
    pd_acks;
  int
    sent_naks;
  int
    checksum_errs;
  char
    init_command [1024];
  int
    special_1;
  int
    cparm;
  int
    cparm_v;
  unsigned char
    random_value [8];
  unsigned char
    challenge [8];
  unsigned char
    vendor_code [3];
  unsigned char
    model;
  unsigned char
    version;
  unsigned char
    serial_number [4];
  unsigned char
    fw_version [3]; //major minor build
  unsigned char
    s_enc [8];
  unsigned char
    s_mac1 [8];
  unsigned char
    s_mac2 [8];

  // for multipart messages, in or out
  char
    *mmsgbuf;
  unsigned short int
    total_len;

  // for assembling multipart message.  assumes one context structure
  // per PD we talk to
  unsigned short int
    next_in;

  // for transmitting multi-part
  unsigned short int
    next_out;
  int
    authenticated;
  gnutls_session_t
    tls_session;
} OSDP_CONTEXT;

#define OSDP_ROLE_CP      (0)
#define OSDP_ROLE_PD      (1)
#define OSDP_ROLE_MONITOR (2)

#define OSDP_CHECKSUM (0)
#define OSDP_CRC (1)

#define OSDP_VERSION_MAJOR (1)
#define OSDP_VERSION_MINOR (0)
#define OSDP_VERSION_BUILD (2)

typedef struct osdp_parameters
{
  // card response

  int
    bits;
  unsigned char
    value [1024];
  int
    value_len;

  // PD device address
  int
    addr;

  //  Serial device filename
  char
    filename [1024];

  // poll delay
  int
    poll;
} OSDP_PARAMETERS;
#define PARAMETER_NONE    (0)
#define PARAMETER_PARAMS  (1)

#define PARMV_NONE            (0)
#define PARMV_ADDR            (21)
#define PARMV_CARD_BITS       (11)
#define PARMV_CARD_VALUE      (12)
#define PARMV_CP_POLL         (31)
#define PARMV_FILENAME        (22)
#define PARMV_ROLE            (13)

#define OSDP_LOG_STRING      (1)
#define OSDP_LOG_NOTIMESTAMP (2)

#define OOSDP_MSG_PD_IDENT  (1)
#define OOSDP_MSG_KEYPAD    (2)
#define OOSDP_MSG_PKT_STATS (3)
#define OOSDP_MSG_PD_CAPAS  (4)


#define OSDP_BUF_MAX (8192)
typedef struct osdp_buffer
{
  unsigned char
    buf [OSDP_BUF_MAX];
  int
    next;
  int
    overflow;
} OSDP_BUFFER;

typedef struct osdp_param
{
  char device [1024];
} OSDP_PARAM;

typedef struct osdp_hdr
{
  unsigned char
    som;
  unsigned char
    addr;
  unsigned char
    len_lsb;
  unsigned char
    len_msb;
  unsigned char
    ctrl;
  unsigned char
    command;
} OSDP_HDR;


typedef struct osdp_rdr_led_ctl
{
  unsigned char
    reader;
  unsigned char
    led;
  unsigned char
    temp_control;
  unsigned char
    temp_on;
  unsigned char
    temp_off;
  unsigned char
    temp_on_color;
  unsigned char
    temp_off_color;
  unsigned char
    temp_timer_lsb;
  unsigned char
    temp_timer_msb;
  unsigned char
    perm_control;
  unsigned char
    perm_on_time;
  unsigned char
    perm_off_time;
  unsigned char
    perm_on_color;
  unsigned char
    perm_off_color;
} OSDP_RDR_LED_CTL;

#define OSDP_LED_TEMP_NOP    (0)
#define OSDP_LED_TEMP_CANCEL (1)
#define OSDP_LED_TEMP_SET    (2)

#define OSDP_LED_NOP (0)
#define OSDP_LED_SET (1)
#define OSDP_LEDCOLOR_BLACK (0)
#define OSDP_LEDCOLOR_RED (1)
#define OSDP_LEDCOLOR_GREEN (2)
#define OSDP_LEDCOLOR_AMBER (3)
#define OSDP_LEDCOLOR_BLUE (4)


typedef struct osdp_msg
{
  unsigned int
    lth;
  unsigned char
    * ptr;
  unsigned char
    msg_cmd;
  unsigned char
    * cmd_payload;
  unsigned char
    * data_payload;
  int
    data_length;
  unsigned char
    * crc_check;
  int
    check_size;
} OSDP_MSG;

typedef struct osdp_multi_getpiv
{
  unsigned char
    oui [3];
  unsigned short int
    total;
  unsigned short int
    offset;
  unsigned short int
    length;
  unsigned short int
    cmd;
  unsigned char
    container_tag [8];
  unsigned char
    data_tag [8];
} ZZZOSDP_MULTI_GETPIV;


typedef struct osdp_multi_hdr
{
  unsigned char
    VendorCode [3];
  unsigned short int
    Reply_ID;
  unsigned short int
    MpdSizeTotal;
  unsigned short int
    MpdOffset;
  unsigned short int
    MpdFragmentSize;
} OSDP_MULTI_HDR;

// open-osdp Reply_ID values...
#define MFGREP_OOSDP_CAKCert (0x01)


#define ST_OK                (0)
#define ST_SELECT_ERROR      (1)
#define ST_BAD_FCNTL         (2)
#define ST_MSG_TOO_SHORT     (3)
#define ST_MSG_BAD_SOM       (4)
#define ST_PARSE_UNKNOWN_CMD (5)
#define ST_BAD_AES_1         (6)
#define ST_BAD_MENU          (7)
#define ST_CMD_UNKNOWN       (8)
#define ST_EXIT              (9)
#define ST_TIMEOUT           (10)
#define ST_SERIAL_OPEN_ERR   (11)
#define ST_SERIAL_SET_ERR    (12)
#define ST_SERIAL_READ_ERR   (13)
#define ST_SERIAL_OVERFLOW   (14)
#define ST_SERIAL_IN         (15)
#define ST_BAD_CRC           (16)
#define ST_MSG_UNKNOWN       (17)
#define ST_LOG_OPEN_ERR      (18)
#define ST_BAD_CHECKSUM      (19)
#define ST_NOT_MY_ADDR       (20)
#define ST_MONITOR_ONLY      (21)
#define ST_ERR_INIT_CREDS    (22)
#define ST_BAD_MULTIPART_BUF (23)
#define ST_MMSG_SEQ_ERR      (24)
#define ST_MMSG_OUT_OF_ORDER (25)
#define ST_MMSG_LAST_FRAG_TOO_BIG (26)
#define ST_NET_INPUT_READY        (27)

#define ST_OSDP_TLS_CLOSED        (31)
#define ST_OSDP_TLS_ERROR         (32)
#define ST_OSDP_TLS_HANDSHAKE     (33)
#define ST_OSDP_TLS_NOCERT        (34)
#define ST_OSDP_TLS_ERR           (35)
#define ST_OSDP_TLS_BIND_ERR      (36)
#define ST_OSDP_TLS_SOCKET_ERR    (37)
#define ST_OSDP_TLS_LISTEN_ERR    (38)
#define ST_OSDP_TLS_NONBLOCK      (39)
#define ST_OSDP_TLS_CLIENT_HANDSHAKE (40)


int
  m_verbosity;
int
  m_version_minor;
int
  m_build;
int
  m_idle_timeout;
int
  m_check;
int
  m_dump;


int action_osdp_MFG (OSDP_CONTEXT *ctx, OSDP_MSG *msg);
int action_osdp_OUT (OSDP_CONTEXT *ctx, OSDP_MSG *msg);
int action_osdp_POLL (OSDP_CONTEXT *ctx, OSDP_MSG *msg);
int action_osdp_RAW (OSDP_CONTEXT *ctx, OSDP_MSG *msg);
int action_osdp_RSTAT (OSDP_CONTEXT *ctx, OSDP_MSG *msg);
int action_osdp_TEXT (OSDP_CONTEXT *ctx, OSDP_MSG *msg);
int background (OSDP_CONTEXT *context);
unsigned char checksum (unsigned char *msg, int length);
int calc_parity (unsigned short value, int length, int sense);
int display_menu (int menu);
int fasc_n_75_to_string (char * s, long int *sample_1);
int next_sequence (OSDP_CONTEXT *ctx);
int initialize_osdp (OSDP_CONTEXT *ctx);
int init_serial (OSDP_CONTEXT *context, char *device);
int oosdp_log (OSDP_CONTEXT *context, int logtype, int level, char *message);
int oosdp_make_message (int msgtype, char *logmsg, void *aux);
int osdp_build_message (unsigned char *buf, int *updated_length,
  unsigned char command, int dest_addr, int sequence, int data_length,
  unsigned char *data, int security);
int osdp_build_secure_message (unsigned char *buf, int *updated_length,
  unsigned char command, int dest_addr, int sequence, int data_length,
  unsigned char *data, int sec_blk_type, int sec_blk_lth,
  unsigned char *sec_blk);
int osdp_timeout (OSDP_CONTEXT *ctx, long int *last_time_check);
int parse_message (OSDP_CONTEXT *context, OSDP_MSG *m, OSDP_HDR *h);
void preserve_current_command (OSDP_TLS_CONFIG *cfg);
void process_current_command (void);
int process_osdp_input (OSDP_BUFFER *osdpbuf);
int monitor_osdp_message (OSDP_CONTEXT *context, OSDP_MSG *msg);
int process_osdp_message (OSDP_CONTEXT *context, OSDP_MSG *msg);
int read_config (OSDP_CONTEXT *context);
int send_message (OSDP_CONTEXT *context, int command, int dest_addr,
  int *current_length, int data_length, unsigned char *data);
int send_osdp_data (OSDP_CONTEXT *ctx, unsigned char *buf, int lth);
int send_secure_message (OSDP_CONTEXT *context, int command, int dest_addr,
  int *current_length, int data_length, unsigned char *data, int sec_blk_type,
  int sec_blk_lth, unsigned char *sec_blk);
void signal_callback_handler (int signum);
unsigned short int fCrcBlk (unsigned char *pData, unsigned short int nLength);
