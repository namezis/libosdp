/*
  oosdp-util - open osdp utility routines

  (C)2014-2017 Smithee Spelvin Agnew & Plinge, Inc.

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


#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_CONTEXT
  context;
extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_PARAMETERS
  p_card;
unsigned int
  web_color_lookup [16] = {
    0x000000, 0xFF0000, 0x00FF00, 0x008080,
    0x444444, 0x550101, 0x660101, 0x770101,
    0x0000FF, 0x010101, 0x010101, 0x010101,
    0x010101, 0x010101, 0x010101, 0x010101,
  };
time_t
  previous_time;
char
  tlogmsg [1024];
char
  tlogmsg2 [1024];


int
  osdp_build_message
    (unsigned char
        *buf,
    int
      *updated_length,
    unsigned char
      command,
    int
      dest_addr,
    int
      sequence,
    int
      data_length,
    unsigned char
      *data,
    int
      secure)

{ /* osdp_build_mesage */

  int
    check_size;
  unsigned char
    *cmd_ptr;
  int
    new_length;
  unsigned char
    *next_data;
  OSDP_HDR
    *p;
  int
    status;
  int
    whole_msg_lth;


  status = ST_OK;
  if (m_check EQUALS OSDP_CHECKSUM)
    check_size = 1;
  else
    check_size = 2;
  new_length = *updated_length;

  p = (OSDP_HDR *)buf;
  p->som = C_SOM;
  new_length ++;

  // addr
  p->addr = dest_addr;
  // if we're the PD set the high order bit
  if (context.role EQUALS OSDP_ROLE_PD)
    p->addr = p->addr | 0x80;

  new_length ++;

  // length

  /*
    length goes in before CRC calc.
    length is 5 (fields to CTRL) + [if no sec] 1 for CMND + data
  */
  whole_msg_lth = 5;
  if (secure != 0)
status = -2;
  else
    whole_msg_lth = whole_msg_lth + 1; //CMND
  whole_msg_lth = whole_msg_lth + data_length;
  whole_msg_lth = whole_msg_lth + check_size; // including CRC

  p->len_lsb = 0x00ff & whole_msg_lth;
  new_length ++;
  p->len_msb = (0xff00 & whole_msg_lth) >> 8;
  new_length ++;

  // control
  p->ctrl = 0;
  p->ctrl = p->ctrl | (0x3 & sequence);

  // set CRC depending on current value of global parameter
  if (m_check EQUALS OSDP_CRC)
    p->ctrl = p->ctrl | 0x04;

  new_length ++;

  // secure is bit 3 (mask 0x08)
  if (secure)
  {
    p->ctrl = p->ctrl | 0x08;
    cmd_ptr = buf + 8; // STUB pretend sec blk is 3 bytes len len 1 payload
  }
  else
  {
    cmd_ptr = buf + 5; // skip security stuff
  };
// hard-coded off for now
if (secure != 0)
  status = -1;
  
  *cmd_ptr = command;
  new_length++;
  next_data = 1+cmd_ptr;

  if (data_length > 0)
  {
    int i;
    unsigned char *sptr;
    sptr = cmd_ptr + 1;
    if (context.verbosity > 9)
      fprintf (stderr, "orig next_data %lx\n", (unsigned long)next_data);
    for (i=0; i<data_length; i++)
    {
      *(sptr+i) = *(i+data);
      new_length ++;
      next_data ++; // where crc goes (after data)
    };
    if (context.verbosity > 5)
      fprintf (stderr, "data_length %d new_length now %d next_data now %lx\n",
        data_length, new_length, (unsigned long)next_data);
  };

  // crc
  if (m_check EQUALS OSDP_CRC)
{
  unsigned short int parsed_crc;
  unsigned char *crc_check;
  crc_check = next_data;
  parsed_crc = fCrcBlk (buf, new_length);

  // low order byte first
  *(crc_check+1) = (0xff00 & parsed_crc) >> 8;
  *(crc_check) = (0x00ff & parsed_crc);
  new_length ++;
  new_length ++;
}
  else
  {
    unsigned char
      cksum;
    unsigned char *
      pchecksum;

    pchecksum = next_data;
    cksum = checksum (buf, new_length);
    *pchecksum = cksum;
    new_length ++;
  };

  if (context.verbosity > 9)
  {
    fprintf (stderr, "build: sequence %d. Lth %d\n", sequence, new_length);
  }
  
  *updated_length = new_length;
  return (status);

} /* osdp_build_message */


/*
  parse_message - parses OSDP message

  Note: if verbosity is set (global m_verbosity) it also prints the PDU
  to stderr.
*/
int
  parse_message
    (OSDP_CONTEXT
      *context,
    OSDP_MSG
      *m,
    OSDP_HDR
      *returned_hdr)

{ /* parse_message */

  char
    logmsg [1024];
  unsigned int
    msg_lth;
  int
    msg_check_type;
  int
    msg_data_length;
  int
    msg_scb;
  int
    msg_sqn;
  OSDP_HDR
    *p;
  unsigned short int
    parsed_crc;
  int
    sec_blk_length;
  int
    status;
  unsigned short int
    wire_crc;


  status = ST_MSG_TOO_SHORT;
  logmsg [0] = 0;

  m->data_payload = NULL;
  msg_data_length = 0;
  p = (OSDP_HDR *)m->ptr;

  msg_check_type = (p->ctrl) & 0x04;
  if (msg_check_type EQUALS 0)
    m->check_size = 1;
  else
  {
    m->check_size = 2;
    m_check = OSDP_CRC;
  };

  if (m->lth >= (m->check_size+sizeof (OSDP_HDR)))
  {
    status = ST_OK;
    msg_lth = p->len_lsb + (256*p->len_msb);

    // now that we have a bit of header figure out how much the whole thing is.  need all of it to process it.
    if (m->lth < msg_lth)
      status = ST_MSG_TOO_SHORT;
    else
      osdp_conformance.multibyte_data_encoding.test_status =
        OCONFORM_EXERCISED;
  };
  if (status != ST_OK)
  {
    if (status != ST_MSG_TOO_SHORT)
    {
      fprintf (context->log,
        "parse_message did not clear the header.  msg_data_length %d. msg_check_type 0x%x m->check_size %d. m->lth %d. msg_lth %d status %d.\n",
        msg_data_length, msg_check_type, m->check_size, m->lth, msg_lth,
        status);
      fflush (context->log);
    };
  };
  if (status EQUALS ST_OK)
  {    
    tlogmsg [0] = 0;
    if (context->verbosity > 3)
      // prints low 7 bits of addr field i.e. not request/reply
      sprintf (tlogmsg,
"Addr:%02x Lth:%d. CTRL %02x",
        (0x7f & p->addr), msg_lth, p->ctrl);
   
    // must start with SOM
    if (p->som != C_SOM)
      status = ST_MSG_BAD_SOM;
  };
  if (status EQUALS ST_OK)
  {
    // first few fields are always in same place
    returned_hdr -> som = p->som;
    returned_hdr -> addr = p->addr;
    returned_hdr -> len_lsb = p->len_lsb;
    returned_hdr -> len_msb = p->len_msb;
    returned_hdr -> ctrl = p->ctrl;

    // various control info in CTRL byte
    msg_sqn = (p->ctrl) & 0x03;
    msg_scb = (p->ctrl) & 0x08;

    // depending on whether it's got a security block or not
    // the command/data starts at a different place
    if (msg_scb EQUALS 0)
    {
      m -> cmd_payload = m->ptr + 5;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
    }
    else
    {
fprintf (stderr, "Parsing security block...\n");
//vegas      m -> cmd_payload = m->ptr + sizeof (OSDP_HDR) + 1; // STUB for sec hdr.
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      sec_blk_length = (unsigned)*(m->ptr + 5);
      m -> cmd_payload = m->ptr + 5 + sec_blk_length;

      // whole thing less 5 hdr less 1 cmd less sec blk less 2 crc
      msg_data_length = msg_data_length - 6 - sec_blk_length - 2;

      fflush (stdout);fflush (stderr);
      if (context->verbosity > 3)
      {
        fprintf (stderr, "sec blk lth %d\n", sec_blk_length);
      };
fprintf (stderr, "mlth %d slth %d cmd 0x%x\n",
  msg_data_length, sec_blk_length, *(m->cmd_payload));
    };

    // extract the command
    returned_hdr -> command = (unsigned char) *(m->cmd_payload);
    m->msg_cmd = returned_hdr->command;

    if ((context->verbosity > 2) || (m->msg_cmd != OSDP_ACK))
    {
      sprintf (tlogmsg2, " Cmd %02x", returned_hdr->command);
      strcat (tlogmsg, tlogmsg2);
    };
///    msg_data_length = 0; // depends on command
    if ((context->verbosity > 4) || ((m->msg_cmd != OSDP_POLL) &&
       (m->msg_cmd != OSDP_ACK)))
      {
        char
          dirtag [1024];
        int i;
        unsigned char
          *p1;
        unsigned char
          *p2;
        char
          tlogmsg [1024];


        strcpy (tlogmsg, "");
        p1 = m->ptr;
        if (*(p1+1) & 0x80)
          strcpy (dirtag, "PD");
        else
          strcpy (dirtag, "CP");
        if (context->verbosity > 8)
        {
          int i;
          char line [1024];
          int len;
          char octet [8];
          len = (*(p1+3))*256+*(p1+2);
          strcpy (line, "      Raw: ");
          for (i=0; i<len; i++)
          {
            sprintf (octet, " %02x", *(p1+i));
            strcat (line, octet);
          };
          strcat (line, "\n");
          strcat (tlogmsg, line);
        };
        if (0 EQUALS strcmp (dirtag, "CP"))
          status = oosdp_log (context, OSDP_LOG_STRING_CP, 1, tlogmsg);
        else
          status = oosdp_log (context, OSDP_LOG_STRING_PD, 1, tlogmsg);
      
        p2 = p1+5;
        if (p->ctrl & 0x08)
        {
          fprintf (context->log,
            "  SEC_BLK_LEN %02x SEC_BLK_TYPE %02x SEC_BLK_DATA[0] %02x\n",
            *(p1+5), *(p1+6), *(p1+7));
          p2 = p1+5+*(p1+5); // before-secblk and secblk
        };
        // was fprintf (context->log, "   CMND/REPLY %02x\n", *p2);
        if (!m_dump)
        {
          if (msg_data_length)
          {
            fprintf (context->log,
              "  DATA (%d. bytes):\n    ",
              msg_data_length);
          };
          p1 = m->ptr + (msg_lth-msg_data_length-2);
          for (i=0; i<msg_data_length; i++)
          {
            fprintf (context->log, " %02x", *(i+p1));
          };
          fprintf (context->log, "\n");

          fprintf (context->log, " Raw data: ");
          for (i=0; i<msg_lth; i++)
          {
            fprintf (context->log, " %02x", *(i+m->ptr));
          };
          fprintf (context->log, "\n");
        };
      };

    // go check the command field
    osdp_conformance.CMND_REPLY.test_status = OCONFORM_EX_GOOD_ONLY;
    switch (returned_hdr->command)
    {
    default:
      osdp_conformance.CMND_REPLY.test_status = OCONFORM_UNTESTED;
      //status = ST_PARSE_UNKNOWN_CMD;
      m->data_payload = m->cmd_payload + 1;
      fprintf (stderr, "Unknown command, default msg_data_length was %d\n",
        msg_data_length);
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "\?\?\?");
      break;

    case OSDP_ACK:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ACK");
      context->pd_acks ++;
      osdp_conformance.cmd_poll.test_status = OCONFORM_EXERCISED;
      osdp_conformance.rep_ack.test_status = OCONFORM_EXERCISED;
      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_BUSY:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BUSY");
      osdp_conformance.resp_busy.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_CCRYPT:
      m->data_payload = m->cmd_payload + 1;
      if (context->verbosity > 2)
      {
        if (context->role EQUALS OSDP_ROLE_PD)
        {
          strcpy (tlogmsg2, "osdp_CHLNG");
        }
        else
        {
          strcpy (tlogmsg2, "osdp_CCRYPT");
        };
      };
      break;

// OSDP_CHLNG

    case OSDP_MFG:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFG");
      break;

    case OSDP_NAK:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      context->sent_naks ++;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_NAK");
      break;

    case OSDP_BUZ:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BUZ");
      break;

    case OSDP_CAP:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_CAP");
      break;

    case OSDP_COM:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_COM");
      break;

    case OSDP_COMSET:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = 5;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_COMSET");
      break;

    case OSDP_ID:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ID");
      break;

    case OSDP_KEYPAD:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_KEYPAD");
      break;

    case OSDP_LED:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LED");
      break;

    case OSDP_LSTAT:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LSTAT");
      break;

   case OSDP_LSTATR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LSTATR");
      break;

    case OSDP_MFGREP:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFGREP");
      break;

    case OSDP_OSTATR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OSTATR");
      break;

    case OSDP_OUT:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OUT");
      break;

    case OSDP_PDCAP:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_PDCAP");
      osdp_conformance.cmd_pdcap.test_status = OCONFORM_EXERCISED;
      osdp_conformance.rep_device_capas.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_PDID:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
// ASSUMES NO SECURITY
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_PDID");
      osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;
      osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_POLL:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_POLL");
      context->cp_polls ++;
      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_RAW:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RAW");
      break;

    case OSDP_RSTAT:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RSTAT");
      break;

    case OSDP_RSTATR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RSTATR");
      break;

    case OSDP_TEXT:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_TEXT");
      break;
    };

    // for convienience save the data payload length

    m->data_length = msg_data_length;

    if (m->check_size EQUALS 2)
    {
      // figure out where crc or checksum starts
      m->crc_check = m->cmd_payload + 1 + msg_data_length;
      if (0)///(msg_scb)
      {
         fprintf (stderr, "enc mac so +4 check\n");
          m->crc_check = m->crc_check + sec_blk_length;
      };
      parsed_crc = fCrcBlk (m->ptr, m->lth - 2);

      wire_crc = *(1+m->crc_check) << 8 | *(m->crc_check);
      if (parsed_crc != wire_crc)
        status = ST_BAD_CRC;

    }
    else
    {
      unsigned parsed_cksum;
      unsigned wire_cksum;

      // checksum

      parsed_cksum = checksum (m->ptr, m->lth-1);
// checksum is in low-order byte of 16 bit message suffix
      wire_cksum = *(m->cmd_payload + 2 + msg_data_length);
//experimental
if (m->lth == 7)
  wire_cksum = *(m->cmd_payload + 1 + msg_data_length);
      if (context->verbosity > 99)
      {
        fprintf (stderr, "pck %04x wck %04x\n",
          parsed_cksum, wire_cksum);
      };
      if (parsed_cksum != wire_cksum)
      {
        status = ST_BAD_CHECKSUM;
        context->checksum_errs ++;
      };
    };
    if ((context->verbosity > 2) || (m_dump > 0))
    {
      char
        log_line [1024];

      sprintf (log_line, "  Message: %s %s", tlogmsg2, tlogmsg);
      sprintf (tlogmsg2, " Seq:%02x ChkType %x Sec %x CRC: %04x",
        msg_sqn, msg_check_type, msg_scb, wire_crc);
      strcat (log_line, tlogmsg2);
      if (((returned_hdr->command != OSDP_POLL) &&
        (returned_hdr->command != OSDP_ACK)) ||
        (context->verbosity > 3))
        fprintf (context->log, "%s\n", log_line);
      tlogmsg [0] = 0; tlogmsg2 [0] = 0;
    };
  };
  if (status EQUALS ST_OK)
  {
    /*
      at this point we think it's a whole well-formed frame.  might not be for
      us but it's a frame.
    */
    context->packets_received ++;

    if (context->role EQUALS OSDP_ROLE_PD)
      if ((p_card.addr != p->addr) && (p->addr != 0x7f))
      {
        if (context->verbosity > 3)
          fprintf (stderr, "addr mismatch for: %02x me: %02x\n",
            p->addr, p_card.addr);
        status = ST_NOT_MY_ADDR;
      };
    if (context->role EQUALS OSDP_ROLE_MONITOR)
    {
      // pretty print the message if tehre are juicy details.
      (void)monitor_osdp_message (context, m);

      status = ST_MONITOR_ONLY;
    };
  };

  // if there was an error dump the log buffer

  if ((status != ST_OK) && (status != ST_MSG_TOO_SHORT))
  {
    if (strlen (logmsg) > 0)
      fprintf (context->log, "%s\n", logmsg);

    // if parse failed report the status code
    if ((context->verbosity > 3) && (status != ST_MONITOR_ONLY))
    {
      fflush (context->log);
      fprintf (context->log,
        "Message input parsing failed, status %d\n", status);
    };
  };
  return (status);

} /* parse_message */


int
  monitor_osdp_message
    (OSDP_CONTEXT
      *context,
     OSDP_MSG
       *msg)

{ /* monitor_osdp_message */

  time_t
    current_time;
  int
    status;
  char
    tlogmsg [1024];


  status = ST_OK;
  switch (msg->msg_cmd)
  {
  case OSDP_KEYPAD:
    status = oosdp_make_message (OOSDP_MSG_KEYPAD, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_PDCAP:
    status = oosdp_make_message (OOSDP_MSG_PD_CAPAS, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_PDID:
    status = oosdp_make_message (OOSDP_MSG_PD_IDENT, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_RAW:
    // in monitor mode we're really not supposed to use 'action' routines
    // but all it does is printf.

    status = action_osdp_RAW (context, msg);
    break;
  };
  (void) time (&current_time);
  if ((current_time - previous_time) > 15)
  {
    status = oosdp_make_message (OOSDP_MSG_PKT_STATS, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_STRING, 1, tlogmsg);
    previous_time = current_time;
  };
  return (status);

} /* monitor_osdp_message */


int
  process_osdp_message
    (OSDP_CONTEXT
      *context,
     OSDP_MSG
       *msg)

{ /* process_osdp_message */

  int
    current_length;
  int
    i;
  char
    logmsg [1024];
  OSDP_HDR
    *oh;
  int
    status;
  char
    tlogmsg [1024];


  status = ST_MSG_UNKNOWN;
  oh = (OSDP_HDR *)(msg->ptr);
  if (context -> role EQUALS OSDP_ROLE_PD)
  {
    if (context->verbosity > 9)
    {
      fprintf (context->log, "PD: command %02x\n",
        context->role);
    };
    if ((oh->ctrl & 0x03) EQUALS 0)
    {
      fprintf (context->log,
        "CP sent sequence 0 - resetting sequence numbers\n");
      context->next_sequence = 0;
    };
    switch (msg->msg_cmd)
    {
    case OSDP_BUZ:
      {
        sprintf (logmsg, "BUZZER %02x %02x %02x %02x %02x\n",
          *(msg->data_payload + 0), *(msg->data_payload + 1),
          *(msg->data_payload + 2), *(msg->data_payload + 3),
          *(msg->data_payload + 4));
        fprintf (context->log, "%s", logmsg);
        fprintf (stderr, "%s", logmsg);
        logmsg[0]=0;
      };
      current_length = 0;
      status = send_message
        (context, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
      context->pd_acks ++;
      break;

    case OSDP_CAP:
      {
        unsigned char
          osdp_cap_response_data [3*(14-1)] = {
            1,2,8, // 8 inputs, on/of/nc/no
            2,2,8, // 8 outputs, on/off/drive
3,1,0, // 1024 bits max
            4,1,8, // on/off only, 8 LED's
5,1,1, // audible annunciator present, claim on/off only
6,1,1, // 1 row of 16 characters
//7 // assume 7 (time keeping) is deprecated
8,1,0, // supports CRC-16
#ifndef OSDP_SECURITY
9,0,0, //no security
#endif
#if OSDP_SECURITY
9,1,1, //SCBK_D, AES 128
#endif
10,0xff & OSDP_BUF_MAX, (0xff00&OSDP_BUF_MAX)>>8, // rec buf max
11,0xff & OSDP_BUF_MAX, (0xff00&OSDP_BUF_MAX)>>8, // largest msg
12,0,0, // no smartcard
13,0,0, // no keypad
14,0,0  // no biometric
};

        status = ST_OK;
        current_length = 0;
        status = send_message (context,
          OSDP_PDCAP, p_card.addr, &current_length,
          sizeof (osdp_cap_response_data), osdp_cap_response_data);
        osdp_conformance.cmd_pdcap.test_status =
          OCONFORM_EXERCISED;
        osdp_conformance.rep_device_capas.test_status =
          OCONFORM_EXERCISED;
fprintf (stderr, "2 pdcap\n");
        if (context->verbosity > 2)
          fprintf (stderr, "Responding with OSDP_PDCAP\n");
      };
      break;

    case OSDP_COMSET:
      {
        int
          new_address;
        int
          new_speed;
        unsigned char
          osdp_com_response_data [5];
        unsigned char
          *p;
        int
          refuse_change;

        refuse_change = 0;
        p = msg->data_payload;
        new_address = *(msg->data_payload);
        new_speed = *(1+msg->data_payload) + (*(2+msg->data_payload) << 8) +
          (*(3+msg->data_payload) << 16) + (*(4+msg->data_payload) << 24);
        new_speed = *(p+1);
        new_speed = new_speed + (*(p+2) << 8);
        new_speed = new_speed + (*(p+3) << 16);
        new_speed = new_speed + (*(p+4) << 24);
        // sanity check the input.
        if (new_address EQUALS 0x7F)
          refuse_change = 1;
        if (new_speed != 9600)
          if (new_speed != 115200)
            if (new_speed != 38400)
              if (new_speed != 19200)
                refuse_change = 1;

        sprintf (logmsg, "COMSET requests new addr %02x new speed %d.",
          new_address, new_speed);
        fprintf (context->log, "%s\n", logmsg);
fprintf (stderr, "%s\n", logmsg); fflush (context->log);

        // respond on the old address, speed, THEN change.

        memset (osdp_com_response_data, 0, sizeof (osdp_com_response_data));
        osdp_com_response_data [0] = new_address;
        if (refuse_change)
        {
          unsigned char
            osdp_nak_response_data [2];

          current_length = 0;
          osdp_nak_response_data [0] = OO_NAK_CMD_REC;
          osdp_nak_response_data [1] = 0xff;
          status = send_message (context,
            OSDP_NAK, p_card.addr, &current_length,
            sizeof (osdp_nak_response_data), osdp_nak_response_data);
          context->sent_naks ++;
        }
        else
        {
          osdp_com_response_data [1] = new_speed & 0xff;
          osdp_com_response_data [2] = (new_speed & 0xff00) >> 8;;
          osdp_com_response_data [3] = (new_speed & 0xff0000) >> 16;;
          osdp_com_response_data [4] = (new_speed & 0xff000000) >> 24;;

          // sending response back on old addr/speed

          current_length = 0;
          status = send_message (context,
            OSDP_COM, p_card.addr, &current_length,
            sizeof (osdp_com_response_data), osdp_com_response_data);
          if (context->verbosity > 2)
          {
            sprintf (logmsg, "Responding with OSDP_COM");
            fprintf (context->log, "%s\n", logmsg); logmsg[0]=0;
          };

          // NOW we change it
          if (!refuse_change)
            p_card.addr = new_address;
          fprintf (context->log, "PD Address set to %02x\n", p_card.addr);
          if (!refuse_change)
          {
            sprintf (context->serial_speed, "%d", new_speed);
            fprintf (stderr, "init_serial: %s\n", context->serial_speed);
            status = init_serial (context, p_card.filename);
          };
          fprintf (context->log, "PD Speed set to %s\n", context->serial_speed);
        };
        status = ST_OK;
      };
      break;

    case OSDP_CHLNG:
      {
        int
          nak;
        unsigned char
          osdp_nak_response_data [2];

        status = ST_OK;
        nak = 0;
        if (OO_SCS_USE_ENABLED != context->secure_channel_use[OO_SCU_ENAB])
          nak = 1;
        if (nak)
        {
          current_length = 0;
          osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
          osdp_nak_response_data [1] = 0xff;
          status = send_message (context,
            OSDP_NAK, p_card.addr, &current_length, 1, osdp_nak_response_data);
          context->sent_naks ++;
          osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
          if (context->verbosity > 2)
          {
            fprintf (context->log, "Responding with OSDP NAK\n");
            fprintf (stderr, "CMD %02x Unknown\n", msg->msg_cmd);
          };
        };
        if (!nak)
        {
          unsigned char
            ccrypt_response [32];
          unsigned char
            cuid [8];
          unsigned char
            sec_blk [1];

          sec_blk [0] = OSDP_KEY_SCBK_D;
          current_length = 0;
          memcpy (context->challenge, msg->data_payload, 8);
          {
            int
              idx;

            fprintf (context->log, "Challenge:");
            for (idx=0; idx<8; idx++)
            {
              fprintf (context->log, " %02x", context->challenge [idx]);
            };
            fprintf (context->log, "\n");
          };
printf ("challenged saved \n");

          // put together response to challenge.  need random, need cUID

          strncpy ((char *)(context->random_value), "abcdefgh", 8);
printf ("fixme: RND.B\n");
          memcpy (cuid+0, context->vendor_code, 3);
          cuid [3] = context->model;
          cuid [4] = context->version;
          memcpy (cuid+5, context->serial_number, 3);
          memcpy (ccrypt_response+0, cuid, 8);
          memcpy (ccrypt_response+8, context->random_value, 8);
printf ("fixme: client cryptogram\n");
          memset (ccrypt_response+16, 17, 16);
          status = send_secure_message (context,
            OSDP_CCRYPT, p_card.addr, &current_length, 
            sizeof (ccrypt_response), ccrypt_response,
            OSDP_SEC_SCS_12, sizeof (sec_blk), sec_blk);
        };
      };
      break;

    case OSDP_ID:
      {
        unsigned char
          osdp_pdid_response_data [12];

        osdp_pdid_response_data [ 0] = context->vendor_code [0];
        osdp_pdid_response_data [ 1] = context->vendor_code [1];
        osdp_pdid_response_data [ 2] = context->vendor_code [2];
        osdp_pdid_response_data [ 3] = context->model;;
        osdp_pdid_response_data [ 4] = context->version;
        osdp_pdid_response_data [ 5] = 0xca;
        osdp_pdid_response_data [ 6] = 0xfe;
        osdp_pdid_response_data [ 7] = 0xde;
        osdp_pdid_response_data [ 8] = 0xad;
        osdp_pdid_response_data [ 9] =
          context->fw_version [0] = OSDP_VERSION_MAJOR;
        osdp_pdid_response_data [10] = m_version_minor;
        osdp_pdid_response_data [11] = m_build;
        status = ST_OK;
        current_length = 0;
        status = send_message (context, OSDP_PDID, p_card.addr,
          &current_length,
          sizeof (osdp_pdid_response_data), osdp_pdid_response_data);
        osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;
        osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
        if (context->verbosity > 2)
        {
          sprintf (logmsg, "Responding with OSDP_PDID");
          fprintf (context->log, "%s\n", logmsg);
        };
      }
    break;

    case OSDP_LED:
      /*
        There are 256 LED's.  They all use the colors in the spec.
        They switch on or off.  They don't blink.
      */
      {
        int
          count;
        OSDP_RDR_LED_CTL
          *led_ctl;

        status = ST_OK;
        oh = (OSDP_HDR *)(msg->ptr);
        led_ctl = (OSDP_RDR_LED_CTL *)(msg->data_payload);
        count = oh->len_lsb + (oh->len_msb << 8);
        count = count - 7;
        count = count / sizeof (*led_ctl);
        fprintf (context->log, "LED Control cmd count %d\n", count);
        fprintf (context->log, "LED Control Payload:\n");
        for (i=0; i<count; i++)
        {
          fprintf (context->log, "[%02d] Rdr %d LED %d Tcmd %d Pcmd %d\n",
            i, led_ctl->reader, led_ctl->led, led_ctl->temp_control,
            led_ctl->perm_control);
          if (led_ctl->reader EQUALS 0)
            if (led_ctl->perm_control EQUALS 1)
            {
              context->led [led_ctl->led].state = OSDP_LED_ACTIVATED;
              context->led [led_ctl->led].web_color =
                web_color_lookup [led_ctl->perm_on_color];
            };
          led_ctl = led_ctl + sizeof(OSDP_RDR_LED_CTL);
        };

        // we always ack the LED command regardless of how many LED's
        // it asks about

        current_length = 0;
        status = send_message
          (context, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
        context->pd_acks ++;
        if (context->verbosity > 4)
          fprintf (stderr, "Responding with OSDP_ACK\n");
      };
      break;

    case OSDP_OUT:
      status = action_osdp_OUT (context, msg);
      break;

    case OSDP_POLL:
      status = action_osdp_POLL (context, msg);
      break;

// OLD OSDP_POLL

    case OSDP_LSTAT:
    status = ST_OK;
    {
      unsigned char
        osdp_lstat_response_data [2];

      osdp_lstat_response_data [ 0] = context->tamper;
      osdp_lstat_response_data [ 1] = context->power_report; // report power failure
      current_length = 0;
      status = send_message (context, OSDP_LSTATR, p_card.addr,
        &current_length,
        sizeof (osdp_lstat_response_data), osdp_lstat_response_data);
      if (context->verbosity > 2)
      {
        sprintf (logmsg, "Responding with OSDP_LSTAT (Power)");
        fprintf (context->log, "%s\n", logmsg);
      };
    };
    break;

    case OSDP_MFG:
#if 0
      status = action_osdp_MFG (context, msg);
#endif
status = -1;
      break;

    case OSDP_RSTAT:
      status = action_osdp_RSTAT (context, msg);
      break;

    case OSDP_TEXT:
      status = action_osdp_TEXT (context, msg);
      break;

    default:
      status = ST_OK;
      {
        unsigned char
          osdp_nak_response_data [2];
        current_length = 0;
        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        osdp_nak_response_data [1] = 0xff;
        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, 1, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
        if (context->verbosity > 2)
        {
          fprintf (stderr, "CMD %02x Unknown\n", msg->msg_cmd);
        };
      };
      break;
    };
  } /* role PD */
  if (context -> role EQUALS OSDP_ROLE_CP)
  {
    switch (msg->msg_cmd)
    {
    case OSDP_ACK:
      status = ST_OK;
      break;

    case OSDP_BUSY:
      status = ST_OK;
      fprintf (context->log, "PD Responded BUSY\n");
      break;

    case OSDP_CCRYPT:
      {
        unsigned char
          scrypt_response [OSDP_KEY_SIZE];
        unsigned char
          sec_blk [1];


        status = ST_OK;
        sec_blk [0] = 0; // SCBK-D
        fprintf (context->log, "PD Responded with osdp_CCRYPT\n");
#if 0
verify pd cryptogram
derive scbk (?)
compute keys
  s_enc is 0x01 0x82 first 6 of rnd.a padded with 0
  s_mac1 is 0x01 0x01 first 6 of rnd.a padded with 0
  s_mac2 is 0x01 0x02 first 6 of rnd.a padded with 0
create server cryptogram
  data is rnd.b
    concat rnd.a
  key is s_enc
send OSDP_SCRYPT
#endif
        memset (scrypt_response, 17, sizeof (scrypt_response));
        status = send_secure_message (context,
          OSDP_SCRYPT, p_card.addr, &current_length, 
          sizeof (scrypt_response), scrypt_response,
          OSDP_SEC_SCS_13, sizeof (sec_blk), sec_blk);
      };
      break;

    case OSDP_KEYPAD:
      status = ST_OK;
      sprintf (tlogmsg, "%02x %02x %02x",
          *(0+msg->data_payload),
          *(1+msg->data_payload),
          *(2+msg->data_payload));
      fprintf (context->log, "PD Keypad Buffer: %s\n", tlogmsg);
      break;

    case OSDP_NAK:
      status = ST_OK;
      if (context->verbosity > 2)
      {
        sprintf (tlogmsg, "osdp_NAK: Error Code %02x Data %02x",
          *(0+msg->data_payload), *(1+msg->data_payload));
        fprintf (context->log, "%s\n", tlogmsg);
        fprintf (stderr, "%s\n", tlogmsg);
      };
      osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_COM:
      status = ST_OK;
      if (context->verbosity > 2)
      {
        fprintf (stderr, "osdp_COM: Addr %02x Baud (m->l) %02x %02x %02x %02x\n",
          *(0+msg->data_payload), *(1+msg->data_payload), *(2+msg->data_payload),
          *(3+msg->data_payload), *(4+msg->data_payload));
      };
      break;

    case OSDP_LSTATR:
      status = ST_OK;
      fprintf (context->log, "Local Status Report:");
      fprintf (context->log,
        " Tamper %d Power %d\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1));
      osdp_conformance.rep_local_stat.test_status =
        OCONFORM_EXERCISED;
      if (*(msg->data_payload) > 0)
        osdp_conformance.rep_reader_tamper.test_status =
          OCONFORM_EXERCISED;
      break;

    case OSDP_MFGREP:
      {
        OSDP_MULTI_HDR
          *mmsg;
        status = ST_OK;
        mmsg = (OSDP_MULTI_HDR *)(msg->data_payload);
        sprintf (tlogmsg,
          "OUI %02x%02x%02x Total %d Offset %d Length %d Command %04x",
          mmsg->VendorCode [0], mmsg->VendorCode [1], mmsg->VendorCode [2],
          mmsg->MpdSizeTotal, mmsg->MpdOffset, mmsg->MpdFragmentSize, mmsg->Reply_ID);
        fprintf (context->log, "  Mfg Reply %s\n", tlogmsg);
        /*
          process a multi-part message fragment
        */
        // if we're already started cannot restart
        if ((mmsg->MpdOffset == 0) && (context->total_len != 0))
          status = ST_MMSG_SEQ_ERR;
        if (status == ST_OK)
        {
          if (mmsg->MpdOffset == 0)
          {
            // starting a new one
            context->total_len = mmsg->MpdSizeTotal;
          };
        };
        if (status == ST_OK)
        {
          // must be in sequential order
          if (mmsg->MpdOffset != context->next_in)
            status = ST_MMSG_OUT_OF_ORDER;
        };
        if (status == ST_OK)
        {
          if ((mmsg->MpdFragmentSize + context->next_in) > context->total_len)
            status = ST_MMSG_LAST_FRAG_TOO_BIG;
        };
        if (status == ST_OK)
        {
          // values checked out.  add this fragment
          memcpy (context->mmsgbuf+context->next_in,
            sizeof (OSDP_MULTI_HDR) + msg->data_payload,
            mmsg->MpdFragmentSize);

          if ((context->next_in + mmsg->MpdFragmentSize) == context->total_len)
          {
            // finished, process it now
printf ("MMSG DONE\n");

            // and clean up when done processing
            context->total_len = 0;
            context->next_in = 0;
          }
          else
          {
            context->next_in = context->next_in + mmsg->MpdFragmentSize;
          };
        };
      };
      break;

    case OSDP_OSTATR:
      osdp_conformance.rep_output_stat.test_status = OCONFORM_EXERCISED;
      status = oosdp_make_message (OOSDP_MSG_OUT_STATUS, tlogmsg, msg);
      fprintf (context->log, "%s\n", tlogmsg);
      break;

    case OSDP_PDCAP:
      status = oosdp_make_message (OOSDP_MSG_PD_CAPAS, tlogmsg, msg);
      fprintf (context->log, "%s\n", tlogmsg);
      break;

    case OSDP_PDID:
      status = oosdp_make_message (OOSDP_MSG_PD_IDENT, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
      break;

    default:
      if (context->verbosity > 2)
      {
        fprintf (stderr, "CMD %02x Unknown to CP\n", msg->msg_cmd);
      };
    break;

    case OSDP_RAW:
      status = action_osdp_RAW (context, msg);
      break;

    case OSDP_RSTATR:
      status = ST_OK;
      fprintf (context->log, "Reader Tamper Status Report:");
      fprintf (context->log,
        " Ext Rdr %d\n",
        *(msg->data_payload + 0));
      break;
    };
  } /* role CP */
  if (status EQUALS ST_MSG_UNKNOWN)
    osdp_conformance.last_unknown_command = msg->msg_cmd;

  return (status);

} /* process_osdp_message */

