/*
  oo-process - process OSDP message input

  (C)Copyright 2014-2016 Smithee Spelvin Agnew & Plinge, Inc.

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


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_CONTEXT
  context;
extern OSDP_PARAMETERS
  p_card;
int
  cp_send_context;
extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
unsigned int
  web_color_lookup [16] = {
    0x000000, 0xFF0000, 0x00FF00, 0x008080,
    0x444444, 0x550101, 0x660101, 0x770101,
    0x0000FF, 0x010101, 0x010101, 0x010101,
    0x010101, 0x010101, 0x010101, 0x010101,
  };


int
  process_osdp_input
    (OSDP_BUFFER
      *osdp_buf)

{ /* process_osdp_input */

  OSDP_MSG
    msg;
  OSDP_HDR
    parsed_msg;
  int
    status;
  OSDP_BUFFER
    temp_buffer;


  memset (&msg, 0, sizeof (msg));

  msg.lth = osdp_buf->next;
  msg.ptr = osdp_buf->buf;
  status = parse_message (&context, &msg, &parsed_msg);
  if (status EQUALS ST_MSG_TOO_SHORT)
    status = ST_SERIAL_IN;
  if (status EQUALS ST_OK)
  {
    status = process_osdp_message (&context, &msg);
  };

  // move the existing buffer up to the front if it was unknown, not mine,
  // monitor only, or processed

  if ((status EQUALS ST_PARSE_UNKNOWN_CMD) || \
    (status EQUALS ST_BAD_CRC) || \
    (status EQUALS ST_BAD_CHECKSUM) || \
    (status EQUALS ST_NOT_MY_ADDR) || \
    (status EQUALS ST_MONITOR_ONLY) || \
    (status EQUALS ST_OK))
  {
    int length;
    length = (parsed_msg.len_msb << 8) + parsed_msg.len_lsb;
    memcpy (temp_buffer.buf, osdp_buf->buf+length, osdp_buf->next-length);
    temp_buffer.next = osdp_buf->next-length;
    memcpy (osdp_buf->buf, temp_buffer.buf, temp_buffer.next);
    osdp_buf->next = temp_buffer.next;
    if (status != ST_OK)
      // if we experienced an error we just reset things and continue
      status = ST_SERIAL_IN;
  };
  return (status);

} /* process_osdp_input */


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
      status = action_osdp_MFG (context, msg);
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

    // figure out if we're doing normal processing or file transfer or multipart message
    // could be none, either, or both so use bitmask

    cp_send_context = 0;
    if (context->filebuf != NULL)
      cp_send_context = cp_send_context | OSDP_CP_SEND_FILE;
    if (context->mmsgbuf != NULL)
      cp_send_context = cp_send_context | OSDP_CP_SEND_MULTIPART;
fprintf (stderr, "CP Send Context %x\n", cp_send_context);

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

    case OSDP_COM:
      status = ST_OK;
      if (context->verbosity > 2)
      {
        fprintf (stderr, "osdp_COM: Addr %02x Baud (m->l) %02x %02x %02x %02x\n",
          *(0+msg->data_payload), *(1+msg->data_payload), *(2+msg->data_payload),
          *(3+msg->data_payload), *(4+msg->data_payload));
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
        status = action_osdp_MFGREP (context, msg);
#ifdef OLD_MULTIPART_STUFF
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
#endif
      };
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

