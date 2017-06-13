#define FILEXFER_VERIDT_1
/*
  oo_multi.c - mult-part messaging for OSDP

  (C)Copyright 2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <stdlib.h>

#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <osdp_filexfer.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


unsigned char
  default_filexfer_buffer [OSDP_FILEXFER_DEFAULT_BUFFERSIZE];
unsigned char
  default_multipart_buffer [OSDP_MULTI_DEFAULT_BUFFERSIZE];


extern OSDP_PARAMETERS
  p_card;


int
  file_transfer_accepted
    (OSDP_CONTEXT
      *ctx)

{ /* file_transfer_accepted */

  int
    status;


  status = ST_OK;
  if (0 != strncmp ("OSDP", (const char *)(ctx->filebuf), 4))
    status = ST_XFER_REFUSE;
  return (status);

} /* file_transfer_accepted */


int
  file_transfer_continue
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      *msg_payload)

{ /* file_transfer_continue */

  OSDP_FILEXFER_RESPONSE_HEADER
    *filexfer_response;
  OSDP_MFG_HDR
    *mfg;
  int
    status;


  status = ST_OK;
  mfg = (OSDP_MFG_HDR *)msg_payload;
  filexfer_response = (OSDP_FILEXFER_RESPONSE_HEADER *)&(mfg->mfg_details_start);

  // if fields are sane...
  if (mfg->Command_ID != MFG_SMITHEE_FWUPDATE_STATUS)
    status = ST_XFER_BAD_RESPONSE;
  if (status EQUALS ST_OK)
  {
    if (filexfer_response->Status != VERIDT_FW_UPDATE_SUCCESS)
      status = ST_XFER_ABORT;
  };
  if (status EQUALS ST_OK)
  {
    if (ctx->next_filexfer_offset EQUALS ctx->total_filexfer_length)
      status= ST_XFER_COMPLETE;
  };
  return (status);

} /* file_transfer_continue */


int
  file_transfer_init_receive
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      *details,
    int
      *new_message_size)

{ /* init_file_receive */

  OSDP_FILEXFER_HEADER_1
    *filexfer;
  OSDP_MFG_HDR
    *mfg;
  int
    status;


  status = ST_OK;
  // if we're already running report an error
  if (ctx->filebuf)
  {
    status = ST_XFER_REC;
  };
  if (status EQUALS ST_OK)
  {
    mfg = (OSDP_MFG_HDR *)&(details[0]);
    filexfer = (OSDP_FILEXFER_HEADER_1 *)&(mfg->mfg_details_start);

    ctx->filebuf = default_filexfer_buffer;
    ctx->total_filexfer_length = filexfer->FtSizeTotal;
    ctx-> next_filexfer_offset = 0;
    *new_message_size = OSDP_FILEXFER_FRAGMENT_MAX;
  };
  return (status);

} /* init_file_receive */


int
  file_transfer_response
    (OSDP_CONTEXT
      *ctx,
    int
      new_fragment_size,
    int
      new_status)

{ /* file_transfer_response */

  unsigned char
    response [sizeof (struct osdp_mfg_hdr) + sizeof (struct osdp_filexfer_hdr)];
  int
    current_length;
  OSDP_FILEXFER_RESPONSE_HEADER
    *filexfer;
  OSDP_MFG_HDR
    *mfg;
  int
    status;


  mfg = (OSDP_MFG_HDR *)&(response[0]);
  memcpy (mfg->VendorCode, "\x0A\x00\x17", 3);
  mfg->Command_ID = MFG_SMITHEE_FWUPDATE_STATUS;
  filexfer = (OSDP_FILEXFER_RESPONSE_HEADER *)&(mfg->mfg_details_start);

  // CLARIFICATION REQUESTED. Values entered from document.

  // build up message
  filexfer->CommandCode = 0x15;
  filexfer->TotalLength = 1;
  filexfer->ReplyMessageOffset = 0;
  filexfer->ReplyDataLength = 2;
  filexfer->Status = 0x85; //VERIDT_FW_UPDATE_SUCCESS

  // ft response, set new frag size, set status

  current_length = 0;
  status = send_message
    (ctx, OSDP_MFGREP, p_card.addr, &current_length, sizeof (response), response);

  // if we're done reset things (on the PD side.)

  if (ctx->total_filexfer_length EQUALS ctx->next_filexfer_offset)
  {
    ctx->filebuf = 0;
    ctx->total_filexfer_length = 0;
    ctx->next_filexfer_offset = 0;
  };

  return (status);

} /* file_transfer_response */


int
  file_transfer_update_buffer
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      *payload)

{ /* file_transfer_update_buffer */

  OSDP_FILEXFER_HEADER_1
    *filexfer;
  OSDP_MFG_HDR
    *mfg;
  int
    status;


  status = ST_OK;
  mfg = (OSDP_MFG_HDR *)payload;
  filexfer = (OSDP_FILEXFER_HEADER_1 *)&(mfg->mfg_details_start);
  memcpy (ctx->filebuf + ctx->next_filexfer_offset,
    &(filexfer->DataFragment),
    filexfer->FtFragmentSize);
  if ((ctx->next_filexfer_offset + filexfer->FtFragmentSize) EQUALS
    ctx->total_filexfer_length)
  {
    // done
    ctx->filebuf = 0;
    ctx->next_filexfer_offset = 0;
    ctx->total_filexfer_length = 0;
fprintf (stderr, "filexfer done resetting values to zero\n");
  };
  return (status);

} /* file_transfer_update_buffer */


int
  file_transfer_validate_header
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      *message_body)

{ /* file_transfer_validate_header */

  OSDP_FILEXFER_HEADER_1
    *filexfer;
  OSDP_MFG_HDR
    *mfg;
  int
    status;


  status = ST_OK;
  mfg = (OSDP_MFG_HDR *)message_body;
{
  unsigned char *q;
  q = &(mfg->mfg_details_start);
  q = q + sizeof (*mfg);
  filexfer = (OSDP_FILEXFER_HEADER_1 *)q;
};
  if (!(ctx->filebuf))
  {
    status = ST_XFER_IDLE;
  };
  if (status EQUALS ST_OK)
  {
    if (filexfer->FtOffset != ctx->next_filexfer_offset)
      status = ST_XFER_OUT_OF_SYNC;
  };
  if (status EQUALS ST_OK)
  {
    if (filexfer->FtFragmentSize > OSDP_FILEXFER_FRAGMENT_MAX)
      status = ST_XFER_FRAG_TOO_BIG;
  };

  return (status);

} /* file_transfer_validate_header */


int
  init_file_send
    (OSDP_CONTEXT
      *ctx)

{ /* init_file_send */

  ctx->filebuf = default_filexfer_buffer;
  return (ST_OK);

} /* init_file_send */


int
  init_multipart
    (OSDP_CONTEXT
      *ctx)

{ /* init_multipart */

  ctx->mmsgbuf = default_multipart_buffer;
  return (ST_OK);

} /* init_multipart */


int
  file_transfer_start
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      *oui,
    unsigned char
      command_id,
    unsigned char
      *buffer,
    int
      buffer_length)
 
{ /* file_transfer_start */

  int
    current_length;
  int
    done;
  OSDP_FILEXFER_HEADER_1
    *filexfer_message;
  int
    message_length;
  OSDP_MFG_HDR
    *mfg_cmd;
  unsigned char
    raw_buffer [sizeof (OSDP_FILEXFER_HEADER_1) + 2048];
  int
    status;


  done = 0;
  status = init_file_send (ctx);
fprintf (stderr,
  "MULTI START: OUI:%02x%02x%02x CMD %02x Buffer contains %d PD Max-msg %d\n",
  oui [0], oui [1], oui [2], command_id, buffer_length, ctx->max_pd_receive_payload);
  ctx->total_filexfer_length = buffer_length;
  ctx->next_filexfer_offset = 0;

#ifdef FILEXFER_VERIDT_1
  // like Veridt did it, with mfg commands

  mfg_cmd = (OSDP_MFG_HDR *) &(raw_buffer [0]);
  memcpy (mfg_cmd->VendorCode, ctx->vendor_code,
    sizeof (mfg_cmd->VendorCode));
  mfg_cmd->Command_ID = command_id;
  filexfer_message = (OSDP_FILEXFER_HEADER_1 *)&(mfg_cmd->mfg_details_start);  
  filexfer_message->FtType = 0x01; // Firware Update File per Veridt proposal
  filexfer_message->FtSizeTotal = buffer_length;
  filexfer_message->FtOffset = 0;
  filexfer_message->FtFragmentSize = ctx->max_pd_filexfer_payload;
  if (filexfer_message->FtFragmentSize > (ctx->total_filexfer_length - ctx->next_filexfer_offset))
  {
    done = 1;
    filexfer_message->FtFragmentSize = ctx->total_filexfer_length - ctx->next_out;
  };

  /*
    OSDP message buffer now contains MFG command with FileXfer subcommand.  Add
    the actual data.
  */
  memcpy (&(filexfer_message->DataFragment),
    ctx->filebuf + ctx->next_filexfer_offset,
    filexfer_message->FtFragmentSize);

  ctx->next_filexfer_offset = filexfer_message->FtFragmentSize +
    ctx->next_filexfer_offset;
  current_length = 0;
  message_length = sizeof (*mfg_cmd) + sizeof (*filexfer_message) + filexfer_message->FtFragmentSize - 1;
  status = send_message (ctx,
    OSDP_MFG, p_card.addr, &current_length, message_length,
    (unsigned char *)&raw_buffer);
  if (done)
  {
    ctx->filebuf = 0;
    ctx->total_filexfer_length = 0;
    ctx->next_filexfer_offset = 0;
  };
#endif
  fprintf (stderr, "filexfer-start current_length %d\n",
    current_length);

  return (status);;

} /* file_transfer_start */


int
  start_multipart
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      *oui,
    unsigned char
      command_id,
    unsigned char
      *buffer,
    int
      buffer_length)

{ /* start_multipart */

  int
    current_length;
  int
    done;
  OSDP_MFG_HDR
    *mfg_cmd;
  OSDP_MULTI_HDR
    *download_message;
  unsigned char
    raw_buffer [sizeof (OSDP_MULTI_HDR) + 1500];
  int
    status;


fprintf (stderr,
  "MULTI START: OUI:%02x%02x%02x CMD %02x Buffer contains %d PD Max-msg %d\n",
  oui [0], oui [1], oui [2], command_id, buffer_length, ctx->max_pd_receive_payload);
  done = 0;
  ctx->mmsgbuf = buffer;
  ctx->total_multipart_length = buffer_length;
  ctx->next_out = 0;

  mfg_cmd = (OSDP_MFG_HDR *) &(raw_buffer [0]);
  memcpy (mfg_cmd->VendorCode, ctx->vendor_code,
    sizeof (mfg_cmd->VendorCode));
  mfg_cmd->Command_ID = command_id;
  download_message = (OSDP_MULTI_HDR *)&(mfg_cmd->mfg_details_start);  
  download_message->MpSizeTotal = buffer_length;
  download_message->MpOffset = 0;
  download_message->MpFragmentSize = ctx->max_pd_receive_payload;
  if (download_message->MpFragmentSize > (ctx->total_multipart_length - ctx->next_out))
  {
    done = 1;
    download_message->MpFragmentSize = ctx->total_multipart_length - ctx->next_out;
  };
  memcpy (raw_buffer+sizeof (download_message), ctx->mmsgbuf + ctx->next_out, download_message->MpFragmentSize);
  ctx->next_out = download_message->MpFragmentSize + ctx->next_out;
  current_length = 0;
  status = send_message (ctx,
    OSDP_MFG, p_card.addr, &current_length, sizeof (raw_buffer),
    (unsigned char *)&raw_buffer);
  if (done)
  {
    ctx->mmsgbuf = 0;
    ctx->total_multipart_length = 0;
    ctx->next_out = 0;
  };

  fprintf (stderr, "multipart-start current_lenght %d\n",
    current_length);
  return (status);

} /* start_multipart */

