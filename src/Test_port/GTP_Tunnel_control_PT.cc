///////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2000-2019 Ericsson Telecom AB
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v2.0
// which accompanies this distribution, and is available at
// https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
///////////////////////////////////////////////////////////////////////////////
//
//  Rev:                <RnXnn>
//  Prodnr:             CNL 113 827
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////

#include "GTP_Tunnel_control_PT.hh"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>

namespace GTP__Tunnel__PortTypes {

GTP__Tunnel__control__PT::GTP__Tunnel__control__PT(const char *par_port_name)
	: GTP__Tunnel__control__PT_BASE(par_port_name)
{
  daemon_fd=-1;
  init_msg_buffer(&recv_buffer);
}

GTP__Tunnel__control__PT::~GTP__Tunnel__control__PT()
{
  free_msg_buffer(&recv_buffer);
}

void GTP__Tunnel__control__PT::log(const char *fmt, ...)
{
	if (TTCN_Logger::log_this_event(TTCN_DEBUG)) {
		TTCN_Logger::begin_event(TTCN_DEBUG);
		TTCN_Logger::log_event("GTP Tunnel Control test port (%s): ", get_name());
		va_list args;
		va_start(args, fmt);
		TTCN_Logger::log_event_va_list(fmt, args);
		va_end(args);
		TTCN_Logger::end_event();
	}
}

void GTP__Tunnel__control__PT::report_ind(GTP__Tunnel__Result__code code,const char *fmt, ...  ){
  GTP__Tunnel__indication ind;
		va_list args;
		va_start(args, fmt);
  char * str=mprintf_va_list(fmt, args);
  ind.result().result__code()=code;
  ind.result().result__text()=str;
  Free(str);
  incoming_message(ind);
}

void GTP__Tunnel__control__PT::set_parameter(const char * /*parameter_name*/,
	const char * /*parameter_value*/)
{

}

/*void GTP__Tunnel__control__PT::Handle_Fd_Event(int fd, boolean is_readable,
	boolean is_writable, boolean is_error) {}*/

void GTP__Tunnel__control__PT::Handle_Fd_Event_Error(int fd)
{
  Handle_Fd_Event_Readable(fd);
}

void GTP__Tunnel__control__PT::Handle_Fd_Event_Writable(int /*fd*/)
{

}

void GTP__Tunnel__control__PT::Handle_Fd_Event_Readable(int fd)
{
  log("Handle_Fd_Event_Readable begin");
  
  inc_buff_size(&recv_buffer,4);  // we should be able to receive the msg length
  int curr_pos;
  int rd=read(fd,recv_buffer.msg+recv_buffer.pos,recv_buffer.size-recv_buffer.pos);
  log("read returned: %d",rd);
  if(rd<=0){  // Read error or the daemon closed the connection
    int en=errno;
    if(rd<0){
      log("Read error: %d %s",en,strerror(en));
      report_ind(GTP__Tunnel__Result__code::ERROR_,"Read error %d %s",en,strerror(en));
    } else {
      log("The daemon closed the connection");
      report_ind(GTP__Tunnel__Result__code::ERROR_,"The daemon closed the connection");
    }
    Handler_Remove_Fd_Read(daemon_fd);
    close(daemon_fd);
    daemon_fd=-1;
  } else {  // process the message
    recv_buffer.pos+=rd;
    
    // read the msg length
    curr_pos=recv_buffer.pos;  // store the write position of the buffer
    
    while(curr_pos){  // process all of the message in the buffer
      recv_buffer.pos=0;  // start from the beginning

      int msg_len;
      if(get_int(&recv_buffer,&msg_len)<0) { goto msg_error;}  // read the msg length
      log("msg length: %d",msg_len);
      if(msg_len>curr_pos){  // we need more data
        log("More data is needed. msg length %d received bytes %d",msg_len,curr_pos);
        recv_buffer.pos=curr_pos;
        inc_buff_size(&recv_buffer,msg_len-curr_pos); // reserve enough space in the buffer to receive data
        log("Handle_Fd_Event_Readable end");
        return;
      }
      if(msg_len<8) { goto msg_error;} // No msg type????
      
      int msg_type;
      if(get_int(&recv_buffer,&msg_type)<0) { goto msg_error;} // read the msg type
      log("msg type: %d",msg_type);

      switch(msg_type){
        case GTP_CTRL_MSG_INIT_ACK:{
            GTP__Tunnel__init__ack ia;
            log("GTP_Tunnel_init_ack received");
            int code;
            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_RES_CODE){ break;} // check it
            if(get_int(&recv_buffer,&code)<0) { break;}  // read the result code
            log("IE val: %d",code);
            ia.result().result__code()=code;
            str_holder str;

            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_RES_TXT){ break;}  // check it
            if(get_str(&recv_buffer,&str)<0) { break;}
            ia.result().result__text()=CHARSTRING(str.str_size,(const char*)str.str_begin);
            log("Message decoded");
            incoming_message(ia);
          }
          break;
        case GTP_CTRL_MSG_CREATE_ACK:{
            log("GTP_Tunnel_create_ack received");
            GTP__Tunnel__create__ack ca;
            int code;
            str_holder str;
            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_OUT_TEID){ break;} // check it
            if(get_str(&recv_buffer,&str)<0) { break;}
            ca.outgoing__TEID()=OCTETSTRING(str.str_size,str.str_begin);

            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            if(code==GTP_CTRL_IE_IN_TEID){
              log("IE code: %d",code);
              if(get_str(&recv_buffer,&str)<0) { break;}
              ca.incoming__TEID()()=OCTETSTRING(str.str_size,str.str_begin);

              if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            } else {
              ca.incoming__TEID()=OMIT_VALUE;
            }
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_RES_CODE){ break;} // check it
            if(get_int(&recv_buffer,&code)<0) { break;}  // read the result code
            log("IE val: %d",code);
            ca.result().result__code()=code;

            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_RES_TXT){ break;}  // check it
            if(get_str(&recv_buffer,&str)<0) { break;}
            ca.result().result__text()=CHARSTRING(str.str_size,(const char*)str.str_begin);
            
            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_ADDR){ break;} // check it
            if(get_str(&recv_buffer,&str)<0) { break;}
            ca.user__address()=OCTETSTRING(str.str_size,str.str_begin);

            log("Message decoded");
            incoming_message(ca);
           }  
          break;
        case GTP_CTRL_MSG_BYE_ACK:{
            log("GTP_Tunnel_bye_ack received");
            GTP__Tunnel__bye__ack ba=NULL_VALUE;
            incoming_message(ba);
          }
          break;
        case GTP_CTRL_MSG_INDICATION:{
            log("GTP_Tunnel_indication received");
            GTP__Tunnel__indication ia;
            int code;
            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_RES_CODE){ break;} // check it
            if(get_int(&recv_buffer,&code)<0) { break;}  // read the result code
            log("IE val: %d",code);
            ia.result().result__code()=code;
            str_holder str;

            if(get_int(&recv_buffer,&code)<0) { break;}  // get the IE code
            log("IE code: %d",code);
            if(code!=GTP_CTRL_IE_RES_TXT){ break;}  // check it
            if(get_str(&recv_buffer,&str)<0) { break;}
            ia.result().result__text()=CHARSTRING(str.str_size,(const char*)str.str_begin);
            log("Message decoded");
            incoming_message(ia);
          }
          break;
        default:
          log("Unknown message type. Ignored");
          report_ind(GTP__Tunnel__Result__code::ERROR_,"Unknown message type: %d. Ignored",msg_type);
          break;
      }
      log("Remove the processed message from the buffer.");
      if(msg_len!=curr_pos){  // there is data in the buffer, move it to the beginning
        memmove(recv_buffer.msg,recv_buffer.msg+msg_len,curr_pos-msg_len);
      }
      recv_buffer.pos=curr_pos-msg_len;
      curr_pos=recv_buffer.pos;
    }
  }

  log("Handle_Fd_Event_Readable end");
  return;

msg_error:
  // process the message decoding error here
  log("Something is wrong with the received message. Dropped.");
  report_ind(GTP__Tunnel__Result__code::ERROR_,"Something is wrong with the received message. Dropped.");
  recv_buffer.pos=0;
  
  log("Handle_Fd_Event_Readable end");

}

/*void GTP__Tunnel__control__PT::Handle_Timeout(double time_since_last_call) {}*/

void GTP__Tunnel__control__PT::user_map(const char * /*system_port*/)
{
  log("Mapped.");
}

void GTP__Tunnel__control__PT::user_unmap(const char * /*system_port*/)
{
  if(daemon_fd!=-1){
    close(daemon_fd);
    daemon_fd=-1;
  }
  log("Unmapped.");
}

void GTP__Tunnel__control__PT::user_start()
{

}

void GTP__Tunnel__control__PT::user_stop()
{

}

void GTP__Tunnel__control__PT::send_msg(const msg_buffer* buffer){
  log("Sending message");
  if(::send(daemon_fd,buffer->msg,buffer->pos,0)<0){
    int en=errno;
    log("Message send error %d %s",en,strerror(en));
    report_ind(GTP__Tunnel__Result__code::ERROR_,"Message send error %d %s",en,strerror(en));

    if(daemon_fd != -1)
    {
      Handler_Remove_Fd_Read(daemon_fd);
      close(daemon_fd);
      daemon_fd=-1;
    }
  } else {
    log("Message sent");
  }
}

void GTP__Tunnel__control__PT::outgoing_send(const GTP__Tunnel__init& send_par)
{
  log("outgoing_send GTP__Tunnel__init called");
  if(daemon_fd!=-1){
    report_ind(GTP__Tunnel__Result__code::ERROR_,"Already connected to the daemon");
    return;
  }

	struct sockaddr_un localAddr;
	localAddr.sun_family = AF_UNIX;
  localAddr.sun_path[0]='\0';  // use abstract socket
  if( (!send_par.interface__name().ispresent()) || (send_par.interface__name()().lengthof()==0)){
    log("No interface name was specified, using the default name: gtp_tunel_daemon");
    snprintf(localAddr.sun_path+1,106,"gtp_tunel_daemon");
  } else {
    log("Interface name was specified, connecting to: gtp_tunel_daemon_%s",(const char*)send_par.interface__name()());
    snprintf(localAddr.sun_path+1,106,"gtp_tunel_daemon_%s",(const char*)send_par.interface__name()());
  }
  
	if((daemon_fd = socket(PF_UNIX,SOCK_STREAM,0))<0) {
    int en=errno;
    log("Socket creation error %d %s",en,strerror(en));
    report_ind(GTP__Tunnel__Result__code::ERROR_,"Socket creation error %d %s",en,strerror(en));
    log("outgoing_send GTP__Tunnel__init finished");
    return;
		
	}

	size_t addrLength = sizeof(localAddr.sun_family) + 1 + strlen(localAddr.sun_path+1);
  log("Connecting to the daemon");
	if(connect(daemon_fd, (struct sockaddr *) &localAddr, addrLength) != 0)
	{
    int en=errno;
    log("Connect failed %d %s",en,strerror(en));
    report_ind(GTP__Tunnel__Result__code::ERROR_,"Connect failed %d %s",en,strerror(en));
    close(daemon_fd);
    daemon_fd=-1;
  } else {
    Handler_Add_Fd_Read(daemon_fd);
    msg_buffer msg_buff;
    init_msg_buffer(&msg_buff);
    
    msg_buff.pos+=4; // skip the length, will be filled later
    int msg_len=4;
    
    msg_len+=put_int(&msg_buff,GTP_CTRL_MSG_INIT);
    if(send_par.tunnel__addres().ispresent()){
      str_holder str;
      
      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_IP);
      str.str_begin=(const unsigned char*)(const char*)send_par.tunnel__addres()().local__ip();
      str.str_size=send_par.tunnel__addres()().local__ip().lengthof();
      msg_len+=put_str(&msg_buff,&str);

      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_PORT);
      msg_len+=put_int(&msg_buff,(int)send_par.tunnel__addres()().local__port());

      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_IP);
      str.str_begin=(const unsigned char*)(const char*)send_par.tunnel__addres()().remote__ip();
      str.str_size=send_par.tunnel__addres()().remote__ip().lengthof();
      msg_len+=put_str(&msg_buff,&str);

      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_PORT);
      msg_len+=put_int(&msg_buff,(int)send_par.tunnel__addres()().remote__port());
    }
    if(send_par.param__list().ispresent()){
      for(int i=0;i<send_par.param__list()().lengthof();i++){
        switch(send_par.param__list()()[i].get_selection()){
          case GTP__Tunnel__param::ALT_set__address__mode:
            msg_len+=put_int(&msg_buff,GTP_CTRL_IE_PARAM_SET_ADDR_MODE);
            msg_len+=put_int(&msg_buff,(int)send_par.param__list()()[i].set__address__mode());
            break;
          default:
            break;
        }
      }
    }
    
    int cp=msg_buff.pos;
    msg_buff.pos=0;
    put_int(&msg_buff,msg_len);
    msg_buff.pos=cp;
    send_msg(&msg_buff);
    free_msg_buffer(&msg_buff);
  }

  log("outgoing_send GTP__Tunnel__init finished");
}

void GTP__Tunnel__control__PT::outgoing_send(const GTP__Tunnel__bye& /*send_par*/)
{
  if(daemon_fd==-1){
    report_ind(GTP__Tunnel__Result__code::ERROR_,"There is no connection to the daemon");
    return;
  }
  msg_buffer msg_buff;
  init_msg_buffer(&msg_buff);

  put_int(&msg_buff,8);
  put_int(&msg_buff,GTP_CTRL_MSG_BYE);


  send_msg(&msg_buff);
  free_msg_buffer(&msg_buff);
  
}

void GTP__Tunnel__control__PT::outgoing_send(const GTP__Tunnel__create& send_par)
{
  if(daemon_fd==-1){
    report_ind(GTP__Tunnel__Result__code::ERROR_,"There is no connection to the daemon");
    return;
  }
  str_holder str;

  msg_buffer msg_buff;
  init_msg_buffer(&msg_buff);

  msg_buff.pos+=4; // skip the length, will be filled later
  int msg_len=4;

  msg_len+=put_int(&msg_buff,GTP_CTRL_MSG_CREATE);

  msg_len+=put_int(&msg_buff,GTP_CTRL_IE_OUT_TEID);
  str.str_begin=(const unsigned char*)send_par.outgoing__TEID();
  str.str_size=send_par.outgoing__TEID().lengthof();
  msg_len+=put_str(&msg_buff,&str);

  if(send_par.incoming__TEID().ispresent()){
    msg_len+=put_int(&msg_buff,GTP_CTRL_IE_IN_TEID);
    str.str_begin=(const unsigned char*)send_par.incoming__TEID()();
    str.str_size=send_par.incoming__TEID()().lengthof();
    msg_len+=put_str(&msg_buff,&str);
  }

  msg_len+=put_int(&msg_buff,GTP_CTRL_IE_ADDR_TYPE);
  msg_len+=put_int(&msg_buff,(int)send_par.user__address__type());

  msg_len+=put_int(&msg_buff,GTP_CTRL_IE_ADDR);
  str.str_begin=(const unsigned char*)send_par.user__address();
  str.str_size=send_par.user__address().lengthof();
  msg_len+=put_str(&msg_buff,&str);

  if(send_par.filter().ispresent()){
    if(send_par.filter()().proto().ispresent()){
      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_FILTER_PROTO);
      msg_len+=put_int(&msg_buff,(int)send_par.filter()().proto()());
    }
    if(send_par.filter()().local__port().ispresent()){
      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_FILTER_LOCAL_PORT);
      msg_len+=put_int(&msg_buff,(int)send_par.filter()().local__port()());
    }

    if(send_par.filter()().remote__ip().ispresent()){
      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_FILTER_REMOTE_IP);
      str.str_begin=(const unsigned char*)send_par.filter()().remote__ip()();
      str.str_size=send_par.filter()().remote__ip()().lengthof();
      msg_len+=put_str(&msg_buff,&str);
    }

    if(send_par.filter()().remote__port().ispresent()){
      msg_len+=put_int(&msg_buff,GTP_CTRL_IE_FILTER_REMOTE_PORT);
      msg_len+=put_int(&msg_buff,(int)send_par.filter()().remote__port()());
    }
  }


  if(send_par.tunnel__addres().ispresent()){
    msg_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_IP);
    str.str_begin=(const unsigned char*)(const char*)send_par.tunnel__addres()().local__ip();
    str.str_size=send_par.tunnel__addres()().local__ip().lengthof();
    msg_len+=put_str(&msg_buff,&str);

    msg_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_PORT);
    msg_len+=put_int(&msg_buff,(int)send_par.tunnel__addres()().local__port());

    msg_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_IP);
    str.str_begin=(const unsigned char*)(const char*)send_par.tunnel__addres()().remote__ip();
    str.str_size=send_par.tunnel__addres()().remote__ip().lengthof();
    msg_len+=put_str(&msg_buff,&str);

    msg_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_PORT);
    msg_len+=put_int(&msg_buff,(int)send_par.tunnel__addres()().remote__port());
  }

  int cp=msg_buff.pos;
  msg_buff.pos=0;
  put_int(&msg_buff,msg_len);
  msg_buff.pos=cp;
  send_msg(&msg_buff);
  free_msg_buffer(&msg_buff);
}

void GTP__Tunnel__control__PT::outgoing_send(const GTP__Tunnel__destroy& send_par)
{
  if(daemon_fd==-1){
    report_ind(GTP__Tunnel__Result__code::ERROR_,"There is no connection to the daemon");
    return;
  }
  str_holder str;

  msg_buffer msg_buff;
  init_msg_buffer(&msg_buff);

  msg_buff.pos+=4; // skip the length, will be filled later
  int msg_len=4;

  msg_len+=put_int(&msg_buff,GTP_CTRL_MSG_DESTROY);

  msg_len+=put_int(&msg_buff,GTP_CTRL_IE_ADDR);
  str.str_begin=(const unsigned char*)send_par.user__address();
  str.str_size=send_par.user__address().lengthof();
  msg_len+=put_str(&msg_buff,&str);

  msg_len+=put_int(&msg_buff,GTP_CTRL_IE_OUT_TEID);
  str.str_begin=(const unsigned char*)send_par.outgoing__TEID();
  str.str_size=send_par.outgoing__TEID().lengthof();
  msg_len+=put_str(&msg_buff,&str);

  msg_len+=put_int(&msg_buff,GTP_CTRL_IE_IN_TEID);
  str.str_begin=(const unsigned char*)send_par.incoming__TEID();
  str.str_size=send_par.incoming__TEID().lengthof();
  msg_len+=put_str(&msg_buff,&str);

  int cp=msg_buff.pos;
  msg_buff.pos=0;
  put_int(&msg_buff,msg_len);
  msg_buff.pos=cp;
  send_msg(&msg_buff);
  free_msg_buffer(&msg_buff);

}

} /* end of namespace */

