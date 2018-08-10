///////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2000-2018 Ericsson Telecom AB
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

#ifndef GTP__Tunnel__control__PT_HH
#define GTP__Tunnel__control__PT_HH

#include "GTP_Tunnel_PortTypes.hh"
#include "GTP_ctrl_handler.h"
namespace GTP__Tunnel__PortTypes {

class GTP__Tunnel__control__PT : public GTP__Tunnel__control__PT_BASE {
public:
	GTP__Tunnel__control__PT(const char *par_port_name = NULL);
	~GTP__Tunnel__control__PT();

	void set_parameter(const char *parameter_name,
		const char *parameter_value);

  int daemon_fd;

private:
	/* void Handle_Fd_Event(int fd, boolean is_readable,
		boolean is_writable, boolean is_error); */
	void Handle_Fd_Event_Error(int fd);
	void Handle_Fd_Event_Writable(int fd);
	void Handle_Fd_Event_Readable(int fd);
	/* void Handle_Timeout(double time_since_last_call); */
protected:
	void user_map(const char *system_port);
	void user_unmap(const char *system_port);

	void user_start();
	void user_stop();

	void outgoing_send(const GTP__Tunnel__init& send_par);
	void outgoing_send(const GTP__Tunnel__bye& send_par);
	void outgoing_send(const GTP__Tunnel__create& send_par);
	void outgoing_send(const GTP__Tunnel__destroy& send_par);

  void report_ind(GTP__Tunnel__Result__code code, const char *fmt, ... );
  void log(const char *fmt, ...);

  void send_msg(const msg_buffer*);
  
  msg_buffer  recv_buffer;

};

} /* end of namespace */

#endif
