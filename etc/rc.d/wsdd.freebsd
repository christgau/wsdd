#!/bin/sh

# PROVIDE: wsdd
# REQUIRE: DAEMON samba_server
# BEFORE: login
# KEYWORD: shutdown

. /etc/rc.subr

name=wsdd
rcvar=wsdd_enable
wsdd_group=$(/usr/local/bin/testparm -s --parameter-name workgroup 2>/dev/null)

: ${wsdd_smb_config_file="/usr/local/etc/smb4.conf"}

# try to manually extract workgroup from samba configuration if testparm failed
if [ -z "$wsdd_group" ] && [ -r $wsdd_smb_config_file ]; then
	wsdd_group="$(grep -i '^[[:space:]]*workgroup[[:space:]]*=' $wsdd_smb_config_file | cut -f2 -d= | tr -d '[:blank:]')"
fi

if [ -n "$wsdd_group" ]; then
	wsdd_opts="-w ${wsdd_group}"
fi

command="/usr/sbin/daemon"
command_args="-u daemon -S /usr/local/bin/wsdd $wsdd_opts"

load_rc_config $name
run_rc_command "$1"
