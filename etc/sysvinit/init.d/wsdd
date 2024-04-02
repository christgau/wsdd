#!/bin/bash

### BEGIN INIT INFO
# Provides:         wsdd
# Required-Start:   $syslog $local_fs $remote_fs $network $named $time samba-ad-dc
# Required-Stop:    $syslog $local_fs $remote_fs $network $named $time samba-ad-dc
# Default-Start:    2 3 4 5
# Default-Stop:     0 1 6
# Short-Description: Web Services Dynamic Discovery host daemon
# Description: Web Services Dynamic Discovery (WSDD) host daemon
### END INIT INFO

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DAEMON_NAME=wsdd
SMB_CONFIG_FILE=/etc/samba/smb.conf
LOG_FILE=/var/log/$DAEMON_NAME.log
WSDD_EXEC=/usr/sbin/$DAEMON_NAME
RUN_AS_USER=daemon
DESC="Web Services Dynamic Discovery host daemon"
PROCESSDIR=/var/run/$DAEMON_NAME
PIDFILE=/var/run/wsdd.pid

# get defaults file; edit that file to configure this script.
if test -e /etc/default/$DAEMON_NAME ; then
  . /etc/default/$DAEMON_NAME
fi

# Exit if the daemon is not installed
[ -x $WSDD_EXEC ] || exit 0

# load init-functions
[ -f /lib/init/vars.sh ] && . /lib/init/vars.sh
[ -f /lib/lsb/init-functions ] && . /lib/lsb/init-functions

# start command
do_start() {
	log_daemon_msg "Starting $DESC" "$DAEMON_NAME"
	OPTS="${WSDD_PARAMS} --chroot ${PROCESSDIR} --shortlog"

	if [ -z "$WSDD_WORKGROUP" ]; then
		# try to extract workgroup with Samba's testparm
		if which testparm >/dev/null 2>/dev/null; then
			GROUP="$(testparm -s --parameter-name workgroup 2>/dev/null)"
		fi

		# fallback to poor man's approach if testparm is unavailable or failed for some reason
		if [ -z "$GROUP" ] && [ -r "${SMB_CONFIG_FILE}" ]; then
			GROUP=`grep -i '^\s*workgroup\s*=' ${SMB_CONFIG_FILE} | cut -f2 -d= | tr -d '[:blank:]'`
		fi

		if [ -n "${GROUP}" ]; then
			OPTS="-w ${GROUP} ${OPTS}"
		fi
	else
		OPTS="-w ${WSDD_WORKGROUP} ${OPTS}"
	fi

	if [ ! -r "${LOG_FILE}" ]; then
		touch "${LOG_FILE}"
	fi
	# change owner of log file to user running wsdd - commented out for now since wsdd itself does not log anything
	# chown ${RUN_AS_USER} "${LOG_FILE}"

    # Ensure PROCESSDIR exists and is accessible
    install -o root -g root -m 755 -d $PROCESSDIR

	start-stop-daemon --start --background --user ${RUN_AS_USER} --make-pidfile --pidfile $PIDFILE --exec ${WSDD_EXEC} -- ${OPTS}
	# direct logging of wsdd output does not work due to the "--background" option which seems needed since the program does not detach itself. A log file other than stdout cannot be defined either :-(
	# crude replacement to log at least something...:
	RETVAL="$?"
	CURRENTDATE=`date +"%F %T,%N"`
	if [ $RETVAL -eq 0 ]; then
		echo "$CURRENTDATE wsdd started successfully, option flags $OPTS" >> $LOG_FILE 2>&1
		exit 0
	else
		echo "$CURRENTDATE wsdd start error with option flags $OPTS, error code $RETVAL" >> $LOG_FILE 2>&1
		log_end_msg 1
        exit 1
	fi
	log_end_msg 0
}

# stop command
do_stop() {
	log_daemon_msg "Stopping $DESC" "$DAEMON_NAME"
	start-stop-daemon --stop --retry 2 --pidfile $PIDFILE
	# same log surrogate as above for stopping
	RETVAL="$?"
	CURRENTDATE=`date +"%F %T,%N"`
	if [ $RETVAL -eq 0 ]; then
		echo "$CURRENTDATE wsdd stopped successfully" >> $LOG_FILE 2>&1
	else
		echo "$CURRENTDATE wsdd stop error code $RETVAL" >> $LOG_FILE 2>&1
	fi
	# Wait a little and remove stale PID file
    sleep 1
    if [ -f $PIDFILE ] && ! ps h `cat $PIDFILE` > /dev/null
    then
        rm -f $PIDFILE
    fi
    log_end_msg 0
	#return "$RETVAL"
}


case "$1" in

    start)
        do_${1}
        ;;

    stop)
        do_${1}
        log_end_msg 0
        ;;

	reload)
        do_stop
        do_start
        log_end_msg 0
		;;

    restart|force-reload)
        do_stop
        sleep 1
        do_start
        ;;

    status)
        status_of_proc "$WSDD_EXEC" "$DAEMON_NAME"
        exit $?
        ;;

    *)
        echo "Usage: /etc/init.d/$DAEMON_NAME {start|stop|restart|status}"
        exit 1
        ;;

esac
exit 0
