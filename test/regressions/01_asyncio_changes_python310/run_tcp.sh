#!/bin/bash

# Test if TCP server socket for API can be created with different Python versions
# The API for ´start_server´ was schanged in 3.10.
# @see related Github issue #162

python_versions=('3' '3.9' '3.10' '3.11' '3.12' '3.13' '3.14')

socket_port="3333"

wsdd_script_args=("--no-autostart" "--no-http" "--discovery" "--listen" "${socket_port}")

return_code=0
python_found=0

# Use netcat to connec to UNIX Domain Socket
netcat="nc"
netcat_args=("-N", "127.0.0.1:${socket_port}")

for version in "${python_versions[@]}"; do
		python_ver_name="python${version}"

		if command -v "${python_ver_name}" >/dev/null 2>&1; then
			python_found=1
			"${python_ver_name}" "${WSDD_SCRIPT}" "${wsdd_script_args[@]}" &
			wsdd_pid=$!

			# wait until socket should be ready
			sleep 2

			# connect to socket and send a simple command
			${netcat} "${netcat_args[@]}" <<< "list"

			# terminate and get exit status
			kill -INT ${wsdd_pid}
			wait ${wsdd_pid}
			status=$?

			if [ ! ${status} -eq 0 ]; then
					return_code=1
			fi
		fi
done

if [ $python_found -eq 1 ]; then
	exit ${return_code}
else
	exit 2
fi
