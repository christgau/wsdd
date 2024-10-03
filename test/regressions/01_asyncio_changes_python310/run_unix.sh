#!/bin/bash

# Test if Unix Domain Socket for API can be created with different Python versions
# The API for ´start_unix_server´ was schanged in 3.10.
# @see Github issue #162

python_versions=('3' '3.7' '3.8' '3.9.' '3.10' '3.11' '3.12')

socket_dir="$(mktemp -d)"
socket_filename="${socket_dir}/wsdd.sock"

wsdd_script_args=("--no-autostart" "--no-http" "--discovery" "--listen" "${socket_filename}")

return_code=0
python_found=0

# Use netcat to connec to UNIX Domain Socket
netcat="nc"
netcat_args=("-U" "${socket_filename}" "-N")

for version in "${python_versions[@]}"; do
		python_ver_name="python${version}"

		if command -v "${python_ver_name}" >/dev/null 2>&1; then
			python_found=1
			rm -f "${socket_filename}"
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

			rm -f "${socket_filename}"
		fi
done

find "${socket_dir}" -delete

if [ $python_found -eq 1 ]; then
	exit ${return_code}
else
	exit 2
fi
