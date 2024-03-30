#!/bin/bash

# see #201 (https://github.com/christgau/wsdd/issues/201)

outfile="$(mktemp)"
python3 ${WSDD_SCRIPT} -i xzy.non-existing > "${outfile}" 2>&1 &
wsdd_pid=$!

# wait for process startup
sleep 3

# send sigterm twice, shortly after another
kill ${wsdd_pid}
kill ${wsdd_pid}

# wait for exception to be dumped
wait

msg="The future belongs to a different loop than the one specified as the loop argument"
! grep -q "${msg}" "${outfile}"
retval=$?

cat "${outfile}"

rm "${outfile}"
exit ${retval}
