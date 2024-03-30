#!/bin/bash

# Run regression tests found as executable .sh scripts in level-1 subdirectories.

basedir="$(realpath "$(dirname "$0")")"

export WSDD_ROOT_DIR="$(realpath "${basedir}/../..")"
export WSDD_SCRIPT="${WSDD_ROOT_DIR}/src/wsdd.py"

test_files=()

for script in "${basedir}"/*/*.sh; do
		if [ -x ${script} ]; then
				test_files+=("${script}")
		fi
done

total_tests="${#test_files[@]}"

[ ${total_tests} -eq 0 ] && exit 0

echo "Running ${total_tests} tests..."

test_number=1

num_succeeded=0
num_failed=0

for test_case in "${test_files[@]}"; do
		log_target="$(mktemp)"

		echo -n "[${test_number}/${total_tests}] $(basename $(dirname "$test_case")) -> $(basename "${test_case}")... "

		if "${test_case}" > ${log_target} 2>&1; then
				echo "OK"
				num_succeeded=$((num_succeeded + 1))
		else
				cat "${log_target}"
				echo "FAILED"
				num_failed=$((num_failed + 1))
		fi

		rm -f "${log_target}"

		test_number=$(($test_number + 1))
done

echo "------------------------------------------"
echo "${num_succeeded} succeeded, ${num_failed} failed."

exit $((${total_tests} - ${num_succeeded}))
