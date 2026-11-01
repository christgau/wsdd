#!/bin/bash

base_dir="$(realpath $(dirname $0))"
root_dir="$(realpath $(dirname $0)/../..)"

for version in 3.11 3.12 3.13 3.14 3.15; do
	echo -n "checking for Python ${version}..."
	mypy --config-file="${base_dir}/mypy.ini" --python-version=${version} ${root_dir}/src/wsdd.py
	echo
done
