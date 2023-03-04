#!/bin/bash

root_dir="$(realpath $(dirname $0)/../..)"

for version in 3.7 3.8 3.9 3.10 3.11; do
	echo -n "checking for Python ${version}..."
	mypy --python-version=${version} ${root_dir}/src/wsdd.py
	echo
done
