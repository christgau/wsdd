#!/bin/sh

repository="palmtop/wsdd"

#download wsdd python script
rm -f wsdd.py
wget -q https://github.com/$repository/raw/master/src/wsdd.py
if ! [ -f wsdd.py ] ; then
echo "Failed to download wsdd.py"
exit
fi
#download wsdd systemd service file
rm -f wsdd.service
wget -q https://github.com/$repository/raw/master/etc/systemd/wsdd.service
if ! [ -f wsdd.service ] ; then
echo "Failed to download wsdd.service"
exit
fi
#install wsdd python script to /usr/bin
sudo cp wsdd.py /usr/bin/wsdd
sudo chown root:root /usr/bin/wsdd
sudo chmod 0755 /usr/bin/wsdd
#install wsdd.service to systemd
sudo cp wsdd.service /etc/systemd/system/wsdd.service
# enable and run the service
sudo systemctl daemon-reload
sudo service wsdd start
sudo systemctl enable wsdd.service

