#!/usr/bin/env bash

cp ../target/tracker-server.jar out/
cp traccar.xml out/conf
cd out
java -Xms1g -Xmx1g -Djava.net.preferIPv4Stack=true -jar  tracker-server.jar conf/traccar.xml
