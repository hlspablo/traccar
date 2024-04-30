#!/usr/bin/env bash

cp ../target/tracker-server.jar out
chmod +x out/tracker-server.jar
cd out
java -Xms1g -Xmx1g -Djava.net.preferIPv4Stack=true -jar  tracker-server.jar conf/traccar.xml
