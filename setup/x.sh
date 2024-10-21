#!/usr/bin/env bash

cd out
java -Xms1g -Xmx1g -Djava.net.preferIPv4Stack=true -jar  tracker-server.jar conf/traccar.xml
