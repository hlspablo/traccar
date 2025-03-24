#!/usr/bin/env bash

cp traccar.xml out/conf
cd out
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:5005 \
     -Xms1g -Xmx1g -Djava.net.preferIPv4Stack=true \
     -jar tracker-server.jar conf/traccar.xml
