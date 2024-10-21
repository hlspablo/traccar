#!/usr/bin/env bash

mkdir -p out/{conf,data,lib,logs,web,schema,templates}

cp ../target/tracker-server.jar out
cp ../target/lib/* out/lib
cp ../schema/* out/schema
cp -r ../templates/* out/templates
cp -r ../traccar-web/build/* out/web
cp traccar.xml out/conf