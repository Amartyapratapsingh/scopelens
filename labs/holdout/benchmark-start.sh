#!/bin/sh
set -eu
mkdir -p /usr/local/tomcat/webapps/benchmark
cd /usr/local/tomcat/webapps/benchmark
jar xf /benchmark.war
cp WEB-INF/lib/hsqldb-*.jar /usr/local/tomcat/lib/
java -Xmx128m -cp 'WEB-INF/lib/*' org.hsqldb.server.Server \
  --database.0 mem:benchmark --dbname.0 benchmarkDataBase --address 127.0.0.1 &
exec /usr/local/tomcat/bin/catalina.sh run
