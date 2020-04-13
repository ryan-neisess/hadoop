mkdir -p /opt/protobuf-3.7-src \
  && curl -L -s -S \
    https://github.com/protocolbuffers/protobuf/releases/download/v3.7.1/protobuf-java-3.7.1.tar.gz \
    -o /opt/protobuf-3.7.1.tar.gz \
  && tar xzf /opt/protobuf-3.7.1.tar.gz --strip-components 1 -C /opt/protobuf-3.7-src \
  && cd /opt/protobuf-3.7-src \
  && ./configure\
  && make install \
  && rm -rf /opt/protobuf-3.7-src