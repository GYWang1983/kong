FROM kong:2.8.1

ARG proxy=""

USER root
RUN /bin/sh -c set -ex \
    # && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    # && apk add --no-cache libuuid \
    && apk add libxml2

#RUN if [ -n $proxy ]; then git config --global http.proxy $proxy; fi

RUN /bin/sh -c set -ex \
    && apk add --no-cache --virtual .build-deps gcc g++ musl-dev zlib-dev \
    #&& git config --global http.proxy http://docker.for.mac.host.internal:1087 \
    && git config --global url."https://github.com/".insteadOf git://github.com/ \
    && git config --global http.version HTTP/1.1 \
    && luarocks install lua-zlib \
    && luarocks install xmlua \
    && luarocks install lua-resty-cookie \
    && luarocks install lua-resty-template \
    && apk del .build-deps
USER kong

COPY resty-patch/websocket/client.lua /usr/local/openresty/lualib/resty/websocket/client.lua
COPY .kong-patch/kong/ /usr/local/share/lua/5.1/kong/
