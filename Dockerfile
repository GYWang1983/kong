FROM kong:2.5.1

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
    && apk del .build-deps
USER kong

COPY kong/db/schema/init.lua kong/db/schema/metaschema.lua /usr/local/share/lua/5.1/kong/db/schema/
COPY kong/db/dao/init.lua /usr/local/share/lua/5.1/kong/db/dao/init.lua
COPY kong/db/strategies/postgres/init.lua /usr/local/share/lua/5.1/kong/db/strategies/postgres/init.lua
COPY kong/cache/init.lua /usr/local/share/lua/5.1/kong/cache/init.lua
COPY kong/tools/kong-lua-sandbox.lua /usr/local/share/lua/5.1/kong/tools/kong-lua-sandbox.lua
COPY kong/templates/nginx.lua kong/templates/nginx_kong.lua /usr/local/share/lua/5.1/kong/templates/
