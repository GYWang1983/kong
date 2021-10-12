FROM 10.20.42.253/library/kong:2.2.1

#USER root
RUN /bin/sh -c set -ex \
    && sudo sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    # && apk add --no-cache libuuid \
    && sudo apk add libxml2 \
    && sudo apk add --no-cache --virtual .build-deps gcc g++ musl-dev zlib-dev \
    && luarocks install lua-zlib \
    && luarocks install xmlua \
    && sudo apk del .build-deps
#USER kong

COPY kong/db/strategies/postgres/init.lua /usr/local/share/lua/5.1/kong/db/strategies/postgres/init.lua
COPY kong/db/schema/init.lua /usr/local/share/lua/5.1/kong/db/schema/init.lua
COPY kong/db/schema/metaschema.lua /usr/local/share/lua/5.1/kong/db/schema/metaschema.lua
COPY kong/db/dao/init.lua /usr/local/share/lua/5.1/kong/db/dao/init.lua
COPY kong/init.lua /usr/local/share/lua/5.1/kong/init.lua
COPY kong/cache.lua /usr/local/share/lua/5.1/kong/cache.lua
COPY kong/templates/*.lua /usr/local/share/lua/5.1/kong/templates/

## ENTRYPOINT ["java", "-jar", "/opt/service/app.jar"]
