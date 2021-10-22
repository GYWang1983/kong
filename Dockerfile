FROM kong:2.5.1

USER root
RUN /bin/sh -c set -ex \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    # && apk add --no-cache libuuid \
    && apk add libxml2 \
    && apk add --no-cache --virtual .build-deps gcc g++ musl-dev zlib-dev \
    && luarocks install lua-zlib \
    && luarocks install xmlua \
    && apk del .build-deps
USER kong

COPY kong/db/strategies/postgres/init.lua /usr/local/share/lua/5.1/kong/db/strategies/postgres/init.lua
COPY kong/db/schema/init.lua /usr/local/share/lua/5.1/kong/db/schema/init.lua
COPY kong/db/schema/metaschema.lua /usr/local/share/lua/5.1/kong/db/schema/metaschema.lua
COPY kong/db/dao/init.lua /usr/local/share/lua/5.1/kong/db/dao/init.lua
COPY kong/init.lua /usr/local/share/lua/5.1/kong/init.lua
COPY kong/cache/init.lua /usr/local/share/lua/5.1/kong/cache/init.lua
COPY kong/templates/*.lua /usr/local/share/lua/5.1/kong/templates/

## ENTRYPOINT ["java", "-jar", "/opt/service/app.jar"]
