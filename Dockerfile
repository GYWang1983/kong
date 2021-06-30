FROM 10.20.42.253/library/kong:2.2.1

USER root
RUN /bin/sh -c set -ex \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache libuuid \
    && apk add --no-cache --virtual .build-deps gcc musl-dev zlib-dev \
    && luarocks install lua-zlib \
    && apk del .build-deps
USER kong

COPY kong/db/strategies/postgres/init.lua /usr/local/share/lua/5.1/kong/db/strategies/postgres/init.lua
COPY kong/db/schema/metaschema.lua /usr/local/share/lua/5.1/kong/db/schema/metaschema.lua
COPY kong/init.lua /usr/local/share/lua/5.1/kong/init.lua
COPY kong/templates/*.lua /usr/local/share/lua/5.1/kong/templates/

## ENTRYPOINT ["java", "-jar", "/opt/service/app.jar"]
