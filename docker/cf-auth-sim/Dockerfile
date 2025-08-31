FROM openresty/openresty:alpine-fat

# Install dependencies
RUN luarocks install lua-resty-http && \
    luarocks install lua-resty-openssl && \
    luarocks install lua-resty-rsa && \
    luarocks install lua-resty-template

# Copy all sources files (nginx/openresty, lua, html)
COPY src/ /