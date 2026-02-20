FROM nginxinc/nginx-unprivileged:stable-alpine

COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/web/dist/ /usr/share/nginx/html/

EXPOSE 8080
