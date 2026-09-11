FROM nginx:1.27-alpine

ARG GIT_SHA=unknown
COPY index.html /usr/share/nginx/html/index.html
RUN sed -i "s/__GIT_SHA__/${GIT_SHA}/" /usr/share/nginx/html/index.html

EXPOSE 80
