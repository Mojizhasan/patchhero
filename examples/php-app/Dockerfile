FROM php:8.3.30-fpm-alpine
WORKDIR /app
COPY . .
RUN docker-php-ext-install pdo pdo_mysql
