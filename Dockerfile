FROM php:8.2-apache
RUN apt-get update && apt-get install -y \
    git \
    unzip
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
WORKDIR /var/www/html
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80