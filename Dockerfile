FROM php:8.2-apache
WORKDIR /var/www/html
RUN apt-get update && apt-get install -y \
    git \
    unzip
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
COPY . .
RUN composer install --no-interaction --no-dev --optimize-autoloader
RUN chown -R www-data:www-data /var/www/html