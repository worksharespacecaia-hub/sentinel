# 行銷活動網站（WordPress）。PHP 8.1 已停止支援；mod_php（apache2handler）
FROM php:8.1-apache
COPY php.ini /usr/local/etc/php/conf.d/marketing.ini
COPY wp-content/ /var/www/html/wp-content/
EXPOSE 80
