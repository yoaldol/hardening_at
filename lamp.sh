#!/bin/bash

# fresh installation script for a basic LAMP stack on an ubuntu 18 box
# setup the below variables and run this script as root to set it all up

# NOTE: you must run this as root, and must have an SSH key already in ~/.ssh/authorized_keys

# TODO: Consider prompting for all of these settings:
# apache settings
DOMAIN=your_domain.com

# ssh user settings
USER=your_ssh_username
PASS=your_ssh_password

# mysql settings
DB_ROOT_PASS=your_mysql_root_pass
DB_NAME=mysql_database
DB_USER=your_mysql_user
# make sure this password is complex: uppercase, lowercase, numeric, and symbol
DB_PASS=abcABC123!

#### START ####
# upgrade packages
apt update && apt -y upgrade

#### APACHE ####
# domain virtualhost
# https://www.digitalocean.com/community/tutorials/how-to-install-the-apache-web-server-on-ubuntu-18-04
apt install -y apache2
ufw allow 'Apache Full'

# create html dir
mkdir /var/www/$DOMAIN
chown $USER:USER /var/www/$DOMAIN

# create index page
echo "
<html>
    <head>
        <title>Welcome to $DOMAIN!</title>
    </head>
    <body>
        <h1>Success! The $DOMAIN virtual host is working!</h1>
    </body>
</html>" >> /var/www/$DOMAIN/index.html

# create virtualhost configuration
echo "
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot /var/www/$DOMAIN
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
" >> /etc/apache2/sites-available/$DOMAIN.conf

# enable virtualhost
a2ensite $DOMAIN.conf
a2dissite 000-default.conf

# setup php
apt install -y php7.2
apt install -y php7.2-mysql
apt install -y php7.2-xml
a2enmod php7.2

# allow ssl
a2enmod ssl

# restart apache
systemctl restart apache2

#### MYSQL ####
apt install -y mysql-server
mysql_secure_installation --use-default --password=$DB_ROOT_PASS

# create database, user, and grant access
mysql -u root -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
mysql -u root -e "CREATE DATABASE $DB_NAME;"
mysql -u root -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION;"

#### SSH ####
ufw allow OpenSSH
echo "y" | ufw enable

# create user
adduser --disabled-password --gecos "" $USER
echo "$USER:$PASS" | chpasswd

# add to sudoers
usermod -aG sudo $USER

# copy ssh keys
rsync --archive --chown=$USER:$USER ~/.ssh /home/$USER