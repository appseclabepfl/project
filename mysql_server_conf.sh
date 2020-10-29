#!/bin/bash


CONTENT="# Copyright (c) 2014, 2017, Oracle and/or its affiliates. All rights reserved.\n
#\n
# This program is free software; you can redistribute it and/or modify\n
# it under the terms of the GNU General Public License, version 2.0,\n
# as published by the Free Software Foundation.\n
#\n
# This program is also distributed with certain software (including\n
# but not limited to OpenSSL) that is licensed under separate terms,\n
# as designated in a particular file or component or in included license\n
# documentation.  The authors of MySQL hereby grant you an additional\n
# permission to link the program and your derivative works with the\n
# separately licensed software that they have included with MySQL.\n
#\n
# This program is distributed in the hope that it will be useful,\n
# but WITHOUT ANY WARRANTY; without even the implied warranty of\n
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n
# GNU General Public License, version 2.0, for more details.\n
#\n
# You should have received a copy of the GNU General Public License\n
# along with this program; if not, write to the Free Software\n
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA\n
\n
#\n
# The MySQL  Server configuration file.\n
#\n
# For explanations see\n
# http://dev.mysql.com/doc/mysql/en/server-system-variables.html\n
\n
\n
[mysqld]\n
pid-file		= /var/run/mysqld/mysqld.pid\n
socket			= /var/run/mysqld/mysqld.sock\n
datadir			= /var/lib/mysql\n
log-error		= /var/log/mysql/error.log\n
early-plugin-load	= keyring_file.so\n
innodb_redo_log_encrypt = ON\n
binlog_encryption	= ON\n
\n
\n
[server]\n
bind_address		= localhost"

echo -e $CONTENT > /etc/mysql/mysql.conf.d/mysqld.cnf
