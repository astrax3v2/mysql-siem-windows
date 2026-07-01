# MySQL SIEM SOP (Windows)

1. Edit my.ini:
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini

2. Add:
[mysqld]
general_log=1
general_log_file="C:/ProgramData/MySQL/MySQL Server 8.0/Data/mysql.log"
slow_query_log=1
slow_query_log_file="C:/ProgramData/MySQL/MySQL Server 8.0/Data/mysql-slow.log"
log_error="C:/ProgramData/MySQL/MySQL Server 8.0/Data/mysql-error.log"

3. Restart:
net stop MySQL80
net start MySQL80
