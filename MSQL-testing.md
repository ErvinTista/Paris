### Get the version of MSSQL
> SELECT @@version

### Get current username
> SELECT user_name()

### Get all users
> SELECT * FROM sys.database_principals

### Get databases
> SELECT * FROM master.dbo.sysdatabases

### Switch to the database
> USE <database>

### List tables
> SELECT * FROM information_schema.tables

### Get table content
> SELECT * FROM <database_name>.dbo.<table_name>


### Check if the current user have permission to execute OS command
> USE master
> EXEC sp_helprotect 'xp_cmdshell'

### Get linked servers
> EXEC sp_linkedservers
> SELECT * FROM sys.servers

### Create a new user with sysadmin privilege
> CREATE LOGIN tester WITH PASSWORD = 'password'
> EXEC sp_addsrvrolemember 'tester', 'sysadmin'

### List directories
> xp_dirtree '.\'
> xp_dirtree 'C:\inetpub\'
> xp_dirtree 'C:\inetpub\wwwroot\'
> xp_dirtree 'C:\Users\'
