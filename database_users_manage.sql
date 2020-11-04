-- USERS AND PERMISSIONS

USE `mysql`;

--
-- Clean old users and permissions
--
DROP USER IF EXISTS `webserver`@`localhost`;

--
-- Create users, bind them to their address and grant permissions
--
CREATE USER `webserver`@`localhost` IDENTIFIED BY 'a$V&kG!He7z-q#XV';

REVOKE ALL PRIVILEGES ON *.* FROM `webserver`@`localhost`;

GRANT SELECT, UPDATE ON `imovies_users`.`users` TO `webserver`@`localhost`;

FLUSH PRIVILEGES;
