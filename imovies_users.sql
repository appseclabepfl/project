/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Create database
--
CREATE DATABASE /*!32312 IF NOT EXISTS*/`imovies_users` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `imovies_users`;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `uid` varchar(64) NOT NULL DEFAULT '',
  `lastname` varchar(64) NOT NULL DEFAULT '',
  `firstname` varchar(64) NOT NULL DEFAULT '',
  `email` varchar(64) NOT NULL DEFAULT '',
  `pwd` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`uid`)
) ENCRYPTION='Y' ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('ps','Schaller','Patrick','ps@imovies.ch','6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7'),('lb','Bruegger','Lukas','lb@imovies.ch','8d0547d4b27b689c3a3299635d859f7d50a2b805'),('ms','Schlaepfer','Michael','ms@imovies.ch','4d7de8512bd584c3137bb80f453e61306b148875'),('a3','Anderson','Andres Andrea','anderson@imovies.ch','6b97f534c330b5cc78d4cc23e01e48be3377105b');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;


-- USERS AND PERMISSIONS

USE `mysql`;

--
-- Clean old users and permissions
--
DROP USER IF EXISTS `coreca`@`10.10.10.3`;
DROP USER IF EXISTS `backup`@`10.10.10.4`;
DROP USER IF EXISTS `webserver`@`10.10.20.2`;

--
-- Create users, bind them to their address and grant permissions
--
CREATE USER `coreca`@`10.10.10.3` IDENTIFIED BY 'database';
CREATE USER `backup`@`10.10.10.4` IDENTIFIED BY 'database';
CREATE USER `webserver`@`10.10.20.2` IDENTIFIED BY 'database';

REVOKE ALL PRIVILEGES ON *.* FROM `coreca`@`10.10.10.3`;
REVOKE ALL PRIVILEGES ON *.* FROM `backup`@`10.10.10.4`;
REVOKE ALL PRIVILEGES ON *.* FROM `webserver`@`10.10.20.2`;

GRANT SELECT ON `imovies_users`.`users` TO `coreca`@`10.10.10.3`;
GRANT CREATE ON *.* TO `backup`@`10.10.10.4`;
GRANT INSERT ON `imovies_users`.`users` TO `backup`@`10.10.10.4`;
GRANT SELECT, UPDATE ON `imovies_users`.`users` TO `webserver`@`10.10.20.2`;

FLUSH PRIVILEGES;
