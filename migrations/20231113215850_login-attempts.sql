/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

CREATE TABLE IF NOT EXISTS `warchief_login_attempts` (
  `attempt_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `id` bigint(20) NOT NULL COMMENT 'Account id',
  `date` bigint(40) NOT NULL DEFAULT UNIX_TIMESTAMP(NOW()) COMMENT 'Attempt date',
  `ip` varchar(30) NOT NULL,
  `successful` tinyint(1) NOT NULL COMMENT 'Successful login attempt',
  `fail_reason` varchar(50) NOT NULL DEFAULT '' COMMENT 'Reason for login failure (if not successful)',
  PRIMARY KEY (`id`,`date`),
  UNIQUE KEY `attempt_id` (`attempt_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
