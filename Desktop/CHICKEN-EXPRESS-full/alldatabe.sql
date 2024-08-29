CREATE TABLE `aclog` (
  `id` int NOT NULL AUTO_INCREMENT,
  `order_code` int NOT NULL,
  `action_time` datetime NOT NULL,
  `username` varchar(255) NOT NULL,
  `action_type` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `order_code` (`order_code`),
  CONSTRAINT `aclog_ibfk_1` FOREIGN KEY (`order_code`) REFERENCES `ceorder` (`ordercode`)
)



CREATE TABLE `cecustomer` (
  `Cname` varchar(100) DEFAULT NULL,
  `Cphone` varchar(11) NOT NULL,
  `Cgender` varchar(10) DEFAULT NULL,
  `Caddress` varchar(255) DEFAULT NULL,
  `Corder` text,
  `Cnote` text,
  PRIMARY KEY (`Cphone`)
)


CREATE TABLE `cedriver` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `added_by` varchar(50) DEFAULT NULL,
  `token` varchar(512) DEFAULT NULL,
  `fcm_token` text,
  `driverphone` varchar(11) DEFAULT NULL,
  `logged_out` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
)

CREATE TABLE `ceogba` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ogname` varchar(255) DEFAULT NULL,
  `ogdes` varchar(255) DEFAULT NULL,
  `ogpric` decimal(10,2) DEFAULT NULL,
  `ogtofr` tinyint(1) DEFAULT NULL,
  `ogpic` varchar(255) DEFAULT NULL,
  `ogsec` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
)

CREATE TABLE `ceorder` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ordercode` int DEFAULT NULL,
  `Cphone` varchar(255) DEFAULT NULL,
  `Cname` varchar(255) DEFAULT NULL,
  `order` text,
  `location` text,
  `locdesc` varchar(500) DEFAULT NULL,
  `date` date DEFAULT NULL,
  `time` time DEFAULT NULL,
  `statu` varchar(255) DEFAULT NULL,
  `note` text,
  `ordemname` varchar(255) DEFAULT NULL,
  `ordtocost` decimal(10,2) DEFAULT NULL,
  `oroutinzone` varchar(255) DEFAULT NULL,
  `orddiscnt` varchar(10) DEFAULT NULL,
  `pprice` decimal(10,2) DEFAULT NULL,
  `ordtracking` varchar(255) DEFAULT NULL,
  `orddrivename` varchar(255) DEFAULT NULL,
  `order_preparing_start_time` datetime DEFAULT NULL,
  `order_preparing_end_time` datetime DEFAULT NULL,
  `order_delivery_start_time` datetime DEFAULT NULL,
  `order_delivered_time` datetime DEFAULT NULL,
  `wlost` varchar(255) DEFAULT NULL,
  `notelost` text,
  `lostime` datetime DEFAULT NULL,
  `order_uuid` varchar(36) DEFAULT NULL,
  `nearest_branch` varchar(50) DEFAULT NULL,
  `scheduled_time` datetime DEFAULT NULL,
  `delivery_method` enum('delivery','pickup') DEFAULT 'delivery',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ordercode` (`ordercode`)
)

CREATE TABLE `ceusersm` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `level` enum('admin','editor','viewer') NOT NULL,
  `aded_by` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
)

CREATE TABLE `order_cancellations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ordercode` varchar(50) NOT NULL,
  `status` varchar(50) NOT NULL,
  `wlost_reason` varchar(255) NOT NULL,
  `comment` text,
  `cancellation_time` datetime NOT NULL,
  `driver_name` varchar(100) DEFAULT NULL,
  `operation_title` varchar(255) DEFAULT NULL,
  `notification_sent` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`)
)


CREATE TABLE `pit_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pit_number` int NOT NULL,
  `chickens_count` int NOT NULL,
  `date` date NOT NULL,
  `pit_status` enum('not_started','cooking','done') DEFAULT 'not_started',
  `start_time` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `pit_number` (`pit_number`,`date`)
)


CREATE TABLE `printer_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip` varchar(255) NOT NULL,
  `port` int NOT NULL,
  PRIMARY KEY (`id`)
)