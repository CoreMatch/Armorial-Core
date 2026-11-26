CREATE TABLE IF NOT EXISTS `core_user_migrations` (
  `migration_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `uid` int unsigned NOT NULL DEFAULT 0,
  `uuid` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `email` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `username` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ownership` enum('none','created_by_migration','preexisting') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'none',
  `status` enum('not_created','created','rolled_back') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'not_created',
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  `rolled_back_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`migration_id`),
  KEY `idx_core_user_migrations_uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
