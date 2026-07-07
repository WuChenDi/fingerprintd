CREATE TABLE `blocking_index` (
	`key` text NOT NULL,
	`visitor_id` text NOT NULL,
	PRIMARY KEY(`key`, `visitor_id`)
);
--> statement-breakpoint
CREATE INDEX `idx_blocking_index_key` ON `blocking_index` (`key`);--> statement-breakpoint
CREATE TABLE `templates` (
	`visitor_id` text PRIMARY KEY NOT NULL,
	`components` text NOT NULL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL,
	`observation_count` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `value_frequency` (
	`value_hash` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL
);
