CREATE TABLE `checkin_events` (
	`account_id` text NOT NULL,
	`visitor_id` text NOT NULL,
	`ip` text NOT NULL,
	`ts` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_checkin_events_visitor_ts` ON `checkin_events` (`visitor_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_account_ts` ON `checkin_events` (`account_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_ip_ts` ON `checkin_events` (`ip`,`ts`);