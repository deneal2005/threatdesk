-- Generated from threatdesk/models by scripts/export_schema.py. Tables are also created at startup.

CREATE TABLE orgs (
	id SERIAL NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	alert_webhooks TEXT, 
	alert_email VARCHAR(254), 
	PRIMARY KEY (id)
);

CREATE TABLE brands (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	name VARCHAR(80) NOT NULL, 
	official_domains JSON NOT NULL, 
	official_handles JSON NOT NULL, 
	official_apps JSON NOT NULL, 
	keywords JSON NOT NULL, 
	logo_blob BYTEA, 
	logo_phash VARCHAR(32), 
	report_token VARCHAR(64) NOT NULL, 
	scan_interval_hours INTEGER NOT NULL, 
	last_scan_at TIMESTAMP WITHOUT TIME ZONE, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id)
);

CREATE INDEX ix_brands_org_id ON brands (org_id);

CREATE UNIQUE INDEX ix_brands_report_token ON brands (report_token);

CREATE TABLE users (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	email VARCHAR(254) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_findings_visit TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	UNIQUE (email)
);

CREATE INDEX ix_users_org_id ON users (org_id);

CREATE TABLE api_keys (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	key_hash VARCHAR(128) NOT NULL, 
	prefix VARCHAR(12) NOT NULL, 
	label VARCHAR(80) NOT NULL, 
	revoked BOOLEAN NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	created_by INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	UNIQUE (key_hash), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_api_keys_org_id ON api_keys (org_id);

CREATE TABLE assets_whitelist (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER NOT NULL, 
	type VARCHAR(24) NOT NULL, 
	value VARCHAR(300) NOT NULL, 
	reason TEXT NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id)
);

CREATE INDEX ix_assets_whitelist_brand_id ON assets_whitelist (brand_id);

CREATE INDEX ix_assets_whitelist_org_id ON assets_whitelist (org_id);

CREATE TABLE brand_apps (
	platform VARCHAR(10) NOT NULL, 
	store_id VARCHAR(160) NOT NULL, 
	bundle_id VARCHAR(160), 
	name VARCHAR(120) NOT NULL, 
	product VARCHAR(120) NOT NULL, 
	store_url VARCHAR(500) NOT NULL, 
	market VARCHAR(60) NOT NULL, 
	category VARCHAR(60) NOT NULL, 
	id SERIAL NOT NULL, 
	is_primary BOOLEAN NOT NULL, 
	active BOOLEAN NOT NULL, 
	verification_status VARCHAR(12) NOT NULL, 
	verification_method VARCHAR(40), 
	verification_note TEXT, 
	verified_at TIMESTAMP WITHOUT TIME ZONE, 
	verify_token VARCHAR(64) NOT NULL, 
	notes TEXT NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	version INTEGER NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_app_brand_store UNIQUE (brand_id, platform, store_id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id) ON DELETE CASCADE
);

CREATE INDEX ix_brand_apps_brand_id ON brand_apps (brand_id);

CREATE INDEX ix_brand_apps_org_id ON brand_apps (org_id);

CREATE INDEX ix_brand_apps_platform ON brand_apps (platform);

CREATE TABLE brand_social_accounts (
	platform VARCHAR(24) NOT NULL, 
	handle VARCHAR(160) NOT NULL, 
	handle_key VARCHAR(160) NOT NULL, 
	platform_id VARCHAR(120), 
	profile_url VARCHAR(500) NOT NULL, 
	display_name VARCHAR(120) NOT NULL, 
	purpose VARCHAR(120) NOT NULL, 
	region VARCHAR(60) NOT NULL, 
	id SERIAL NOT NULL, 
	is_primary BOOLEAN NOT NULL, 
	active BOOLEAN NOT NULL, 
	verification_status VARCHAR(12) NOT NULL, 
	verification_method VARCHAR(40), 
	verification_note TEXT, 
	verified_at TIMESTAMP WITHOUT TIME ZONE, 
	verify_token VARCHAR(64) NOT NULL, 
	notes TEXT NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	version INTEGER NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_social_brand_handle UNIQUE (brand_id, platform, handle_key), 
	CONSTRAINT uq_social_brand_pid UNIQUE (brand_id, platform, platform_id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id) ON DELETE CASCADE
);

CREATE INDEX ix_brand_social_accounts_brand_id ON brand_social_accounts (brand_id);

CREATE INDEX ix_brand_social_accounts_org_id ON brand_social_accounts (org_id);

CREATE INDEX ix_brand_social_accounts_platform ON brand_social_accounts (platform);

CREATE TABLE brand_websites (
	url VARCHAR(500) NOT NULL, 
	domain VARCHAR(253) NOT NULL, 
	url_key VARCHAR(500) NOT NULL, 
	kind VARCHAR(20) NOT NULL, 
	purpose VARCHAR(120) NOT NULL, 
	id SERIAL NOT NULL, 
	is_primary BOOLEAN NOT NULL, 
	active BOOLEAN NOT NULL, 
	verification_status VARCHAR(12) NOT NULL, 
	verification_method VARCHAR(40), 
	verification_note TEXT, 
	verified_at TIMESTAMP WITHOUT TIME ZONE, 
	verify_token VARCHAR(64) NOT NULL, 
	notes TEXT NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	version INTEGER NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_website_brand_url UNIQUE (brand_id, url_key), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id) ON DELETE CASCADE
);

CREATE INDEX ix_brand_websites_brand_id ON brand_websites (brand_id);

CREATE INDEX ix_brand_websites_domain ON brand_websites (domain);

CREATE INDEX ix_brand_websites_org_id ON brand_websites (org_id);

CREATE TABLE campaigns (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER, 
	label VARCHAR(200) NOT NULL, 
	shared JSON NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id)
);

CREATE INDEX ix_campaigns_brand_id ON campaigns (brand_id);

CREATE INDEX ix_campaigns_org_id ON campaigns (org_id);

CREATE TABLE findings (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER, 
	source VARCHAR(40) NOT NULL, 
	kind VARCHAR(20) NOT NULL, 
	dedupe_key VARCHAR(300) NOT NULL, 
	scope_key VARCHAR(320) NOT NULL, 
	display_name VARCHAR(300) NOT NULL, 
	url TEXT NOT NULL, 
	first_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	score INTEGER NOT NULL, 
	severity VARCHAR(10) NOT NULL, 
	verdict VARCHAR(40) NOT NULL, 
	status VARCHAR(24) NOT NULL, 
	assignee_id INTEGER, 
	summary_ai TEXT, 
	ai_json JSON, 
	is_user_submitted BOOLEAN NOT NULL, 
	in_triage BOOLEAN NOT NULL, 
	checks_ran INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_finding_scope UNIQUE (org_id, scope_key), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id), 
	FOREIGN KEY(assignee_id) REFERENCES users (id)
);

CREATE INDEX ix_findings_brand_id ON findings (brand_id);

CREATE INDEX ix_findings_org_id ON findings (org_id);

CREATE INDEX ix_findings_status ON findings (status);

CREATE TABLE jobs (
	id SERIAL NOT NULL, 
	org_id INTEGER, 
	type VARCHAR(24) NOT NULL, 
	payload JSON NOT NULL, 
	status VARCHAR(10) NOT NULL, 
	attempts INTEGER NOT NULL, 
	max_attempts INTEGER NOT NULL, 
	error TEXT, 
	result JSON, 
	run_after TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	started TIMESTAMP WITHOUT TIME ZONE, 
	finished TIMESTAMP WITHOUT TIME ZONE, 
	created_by INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_jobs_org_id ON jobs (org_id);

CREATE INDEX ix_jobs_run_after ON jobs (run_after);

CREATE INDEX ix_jobs_status ON jobs (status);

CREATE TABLE campaign_findings (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	campaign_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(campaign_id) REFERENCES campaigns (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_campaign_findings_campaign_id ON campaign_findings (campaign_id);

CREATE INDEX ix_campaign_findings_finding_id ON campaign_findings (finding_id);

CREATE INDEX ix_campaign_findings_org_id ON campaign_findings (org_id);

CREATE TABLE case_events (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	user_id INTEGER, 
	type VARCHAR(16) NOT NULL, 
	body TEXT NOT NULL, 
	to_status VARCHAR(24), 
	at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE INDEX ix_case_events_finding_id ON case_events (finding_id);

CREATE INDEX ix_case_events_org_id ON case_events (org_id);

CREATE TABLE check_results (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	"check" VARCHAR(40) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	detail JSON NOT NULL, 
	ran_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_check_results_finding_id ON check_results (finding_id);

CREATE INDEX ix_check_results_org_id ON check_results (org_id);

CREATE TABLE evidence (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	kind VARCHAR(40) NOT NULL, 
	captured_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	content_json JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_evidence_finding_id ON evidence (finding_id);

CREATE INDEX ix_evidence_org_id ON evidence (org_id);

CREATE TABLE indicators (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	type VARCHAR(16) NOT NULL, 
	value VARCHAR(300) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_indicator UNIQUE (finding_id, type, value), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_indicators_finding_id ON indicators (finding_id);

CREATE INDEX ix_indicators_org_id ON indicators (org_id);

CREATE INDEX ix_indicators_value ON indicators (value);

CREATE TABLE notifications (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	finding_id INTEGER, 
	text TEXT NOT NULL, 
	read BOOLEAN NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_notifications_org_id ON notifications (org_id);

CREATE TABLE reports_intake (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	brand_id INTEGER NOT NULL, 
	reporter_contact VARCHAR(200), 
	url TEXT, 
	text TEXT, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	finding_id INTEGER, 
	job_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(brand_id) REFERENCES brands (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id)
);

CREATE INDEX ix_reports_intake_brand_id ON reports_intake (brand_id);

CREATE INDEX ix_reports_intake_org_id ON reports_intake (org_id);

CREATE TABLE signals (
	id SERIAL NOT NULL, 
	org_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	code VARCHAR(60) NOT NULL, 
	points INTEGER NOT NULL, 
	evidence TEXT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(org_id) REFERENCES orgs (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);

CREATE INDEX ix_signals_finding_id ON signals (finding_id);

CREATE INDEX ix_signals_org_id ON signals (org_id);
