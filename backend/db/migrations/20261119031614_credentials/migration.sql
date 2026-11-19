CREATE TABLE "credentialTemplates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"siteId" uuid NOT NULL,
	"key" varchar(64) NOT NULL,
	"name" varchar(255) NOT NULL,
	"icon" varchar(255),
	"fields" jsonb DEFAULT '[]' NOT NULL,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"siteId" uuid NOT NULL,
	"path" varchar(255) NOT NULL,
	"key" varchar(128) NOT NULL,
	"templateId" uuid NOT NULL,
	"name" varchar(255) NOT NULL,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"fields" jsonb DEFAULT '{}' NOT NULL,
	"secrets" bytea,
	"secretFields" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"keyId" varchar(16),
	"ts" tsvector,
	"createdBy" uuid,
	"updatedBy" uuid,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL,
	"secretsUpdatedAt" timestamp,
	CONSTRAINT "credentials_keyId_check" CHECK (("secrets" IS NULL) = ("keyId" IS NULL)),
	CONSTRAINT "credentials_secrets_check" CHECK ("secrets" IS NULL OR substring("secrets" FROM 1 FOR 4) = 'WKC1'::bytea)
);
--> statement-breakpoint
CREATE UNIQUE INDEX "credentialTemplates_siteId_key_key" ON "credentialTemplates" ("siteId","key");--> statement-breakpoint
CREATE UNIQUE INDEX "credentials_siteId_path_key_key" ON "credentials" ("siteId","path","key");--> statement-breakpoint
CREATE INDEX "credentials_templateId_idx" ON "credentials" ("templateId");--> statement-breakpoint
CREATE INDEX "credentials_ts_idx" ON "credentials" USING gin ("ts");--> statement-breakpoint
ALTER TABLE "credentialTemplates" ADD CONSTRAINT "credentialTemplates_siteId_sites_id_fkey" FOREIGN KEY ("siteId") REFERENCES "sites"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_siteId_sites_id_fkey" FOREIGN KEY ("siteId") REFERENCES "sites"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_templateId_credentialTemplates_id_fkey" FOREIGN KEY ("templateId") REFERENCES "credentialTemplates"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_createdBy_users_id_fkey" FOREIGN KEY ("createdBy") REFERENCES "users"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_updatedBy_users_id_fkey" FOREIGN KEY ("updatedBy") REFERENCES "users"("id") ON DELETE SET NULL;