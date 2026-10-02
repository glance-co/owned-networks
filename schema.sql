-- Independently operable signed public networks. These tables have no founder,
-- user-account, email, Gmail or application-session ownership relationships.
CREATE TABLE "OwnedNetwork" (
  "host" VARCHAR(2048) NOT NULL,
  "id" UUID NOT NULL,
  "sequence" INTEGER NOT NULL,
  "head" VARCHAR(43) NOT NULL,
  "frozen" BOOLEAN NOT NULL DEFAULT FALSE,
  "destination" VARCHAR(2048),
  "journalCiphertext" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL,
  "updatedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "OwnedNetwork_pkey" PRIMARY KEY ("host","id"),
  CONSTRAINT "OwnedNetwork_sequence_positive" CHECK ("sequence">0),
  CONSTRAINT "OwnedNetwork_frozen_destination" CHECK (("frozen" AND "destination" IS NOT NULL AND "destination"<>"host") OR (NOT "frozen" AND "destination" IS NULL))
);
CREATE TABLE "OwnedNetworkRate" (
  "key" VARCHAR(64) NOT NULL,
  "windowAt" TIMESTAMPTZ(3) NOT NULL,
  "count" INTEGER NOT NULL,
  "expiresAt" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "OwnedNetworkRate_pkey" PRIMARY KEY ("key"),
  CONSTRAINT "OwnedNetworkRate_count_positive" CHECK ("count">0)
);
CREATE INDEX "OwnedNetworkRate_expiresAt_idx" ON "OwnedNetworkRate" ("expiresAt");
