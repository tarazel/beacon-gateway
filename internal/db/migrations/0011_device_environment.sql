-- APNs environment per device. A device token is only valid against the APNs
-- environment of the build that registered it (Xcode development-signed builds
-- get sandbox tokens; TestFlight / App Store builds get production tokens), so a
-- single gateway-wide setting cannot serve both.
--
-- NULL = the client didn't report one (older iOS builds, Android); the gateway
-- falls back to APNS_USE_SANDBOX.
ALTER TABLE devices ADD COLUMN environment TEXT
    CHECK (environment IN ('production', 'sandbox'));
