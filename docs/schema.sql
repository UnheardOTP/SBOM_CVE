-- ─────────────────────────────────────────────────────────────────
-- SBOM CVE Scanner — Database Schema
-- Run this once to set up the database.
-- ─────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS sbom_cve
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE sbom_cve;


-- ─── DB User Creation (for Docker/automation) ───────────────
-- These can use Docker env substitution or manual editing before running.
-- Replace ${DB_USER} and ${DB_PASSWORD} with your values or use Docker entrypoint substitution.
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON sbom_cve.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;


-- ─── Users ───────────────────────────────────────────────────────
-- User accounts for login and scan separation

CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(64)     NOT NULL UNIQUE,
    password_hash   VARCHAR(255)    NOT NULL,
    force_password_change BOOLEAN    NOT NULL DEFAULT 0,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;



-- ─── Scans ────────────────────────────────────────────────────────
-- Top-level record for each scan run
CREATE TABLE IF NOT EXISTS scans (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED    NOT NULL,
    company_name    VARCHAR(255)    NOT NULL DEFAULT 'Unknown',
    component_count INT UNSIGNED    NOT NULL DEFAULT 0,
    cve_count       INT UNSIGNED    NOT NULL DEFAULT 0,
    scan_date       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_company   (company_name),
    INDEX idx_scan_date (scan_date),
    INDEX idx_scan_user_id (user_id),
    CONSTRAINT fk_scan_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Scan Components ─────────────────────────────────────────────
-- Individual components that were scanned
CREATE TABLE IF NOT EXISTS scan_components (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id     INT UNSIGNED    NOT NULL,
    name        VARCHAR(255)    NOT NULL,
    version     VARCHAR(100)    DEFAULT '',
    ecosystem   VARCHAR(100)    DEFAULT '',

    INDEX idx_scan_id (scan_id),
    CONSTRAINT fk_comp_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Scan CVEs ────────────────────────────────────────────────────
-- CVEs found during a scan
CREATE TABLE IF NOT EXISTS scan_cves (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id             INT UNSIGNED    NOT NULL,
    cve_id              VARCHAR(30)     NOT NULL,       -- e.g. CVE-2023-12345
    component           VARCHAR(255)    NOT NULL,
    component_version   VARCHAR(100)    DEFAULT '',
    description         TEXT,
    cvss_score          DECIMAL(4,1),                   -- e.g. 9.8
    severity            ENUM('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')
                        NOT NULL DEFAULT 'UNKNOWN',
    vector_string       VARCHAR(255)    DEFAULT '',
    affected_versions   JSON,                           -- array of version range strings
    nvd_url             VARCHAR(512)    DEFAULT '',
    published           DATE,
    last_modified       DATE,

    INDEX idx_scan_id   (scan_id),
    INDEX idx_cve_id    (cve_id),
    INDEX idx_severity  (severity),
    INDEX idx_score     (cvss_score),
    CONSTRAINT fk_cve_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB;
