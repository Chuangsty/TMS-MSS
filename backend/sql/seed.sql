USE tms_mss;

-- "IGNORE" prevents insert errors

-- Account status
INSERT IGNORE INTO account_status (slug, status_name) values
('ACTIVE', 'Active'),
('DISABLED', 'Disabled');

-- Account status
INSERT IGNORE INTO roles (slug, role_name) values
('ADMIN', 'Admin'),
('PROJECT_LEAD', 'Project Lead'),
('PROJECT_MANAGER', 'PRoject Manager'),
('DEVELOPER','Developer');
