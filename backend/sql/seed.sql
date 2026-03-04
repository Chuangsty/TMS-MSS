USE tms;

-- =========================
-- ACCOUNT STATUS
-- =========================
INSERT IGNORE INTO account_status (slug, status_name) VALUES
('ACTIVE', 'Active'),
('DISABLED', 'Disabled');

-- =========================
-- ROLES
-- =========================
INSERT IGNORE INTO roles (slug, role_name) VALUES
('ADMIN', 'Admin'),
('PROJECT_LEAD', 'Project Lead'),
('PROJECT_MANAGER', 'Project Manager'),
('DEVELOPER', 'Developer');

-- =========================
-- USER PERMISSIONS
-- =========================
INSERT IGNORE INTO user_permissions (slug, description) VALUES
('CREATE_APP', 'Create application'),
('UPDATE_APP', 'Update application'),
('CREATE_TASK', 'Create task'),
('UPDATE_TASK', 'Update task'),
('MANAGE_PLAN', 'Create plan/Edit content'),
('TAKE_ON_TASK', 'Developer takes on task'),
('FORFEIT_TASK', 'Developer forfeit task'),
('SUBMIT_TASK', 'Developer submit task for review'),
('APPROVE_TASK', 'Developer approve task'),
('REJECT_TASK', 'Developer reject task'),
('UPDATE_TASK_NOTE', 'Update task note');

-- =========================
-- ROLE <--> PERMISSIONS
-- =========================
INSERT IGNORE INTO role_user_permissions (role_id, user_permissions_id)
SELECT r.id, p.id
FROM roles r
JOIN user_permissions p
WHERE
    (r.slug = 'ADMIN')
 OR (r.slug = 'PROJECT_LEAD' AND p.slug IN ('CREATE_APP','UPDATE_APP','CREATE_TASK','UPDATE_TASK', 'APPROVE_TASK', 'REJECT_TASK', 'UPDATE_TASK_NOTE'))
 OR (r.slug = 'PROJECT_MANAGER' AND p.slug IN ('MANAGE_PLAN', 'UPDATE_TASK_NOTE'))
 OR (r.slug = 'DEVELOPER' AND p.slug IN ('TAKE_ON_TASK', 'FORFEIT_TASK', 'SUBMIT_TASK', 'UPDATE_TASK_NOTE'));

-- =========================
-- STATES (Apps + Plans)
-- =========================
INSERT IGNORE INTO states (slug, state_name) VALUES
('ON_GOING', 'On-going'),
('COMPLETED', 'Completed');

-- =========================
-- TASK STATES
-- =========================
INSERT IGNORE INTO task_states (slug, task_state_name) VALUES
('OPEN', 'Open'),
('TODO', 'To Do'),
('DOING', 'Doing'),
('DONE', 'Done'),
('CLOSED', 'Closed');