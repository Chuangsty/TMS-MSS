CREATE DATABASE IF NOT EXISTS tms_mss;
USE tms_mss;

-- =========================
-- SECTION 1: ACCESS CONTROL
-- =========================

-- Account status table
CREATE TABLE IF NOT EXISTS account_status(
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(20) NOT NULL UNIQUE,
    status_name VARCHAR(50) NOT NULL UNIQUE
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    account_status_id INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_users_account_status
    FOREIGN KEY (account_status_id) REFERENCES account_status(id)
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles(
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(20) NOT NULL UNIQUE,
    role_name VARCHAR(50) NOT NULL UNIQUE
);

-- Permissions table
CREATE TABLE IF NOT EXISTS user_permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(50) NOT NULL UNIQUE,
  description VARCHAR(100)
);

-- User roles (many to many) table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),

    CONSTRAINT fk_user_roles_users
    FOREIGN KEY (user_id) REFERENCES users(id),

    CONSTRAINT fk_user_roles_roles
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Indexing for better query
CREATE INDEX idx_user_roles_role ON user_roles(role_id);

-- ===========================================
-- SECTION 1.1: ACCESS CONTROL PERMISSIONS
-- ===========================================

-- Role's permissions
CREATE TABLE IF NOT EXISTS role_user_permissions (
  role_id INT NOT NULL,
  user_permissions_id INT NOT NULL,
  PRIMARY KEY (role_id, user_permissions_id),

  CONSTRAINT fk_role_permissions_roles
    FOREIGN KEY (role_id) REFERENCES roles(id),

  CONSTRAINT fk_role_permissions_permissions
    FOREIGN KEY (user_permissions_id) REFERENCES user_permissions(id)
);

-- Indexing for better query
CREATE INDEX idx_role_permissions_permission ON role_user_permissions(user_permissions_id);

-- =========================
-- SECTION 2: WORKFLOW
-- =========================

-- States of progress for apps and plans
CREATE TABLE IF NOT EXISTS states (
  id INT AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(20) NOT NULL UNIQUE,
  state_name VARCHAR(50) NOT NULL
);

-- States of progress for tasks
CREATE TABLE IF NOT EXISTS task_states (
  id INT AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(20) NOT NULL UNIQUE,
  task_state_name VARCHAR(50) NOT NULL
);

-- Apps table
CREATE TABLE IF NOT EXISTS apps (
  id INT AUTO_INCREMENT PRIMARY KEY,
  appName VARCHAR(50) NOT NULL,
  appDescription TEXT,
  project_lead INT NOT NULL,
  startDate TIMESTAMP NULL,
  endDate TIMESTAMP NULL,
  states_id INT NOT NULL DEFAULT 1,

  CONSTRAINT fk_apps_project_lead
    FOREIGN KEY (project_lead) REFERENCES users(id),

  CONSTRAINT fk_apps_status
    FOREIGN KEY (states_id) REFERENCES states(id)
);

-- Plans table
CREATE TABLE IF NOT EXISTS plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  planName VARCHAR(50) NOT NULL,
  app_id INT NOT NULL,
  project_manager INT NOT NULL,
  startDate TIMESTAMP NULL,
  endDate TIMESTAMP NULL,
  states_id INT NOT NULL DEFAULT 1,

  CONSTRAINT fk_plans_app
    FOREIGN KEY (app_id) REFERENCES apps(id),

  CONSTRAINT fk_plans_pm
    FOREIGN KEY (project_manager) REFERENCES users(id),

  CONSTRAINT fk_plans_status
    FOREIGN KEY (states_id) REFERENCES states(id)
);

-- Tasks table
CREATE TABLE IF NOT EXISTS tasks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  taskName VARCHAR(50) NOT NULL,
  task_description TEXT,
  update_note TEXT,
  app_id INT NOT NULL,
  plan_id INT NULL,
  dev INT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  taken_at TIMESTAMP NULL,
  update_at TIMESTAMP NULL,
  task_state_id INT NOT NULL DEFAULT 1,

  CONSTRAINT fk_tasks_app
    FOREIGN KEY (app_id) REFERENCES apps(id),

  CONSTRAINT fk_tasks_plan
    FOREIGN KEY (plan_id) REFERENCES plans(id),

  CONSTRAINT fk_tasks_dev
    FOREIGN KEY (dev) REFERENCES users(id),

  CONSTRAINT fk_tasks_state
    FOREIGN KEY (task_state_id) REFERENCES task_states(id)
);

-- Indexing for better query
CREATE INDEX idx_tasks_app_state ON tasks(app_id, task_state_id);
CREATE INDEX idx_tasks_plan ON tasks(plan_id);
CREATE INDEX idx_tasks_dev ON tasks(dev);