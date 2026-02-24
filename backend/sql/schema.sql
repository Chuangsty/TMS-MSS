CREATE DATABASE IF NOT EXISTS tms_mss;
USE tms_mss;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    account_status_id INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_users_account_status
    FOREIGN KEY (account_status_id) REFERENCES account_status(id)
);

-- Account status table
CREATE TABLE IF NOT EXISTS account_status(
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(20) NOT NULL UNIQUE,
    status_name VARCHAR(50) NOT NULL UNIQUE
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles(
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(20) NOT NULL UNIQUE,
    role_name VARCHAR(50) NOT NULL UNIQUE
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