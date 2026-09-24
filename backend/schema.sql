CREATE DATABASE IF NOT EXISTS infra_risk_radar;
USE infra_risk_radar;

CREATE TABLE IF NOT EXISTS projects (
  id VARCHAR(20) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  ministry VARCHAR(100),
  sector VARCHAR(100),
  state VARCHAR(100),
  risk ENUM('High','Medium','Low') DEFAULT 'Medium',
  progress INT DEFAULT 0,
  original_cost DECIMAL(14,2) DEFAULT 0,
  revised_cost DECIMAL(14,2) DEFAULT 0,
  expenditure DECIMAL(14,2) DEFAULT 0,
  start_date VARCHAR(50),
  completion_date VARCHAR(50),
  status VARCHAR(50),
  lat DECIMAL(10,6),
  lng DECIMAL(10,6),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  level VARCHAR(30),
  project_id VARCHAR(20),
  message TEXT,
  alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  acknowledged BOOLEAN DEFAULT FALSE,
  FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE SET NULL
);