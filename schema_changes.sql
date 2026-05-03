-- SQL migrations needed for the new features
-- Run these against your corporate_wear database

-- 1. Add return_required and stock_risk flags to products
ALTER TABLE products 
  ADD COLUMN IF NOT EXISTS return_required TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS stock_risk TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS price_eur DECIMAL(10,2) DEFAULT NULL;

-- 2. Add first_name / last_name to users (keep full_name for backwards compat)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS first_name VARCHAR(100) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS last_name VARCHAR(100) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS employee_id VARCHAR(50) DEFAULT NULL;

-- 3. Add department to order_carts
ALTER TABLE order_carts
  ADD COLUMN IF NOT EXISTS department VARCHAR(100) DEFAULT NULL;

-- 4. Add return_note to user_uniforms
ALTER TABLE user_uniforms
  ADD COLUMN IF NOT EXISTS return_note TEXT DEFAULT NULL;

-- 5. Add archived_at to team_members (for 6-month archive)
ALTER TABLE team_members
  ADD COLUMN IF NOT EXISTS archived_at DATETIME DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS is_archived TINYINT(1) NOT NULL DEFAULT 0;

-- 6. Add out_of_stock flag to order_items
ALTER TABLE order_items
  ADD COLUMN IF NOT EXISTS out_of_stock TINYINT(1) NOT NULL DEFAULT 0;

-- 7. Ensure order_carts has facility_id
ALTER TABLE order_carts
  ADD COLUMN IF NOT EXISTS facility_id INT DEFAULT NULL;

-- Backfill first_name / last_name from full_name
UPDATE users SET 
  first_name = TRIM(SUBSTRING_INDEX(full_name, ' ', 1)),
  last_name = TRIM(SUBSTRING(full_name, LOCATE(' ', full_name)+1))
WHERE first_name IS NULL AND full_name IS NOT NULL;

-- 8. User extra roles (multiple roles per user)
CREATE TABLE IF NOT EXISTS user_extra_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    job_role_id INT NOT NULL,
    UNIQUE KEY unique_user_role (user_id, job_role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (job_role_id) REFERENCES job_roles(id) ON DELETE CASCADE
);
