from dotenv import load_dotenv
load_dotenv()

LOW_STOCK_THRESHOLD = 2
import os
import io
import uuid
import pandas as pd
from datetime import date, datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, send_from_directory
import mysql.connector
from mysql.connector import IntegrityError
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from werkzeug.utils import secure_filename

# Optional: email sending
try:
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    EMAIL_ENABLED = True
except Exception:
    EMAIL_ENABLED = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("static/reports", exist_ok=True)

# ─────────────────────────────────────────────
# DB CONNECTION  (adjust env vars as needed)
# ─────────────────────────────────────────────
def get_db_config():
    config = dict(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", 3306)),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", "1234"),
        database=os.environ.get("DB_NAME", "corporate_wear"),
        buffered=True,
        ssl_disabled=False,
        ssl_verify_cert=False,
        ssl_ca=None,  
        connection_timeout=10,
        
    )
    return config

db = None
_pool = None

def get_pool():
    global _pool
    if _pool is None:
        _pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name="apppool",
            pool_size=5,
            **get_db_config()
        )
    return _pool

def get_db():
    global db
    if db is None or not db.is_connected():
        try:
            db = mysql.connector.connect(**get_db_config())
        except Exception:
            db = mysql.connector.connect(**get_db_config())
    return db

def get_cursor():
    try:
        conn = get_pool().get_connection()
        cursor = conn.cursor(dictionary=True)
        # Wrap cursor so connection is returned to pool on close
        original_close = cursor.close
        def close_and_return():
            original_close()
            conn.close()
        cursor.close = close_and_return
        return cursor
    except Exception:
        # Fallback to global connection
        global db
        db = mysql.connector.connect(**get_db_config())
        return db.cursor(dictionary=True)

# ─────────────────────────────────────────────
# EMAIL HELPER
# ─────────────────────────────────────────────
def send_welcome_email(to_email, full_name, system_role, site_url=None):
    import ssl, threading
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", 465))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    from_addr = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_host or not smtp_user:
        print("[EMAIL] Skipping - not configured")
        return

    url = site_url or os.environ.get("SITE_URL", "http://localhost:5000")
    subject = "Your DHL Corporate Wear account has been created"
    body = f"""Hi {full_name},

Your account as {system_role} has been created in the DHL Corporate Wear uniform system.

You can log in here: {url}/login

Best regards,
DHL Corporate Wear Team"""

    def _send():
        try:
            msg = MIMEMultipart()
            msg["From"] = from_addr
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, to_email, msg.as_string())
            print(f"[EMAIL] Sent successfully to {to_email}")
        except Exception as e:
            print(f"[EMAIL] Failed to send to {to_email}: {e}")

    threading.Thread(target=_send, daemon=True).start()


def send_status_email(to_email, full_name, cart_id, status):
    import ssl, threading
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_port = int(os.environ.get("SMTP_PORT", 465))
    from_addr = os.environ.get("SMTP_FROM", smtp_user)
    site_url = os.environ.get("SITE_URL", "http://localhost:5000")
    if not smtp_host or not smtp_user:
        return
    status_label = "packed and ready for delivery" if status == "packed" else "completed and delivered"
    subject = f"Order #{cart_id} has been {status}"
    body = f"""Hi {full_name},

Your order #{cart_id} has been {status_label}.

View it here: {site_url}/order/{cart_id}

Best regards,
DHL Corporate Wear Team"""

    def _send():
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import smtplib
            msg = MIMEMultipart()
            msg["From"] = from_addr
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, to_email, msg.as_string())
        except Exception as e:
            print(f"[EMAIL] Status email failed: {e}")
    threading.Thread(target=_send, daemon=True).start()
# ─────────────────────────────────────────────
def can_act_for_supervisor(real_supervisor_id):
    current_user = session.get("user_id")
    role = session.get("system_role")

    if role == "admin":
        return True
    if current_user == real_supervisor_id:
        return True

    cursor = get_cursor()
    cursor.execute("""
            SELECT id FROM supervisor_delegations
            WHERE from_supervisor_id = %s
            AND to_supervisor_id = %s
            AND start_date <= CURDATE()
            AND end_date >= CURDATE()
        """, (real_supervisor_id, current_user))
    return cursor.fetchone() is not None


# ─────────────────────────────────────────────
# BUDGET HELPER
# ─────────────────────────────────────────────
def get_supervisor_month_usage(supervisor_id):
    cursor = get_cursor()
    now = datetime.now()
    cursor.execute("""
        SELECT COALESCE(SUM(total_price), 0) as total
        FROM order_carts
        WHERE supervisor_id = %s
          AND status IN ('packed','completed')
          AND MONTH(created_at) = %s
          AND YEAR(created_at) = %s
    """, (supervisor_id, now.month, now.year))
    result = cursor.fetchone()
    return float(result["total"]) if result else 0.0


# ─────────────────────────────────────────────
# CART HELPER
# ─────────────────────────────────────────────
def get_or_create_cart(team_member_id, supervisor_id=None):
    cursor = get_cursor()
    # Verify the team member exists
    cursor.execute("SELECT id FROM team_members WHERE id = %s", (team_member_id,))
    if not cursor.fetchone():
        return None
    # Use the logged-in supervisor (may be a delegate), not the worker's original owner
    from flask import session as _session
    acting_supervisor = supervisor_id or _session.get("user_id")

    cursor.execute("""
        SELECT id FROM order_carts
        WHERE supervisor_id = %s AND status = 'created'
        LIMIT 1
    """, (acting_supervisor,))
    cart = cursor.fetchone()
    if cart:
        return cart["id"]

    cursor.execute("INSERT INTO order_carts (supervisor_id, status) VALUES (%s, 'created')", (acting_supervisor,))
    db.commit()
    return cursor.lastrowid


# ─────────────────────────────────────────────
# EFFECTIVE SUPERVISORS (delegation aware)
# ─────────────────────────────────────────────
def get_effective_supervisors(user_id):
    cursor = get_cursor()
    supervisors = [user_id]
    cursor.execute("""
        SELECT from_supervisor_id
        FROM supervisor_delegations
        WHERE to_supervisor_id = %s
          AND start_date <= %s
          AND end_date >= %s
    """, (user_id, date.today(), date.today()))
    for row in cursor.fetchall():
        supervisors.append(row["from_supervisor_id"])
    return supervisors

def notify_packers_new_order(cart_id, supervisor_name, total):
    import ssl, threading
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_port = int(os.environ.get("SMTP_PORT", 465))
    from_addr = os.environ.get("SMTP_FROM", smtp_user)
    site_url = os.environ.get("SITE_URL", "http://localhost:5000")
    if not smtp_host or not smtp_user:
        return
    cursor = get_cursor()
    cursor.execute("SELECT email, full_name FROM users WHERE system_role='packer'")
    packers = cursor.fetchall()
    for packer in packers:
        subject = f"New order #{cart_id} ready to pack"
        body = f"Hi {packer['full_name']},\n\nOrder #{cart_id} from {supervisor_name} (total: {total:.2f} SEK) is ready to pack.\n\nLog in here: {site_url}/orders\n\nBest regards,\nDHL Corporate Wear Team"
        def _send(to=packer["email"], s=subject, b=body):
            try:
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                import smtplib
                msg = MIMEMultipart()
                msg["From"] = from_addr
                msg["To"] = to
                msg["Subject"] = s
                msg.attach(MIMEText(b, "plain"))
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as srv:
                    srv.login(smtp_user, smtp_pass)
                    srv.sendmail(from_addr, to, msg.as_string())
            except Exception as e:
                print(f"[EMAIL] Packer notify failed: {e}")
        threading.Thread(target=_send, daemon=True).start()
# ─────────────────────────────────────────────
# CONTEXT PROCESSORS
# ─────────────────────────────────────────────
@app.context_processor
def inject_global_counts():
    if "user_id" not in session:
        return dict(unread_news_count=0)
    try:
        cursor = get_cursor()
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM news_posts np
            LEFT JOIN news_reads nr ON np.id = nr.post_id AND nr.user_id = %s
            WHERE (np.target_role = 'all' OR np.target_role = %s)
              AND nr.id IS NULL
        """, (session["user_id"], session.get("system_role")))
        result = cursor.fetchone()
        cursor.close()
        return dict(unread_news_count=result["count"] if result else 0)
    except Exception:
        return dict(unread_news_count=0)


@app.context_processor
def inject_cart_count():
    return dict(cart_count=0)  # cart_count handled per-page via selected_member


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        cursor = get_cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()
        if user:
            session["user_id"] = user["id"]
            session["system_role"] = user["system_role"]
            session["job_role_id"] = user.get("job_role_id")
            if user["system_role"] == "packer":
                return redirect(url_for("view_orders"))
            elif user["system_role"] == "supervisor":
                return redirect(url_for("news"))       # news is the landing page
            elif user["system_role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("shop"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# SHOP
# ─────────────────────────────────────────────
@app.route("/shop")
def shop():
    if "user_id" not in session:
        return redirect(url_for("login"))

    selected_role = request.args.get("role")
    selected_member = request.args.get("team_member_id")
    search = request.args.get("search", "").strip()
    role = session["system_role"]

    # --- Team members (from team_members table) ---
    team = []
    if role in ("supervisor", "admin"):
        c = get_cursor()
        if role == "supervisor":
            supervisor_ids = get_effective_supervisors(session["user_id"])
            placeholders = ",".join(["%s"] * len(supervisor_ids))
            c.execute(f"""
                SELECT id, full_name, employee_number FROM team_members
                WHERE supervisor_id IN ({placeholders}) ORDER BY full_name
            """, supervisor_ids)
        else:
            c.execute("""
                SELECT id, full_name, employee_number FROM team_members
                ORDER BY full_name
            """)
        team = c.fetchall()
        c.close()

    require_selection = False  # browsing always allowed

    recommended_sizes = {}

    # Load worker's saved sizes + auto-set role filter from worker's job role
    worker_job_role_id = None
    if selected_member:
        c = get_cursor()
        c.execute("SELECT job_role_id FROM team_members WHERE id = %s", (selected_member,))
        row = c.fetchone()
        worker_job_role_id = row["job_role_id"] if row else None
        c.close()
        # Auto-apply worker's role as the filter unless supervisor manually overrode it
        if worker_job_role_id and not selected_role:
            selected_role = str(worker_job_role_id)

    # Load worker's saved sizes if a member is selected
    if selected_member:
        c = get_cursor()
        c.execute("SELECT product_type, size FROM worker_sizes WHERE team_member_id = %s", (selected_member,))
        for row in c.fetchall():
            recommended_sizes[row["product_type"].upper()] = row["size"]
        c.close()

    # --- Cart count ---
    cart_count = 0
    if selected_member:
        c = get_cursor()
        c.execute("""
            SELECT COALESCE(SUM(oi.quantity), 0) as cnt
            FROM order_items oi
            JOIN order_carts oc ON oi.cart_id = oc.id
            WHERE oi.team_member_id = %s AND oc.status = 'created'
        """, (selected_member,))
        row = c.fetchone()
        cart_count = int(row["cnt"]) if row else 0
        c.close()

    # --- Job roles ---
    c = get_cursor()
    c.execute("SELECT id, name FROM job_roles ORDER BY name")
    job_roles = c.fetchall()
    c.close()

    # --- Products ---
    c = get_cursor()
    if role == "admin":
        # Admin always sees everything, can filter by role manually
        if selected_role:
            c.execute("""
                SELECT DISTINCT p.* FROM products p
                JOIN product_job_roles pj ON p.id = pj.product_id
                WHERE pj.job_role_id = %s ORDER BY p.article_number
            """, (selected_role,))
        else:
            c.execute("SELECT * FROM products ORDER BY article_number")
    elif role == "supervisor":
        # Supervisor sees ALL products always
        if selected_role:
            c.execute("""
                SELECT DISTINCT p.* FROM products p
                JOIN product_job_roles pj ON p.id = pj.product_id
                WHERE pj.job_role_id = %s ORDER BY p.article_number
            """, (selected_role,))
        else:
            c.execute("SELECT * FROM products ORDER BY article_number")
    else:
        if selected_role:
            c.execute("""
                SELECT DISTINCT p.* FROM products p
                JOIN product_job_roles pj ON p.id = pj.product_id
                WHERE pj.job_role_id = %s ORDER BY p.article_number
            """, (selected_role,))
        else:
            c.execute("""
                SELECT DISTINCT p.* FROM products p
                JOIN product_job_roles pj ON p.id = pj.product_id
                WHERE pj.job_role_id = %s
                OR pj.job_role_id = (SELECT id FROM job_roles WHERE name='Everyone')
                ORDER BY p.article_number
            """, (session["job_role_id"],))
    products = c.fetchall()
    c.close()

    # --- Build set of product IDs the worker is eligible to order ---
    # Used in template to disable Add to Cart for ineligible products
    worker_eligible_ids = None
    if selected_member and worker_job_role_id:
        c = get_cursor()
        c.execute("""
            SELECT DISTINCT p.id FROM products p
            JOIN product_job_roles pj ON p.id = pj.product_id
            WHERE pj.job_role_id = %s
            OR pj.job_role_id = (SELECT id FROM job_roles WHERE name='Everyone')
        """, (worker_job_role_id,))
        worker_eligible_ids = {row["id"] for row in c.fetchall()}
        c.close()

    # --- Apply search filter ---
    if search:
        products = [p for p in products if search.lower() in p["name"].lower() or search.lower() in (p.get("article_number") or "").lower()]

    # --- Sizes + roles in bulk (avoids N+1 queries) ---
    if products:
        product_ids = [p["id"] for p in products]
        placeholders = ",".join(["%s"] * len(product_ids))

        c = get_cursor()
        c.execute(f"SELECT id, product_id, size, stock FROM product_sizes WHERE product_id IN ({placeholders})", product_ids)
        sizes_map = {}
        for row in c.fetchall():
            sizes_map.setdefault(row["product_id"], []).append(row)
        c.close()

        c = get_cursor()
        c.execute(f"SELECT product_id, job_role_id FROM product_job_roles WHERE product_id IN ({placeholders})", product_ids)
        roles_map = {}
        for row in c.fetchall():
            roles_map.setdefault(row["product_id"], []).append(row["job_role_id"])
        c.close()

        for product in products:
            product["sizes"] = sizes_map.get(product["id"], [])
            product["role_ids"] = roles_map.get(product["id"], [])
            product["recommended_size"] = recommended_sizes.get(product.get("type", "").upper())

    return render_template(
        "shop.html",
        products=products,
        job_roles=job_roles,
        selected_role=selected_role,
        selected_member=selected_member,
        search=search,
        team=team,
        require_selection=require_selection,
        cart_count=cart_count,
        worker_eligible_ids=worker_eligible_ids,
    )

# ─────────────────────────────────────────────
# CART
# ─────────────────────────────────────────────
@app.route("/add-to-cart", methods=["POST"])
def add_to_cart():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("system_role") == "admin":
        flash("Admins cannot place orders.", "error")
        return redirect(url_for("shop"))

    team_member_id = request.form.get("team_member_id")
    product_size_id = request.form.get("product_size_id")
    if not product_size_id:
        flash("Please select a size.", "error")
        return redirect(url_for("shop"))

    quantity = int(request.form.get("quantity", 1))
    cursor = get_cursor()

    # Verify the worker belongs to this supervisor OR a delegated supervisor
    if session.get("system_role") == "supervisor":
        effective_ids = get_effective_supervisors(session["user_id"])
        placeholders = ",".join(["%s"] * len(effective_ids))
        c = get_cursor()
        c.execute(f"SELECT id FROM team_members WHERE id = %s AND supervisor_id IN ({placeholders})",
                  [team_member_id] + effective_ids)
        if not c.fetchone():
            flash("Invalid team member.", "error")
            c.close()
            return redirect(url_for("shop"))
        c.close()

    cart_id = get_or_create_cart(team_member_id)
    if not cart_id:
        flash("Could not create cart.", "error")
        return redirect(url_for("shop"))

    cursor = get_cursor()
    # Check if item already in cart
    cursor.execute("""
        SELECT id, quantity FROM order_items
        WHERE cart_id = %s AND product_size_id = %s AND team_member_id = %s
    """, (cart_id, product_size_id, team_member_id))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("UPDATE order_items SET quantity = quantity + %s WHERE id = %s",
                       (quantity, existing["id"]))
    else:
        cursor.execute("""
            SELECT p.price FROM product_sizes ps
            JOIN products p ON ps.product_id = p.id
            WHERE ps.id = %s
        """, (product_size_id,))
        price_row = cursor.fetchone()
        price = price_row["price"] if price_row else 0
        cursor.execute("""
            INSERT INTO order_items (cart_id, product_size_id, team_member_id, quantity, price_at_time)
            VALUES (%s, %s, %s, %s, %s)
        """, (cart_id, product_size_id, team_member_id, quantity, price))
    db.commit()

    # Count cart items for badge update
    c2 = get_cursor()
    c2.execute("""
        SELECT COALESCE(SUM(oi.quantity),0) as cnt
        FROM order_items oi
        JOIN order_carts oc ON oi.cart_id = oc.id
        WHERE oc.supervisor_id = %s AND oc.status = 'created'
    """, (session["user_id"],))
    row = c2.fetchone()
    cart_count = int(row["cnt"]) if row else 0
    c2.close()
    cursor.close()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "cart_count": cart_count})

    flash("Added to cart.", "success")
    return redirect(url_for("shop", team_member_id=team_member_id))


@app.route("/cart")
def view_cart():
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor = get_cursor()
    cursor.execute("""
        SELECT * FROM order_carts
        WHERE supervisor_id = %s AND status = 'created'
        ORDER BY created_at DESC LIMIT 1
    """, (session["user_id"],))
    cart = cursor.fetchone()

    if not cart:
        return render_template("cart.html", items=[], total=0, cart=None)

    session["cart_id"] = cart["id"]

    cursor.execute("""
        SELECT p.name, p.article_number, ps.size,
               oi.quantity, oi.price_at_time,
               (oi.quantity * oi.price_at_time) AS subtotal,
               tm.full_name AS worker_name,
               oi.id AS item_id
        FROM order_items oi
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        LEFT JOIN team_members tm ON oi.team_member_id = tm.id
        WHERE oi.cart_id = %s
    """, (cart["id"],))
    items = cursor.fetchall()
    total = sum(float(item["subtotal"]) for item in items)

    # Load team members so cart page can assign order to a member
    c = get_cursor()
    c.execute("""
        SELECT id, full_name, employee_number FROM team_members
        WHERE supervisor_id = %s ORDER BY full_name
    """, (session["user_id"],))
    team = c.fetchall()
    c.close()

    return render_template("cart.html", items=items, total=total, cart=cart, team=team)


@app.route("/cart/remove/<int:item_id>", methods=["POST"])
def remove_cart_item(item_id):
    cursor = get_cursor()
    # Verify ownership
    cart_id = session.get("cart_id")
    cursor.execute("SELECT cart_id FROM order_items WHERE id = %s", (item_id,))
    row = cursor.fetchone()
    if row and row["cart_id"] == cart_id:
        cursor.execute("DELETE FROM order_items WHERE id = %s", (item_id,))
        db.commit()
        flash("Item removed.", "success")
    return redirect(url_for("view_cart"))


@app.route("/checkout", methods=["POST"])
def checkout():
    if "cart_id" not in session:
        return redirect(url_for("shop"))

    cart_id = session["cart_id"]
    cursor = get_cursor()

    # Get cart
    cursor.execute("SELECT * FROM order_carts WHERE id = %s", (cart_id,))
    cart_data = cursor.fetchone()
    if not cart_data:
        flash("Cart not found.", "error")
        return redirect(url_for("shop"))

    supervisor_id = cart_data["supervisor_id"]

    # Get cart items
    cursor.execute("SELECT product_size_id, quantity, price_at_time FROM order_items WHERE cart_id = %s", (cart_id,))
    items = cursor.fetchall()
    if not items:
        flash("Cart is empty.", "error")
        return redirect(url_for("shop"))

    # Calculate total
    total = sum(float(i["quantity"]) * float(i["price_at_time"]) for i in items)

    # Check budget
    cursor.execute("SELECT monthly_budget FROM users WHERE id = %s", (supervisor_id,))
    budget_row = cursor.fetchone()
    if budget_row and budget_row["monthly_budget"]:
        budget = float(budget_row["monthly_budget"])
        used = get_supervisor_month_usage(supervisor_id)
        if used + total > budget:
            flash(f"Monthly budget exceeded. Used: {used:.2f}, Order: {total:.2f}, Budget: {budget:.2f}", "error")
            return redirect(url_for("view_cart"))

    # Deduct stock
    for item in items:
        cursor.execute("""
            UPDATE product_sizes SET stock = stock - %s
            WHERE id = %s AND stock >= %s
        """, (item["quantity"], item["product_size_id"], item["quantity"]))
        if cursor.rowcount == 0:
            flash("Not enough stock for one or more items.", "error")
            db.rollback()
            return redirect(url_for("view_cart"))

    comment = request.form.get("comment") or None

    team_member_id = request.form.get("team_member_id") or None
    # If not passed in form, derive from the items (first worker in cart)
    if not team_member_id:
        cursor.execute("""
            SELECT DISTINCT team_member_id FROM order_items
            WHERE cart_id = %s AND team_member_id IS NOT NULL LIMIT 1
        """, (cart_id,))
        row = cursor.fetchone()
        if row:
            team_member_id = row["team_member_id"]

    cursor.execute("""
            UPDATE order_carts SET total_price = %s, status = 'submitted', comment = %s, team_member_id = %s
            WHERE id = %s
        """, (total, comment, team_member_id, cart_id))
    db.commit()

    cursor.execute("SELECT full_name FROM users WHERE id=%s", (supervisor_id,))
    sup = cursor.fetchone()
    notify_packers_new_order(cart_id, sup["full_name"] if sup else "Unknown", total)

    session.pop("cart_id", None)
    flash("Order submitted successfully.", "success")
    return redirect(url_for("view_orders"))


# ─────────────────────────────────────────────
# ORDERS
# ─────────────────────────────────────────────
@app.route("/orders")
def view_orders():
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor = get_cursor()
    role = session["system_role"]

    query = """
        SELECT oc.id, oc.status, oc.created_at, oc.total_price,
               u.full_name AS supervisor_name,
               COALESCE(
                   tm.full_name,
                   (SELECT GROUP_CONCAT(DISTINCT tm2.full_name SEPARATOR ', ')
                    FROM order_items oi2
                    JOIN team_members tm2 ON oi2.team_member_id = tm2.id
                    WHERE oi2.cart_id = oc.id)
               ) AS worker_name,
               tm.employee_number,
               (SELECT COUNT(*) FROM order_items oi WHERE oi.cart_id = oc.id) AS item_count
        FROM order_carts oc
        JOIN users u ON oc.supervisor_id = u.id
        LEFT JOIN team_members tm ON oc.team_member_id = tm.id
    """
    filters, values = [], []

    if role == "supervisor":
        filters.append("oc.supervisor_id = %s")
        values.append(session["user_id"])

    supervisor_id = request.args.get("supervisor")
    if supervisor_id and role == "admin":
        filters.append("oc.supervisor_id = %s")
        values.append(supervisor_id)

    status = request.args.get("status")
    if status:
        filters.append("oc.status = %s")
        values.append(status)

    start_date = request.args.get("start")
    if start_date:
        filters.append("oc.created_at >= %s")
        values.append(start_date)

    end_date = request.args.get("end")
    if end_date:
        filters.append("oc.created_at <= %s")
        values.append(end_date)

    hide_sent = request.args.get("hide_sent", "1")
    if hide_sent == "1" and not status:
        filters.append("oc.status != 'completed'")
    elif hide_sent == "1" and status == "completed":
        # User explicitly selected "completed/sent" status, so show them
        pass

    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY oc.created_at DESC"

    cursor.execute(query, values)
    carts = cursor.fetchall()

    # For admin filter dropdowns
    supervisors = []
    if role == "admin":
        cursor.execute("SELECT id, full_name FROM users WHERE system_role='supervisor' ORDER BY full_name")
        supervisors = cursor.fetchall()

    return render_template("orders.html", carts=carts, supervisors=supervisors,
                           current_filters=request.args)


@app.route("/order/<int:cart_id>")
def order_detail(cart_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor = get_cursor()
    cursor.execute("""
        SELECT oc.*, u.full_name AS supervisor_name,
               tm.full_name AS worker_name, tm.employee_number
        FROM order_carts oc
        JOIN users u ON oc.supervisor_id = u.id
        LEFT JOIN team_members tm ON oc.team_member_id = tm.id
        WHERE oc.id = %s
    """, (cart_id,))
    cart = cursor.fetchone()

    cursor.execute("""
        SELECT oi.quantity, oi.price_at_time,
               (oi.quantity * oi.price_at_time) AS subtotal,
               ps.size, p.name, p.article_number,
               tm.full_name AS worker_name, tm.employee_number
        FROM order_items oi
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        LEFT JOIN team_members tm ON oi.team_member_id = tm.id
        WHERE oi.cart_id = %s
    """, (cart_id,))
    items = cursor.fetchall()
    total = sum(float(i["subtotal"]) for i in items)

    return render_template("order_detail.html", cart=cart, items=items, total=total)


@app.route("/pack_order/<int:cart_id>", methods=["POST"])
def pack_order(cart_id):
    if session.get("system_role") != "packer":
        return redirect(url_for("view_orders"))
    cursor = get_cursor()
    cursor.execute("UPDATE order_carts SET status='packed' WHERE id=%s", (cart_id,))
    db.commit()
    # Notify supervisor
    cursor.execute("""
        SELECT oc.id, u.email, u.full_name
        FROM order_carts oc JOIN users u ON oc.supervisor_id = u.id
        WHERE oc.id = %s
    """, (cart_id,))
    row = cursor.fetchone()
    if row:
        send_status_email(row["email"], row["full_name"], cart_id, "packed")
    flash("Order marked as packed.", "success")
    return redirect(url_for("order_detail", cart_id=cart_id))


@app.route("/complete_order/<int:cart_id>", methods=["POST"])
def complete_order(cart_id):
    if session.get("system_role") not in ("packer", "admin"):
        return redirect(url_for("view_orders"))
    cursor = get_cursor()
    cursor.execute("UPDATE order_carts SET status='completed' WHERE id=%s", (cart_id,))

    # Insert each order item into user_uniforms so they appear in My Uniforms
    cursor.execute("""
        SELECT oi.product_size_id, oi.team_member_id
        FROM order_items oi
        WHERE oi.cart_id = %s
    """, (cart_id,))
    items = cursor.fetchall()
    for item in items:
        cursor.execute("""
            INSERT INTO user_uniforms (product_size_id, team_member_id, status, issued_at)
            VALUES (%s, %s, 'active', NOW())
        """, (item["product_size_id"], item["team_member_id"]))

    db.commit()
    # Notify supervisor
    cursor.execute("""
        SELECT oc.id, u.email, u.full_name
        FROM order_carts oc JOIN users u ON oc.supervisor_id = u.id
        WHERE oc.id = %s
    """, (cart_id,))
    row = cursor.fetchone()
    if row:
        send_status_email(row["email"], row["full_name"], cart_id, "completed")
    flash("Order completed.", "success")
    return redirect(url_for("order_detail", cart_id=cart_id))


@app.route("/cancel_order/<int:cart_id>", methods=["POST"])
def cancel_order(cart_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    cursor = get_cursor()
    cursor.execute("SELECT * FROM order_carts WHERE id=%s", (cart_id,))
    cart = cursor.fetchone()
    if not cart:
        flash("Order not found.", "error")
        return redirect(url_for("view_orders"))
    # Only supervisor who owns it (or admin) can cancel, and only if not yet packed
    if session.get("system_role") == "supervisor" and cart["supervisor_id"] != session["user_id"]:
        flash("Not authorised.", "error")
        return redirect(url_for("view_orders"))
    if cart["status"] in ("packed", "completed"):
        flash("Cannot cancel an order that is already packed or completed.", "error")
        return redirect(url_for("view_orders"))
    cursor.execute("UPDATE order_carts SET status='cancelled' WHERE id=%s", (cart_id,))
    db.commit()
    flash("Order cancelled.", "success")
    return redirect(url_for("view_orders"))


# ─────────────────────────────────────────────
# ORDER EXPORTS
# ─────────────────────────────────────────────
@app.route("/orders/export/excel")
def export_orders_excel():
    if session.get("system_role") not in ("admin", "supervisor", "packer"):
        return redirect(url_for("view_orders"))

    cursor = get_cursor()
    query = """
        SELECT oc.id AS order_id, oc.status, oc.created_at, oc.total_price,
               u.full_name AS supervisor,
               p.name AS product, p.article_number, ps.size,
               oi.quantity, oi.price_at_time,
               (oi.quantity * oi.price_at_time) AS subtotal,
               tm.full_name AS worker, tm.employee_number
        FROM order_carts oc
        JOIN users u ON oc.supervisor_id = u.id
        JOIN order_items oi ON oi.cart_id = oc.id
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        LEFT JOIN team_members tm ON oi.team_member_id = tm.id
    """
    filters, values = [], []
    if session["system_role"] == "supervisor":
        filters.append("oc.supervisor_id = %s")
        values.append(session["user_id"])

    sup = request.args.get("supervisor")
    if sup and session["system_role"] == "admin":
        filters.append("oc.supervisor_id = %s")
        values.append(sup)

    status = request.args.get("status")
    if status:
        filters.append("oc.status = %s")
        values.append(status)

    start_date = request.args.get("start")
    if start_date:
        filters.append("oc.created_at >= %s")
        values.append(start_date)

    end_date = request.args.get("end")
    if end_date:
        filters.append("oc.created_at <= %s")
        values.append(end_date)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    cursor.execute(query, values)
    data = cursor.fetchall()
    df = pd.DataFrame(data)
    # Format datetime columns
    for col in df.columns:
        if df[col].dtype == "object":
            try:
                df[col] = df[col].astype(str)
            except Exception:
                pass
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Orders")
        ws = writer.sheets["Orders"]
        for col in ws.columns:
            max_len = max((len(str(cell.value)) if cell.value else 0) for cell in col)
            ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 50)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="orders_export.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/orders/export/pdf")
def export_orders_pdf():
    if session.get("system_role") not in ("admin", "supervisor", "packer"):
        return redirect(url_for("view_orders"))

    cursor = get_cursor()
    query = """
        SELECT oc.id, oc.status, oc.created_at, oc.total_price,
               u.full_name AS supervisor,
               p.name AS product, ps.size, oi.quantity, oi.price_at_time,
               tm.full_name AS worker
        FROM order_carts oc
        JOIN users u ON oc.supervisor_id = u.id
        JOIN order_items oi ON oi.cart_id = oc.id
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        LEFT JOIN team_members tm ON oi.team_member_id = tm.id
    """
    filters, values = [], []
    if session["system_role"] == "supervisor":
        filters.append("oc.supervisor_id = %s")
        values.append(session["user_id"])

    sup = request.args.get("supervisor")
    if sup and session["system_role"] == "admin":
        filters.append("oc.supervisor_id = %s")
        values.append(sup)

    status = request.args.get("status")
    if status:
        filters.append("oc.status = %s")
        values.append(status)

    start_date = request.args.get("start")
    if start_date:
        filters.append("oc.created_at >= %s")
        values.append(start_date)

    end_date = request.args.get("end")
    if end_date:
        filters.append("oc.created_at <= %s")
        values.append(end_date)

    if filters:
        query += " WHERE " + " AND ".join(filters)
    cursor.execute(query, values)
    rows = cursor.fetchall()

    buffer = io.BytesIO()
    from reportlab.lib.units import mm
    left_margin = 15 * mm
    right_margin = 15 * mm
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=left_margin, rightMargin=right_margin, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Order Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    headers = ["Order ID", "Status", "Date", "Supervisor", "Product", "Size", "Qty", "Price", "Worker"]
    table_data = [headers]
    for r in rows:
        table_data.append([
            str(r["id"]), r["status"],
            str(r["created_at"])[:10],
            r["supervisor"], r["product"],
            r["size"], str(r["quantity"]),
            f'{float(r["price_at_time"]):.2f}',
            r["worker"] or "-"
        ])

    usable_width = 210*mm - left_margin - right_margin
    col_widths = [
        0.07 * usable_width,
        0.08 * usable_width,
        0.09 * usable_width,
        0.11 * usable_width,
        0.28 * usable_width,
        0.06 * usable_width,
        0.05 * usable_width,
        0.08 * usable_width,
        0.18 * usable_width,
    ]

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FFCC00")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("LEADING", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9F9F9")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="orders.pdf",
                     mimetype="application/pdf")


# ─────────────────────────────────────────────
# TEAM MANAGEMENT (Supervisor)
# ─────────────────────────────────────────────
@app.route("/team")
def view_team():
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    uid = session["user_id"]
    cursor.execute("""
        SELECT tm.id, tm.full_name, tm.employee_number, jr.name AS role_name,
               MAX(CASE WHEN ws.product_type='SHIRT' THEN ws.size END) AS shirt_size,
               MAX(CASE WHEN ws.product_type='PANTS' THEN ws.size END) AS pants_size,
               MAX(CASE WHEN ws.product_type='SHOES' THEN ws.size END) AS shoe_size
        FROM team_members tm
        LEFT JOIN job_roles jr ON tm.job_role_id = jr.id
        LEFT JOIN worker_sizes ws ON ws.team_member_id = tm.id
        WHERE tm.supervisor_id = %s
        GROUP BY tm.id, tm.full_name, tm.employee_number, jr.name
        ORDER BY tm.full_name
    """, (uid,))
    team = cursor.fetchall()

    # Delegated teams (read-only)
    cursor.execute("""
        SELECT sd.id AS delegation_id, u.full_name AS supervisor_name,
               tm.id, tm.full_name, tm.employee_number, jr.name AS role_name,
               MAX(CASE WHEN ws.product_type='SHIRT' THEN ws.size END) AS shirt_size,
               MAX(CASE WHEN ws.product_type='PANTS' THEN ws.size END) AS pants_size,
               MAX(CASE WHEN ws.product_type='SHOES' THEN ws.size END) AS shoe_size
        FROM supervisor_delegations sd
        JOIN users u ON sd.from_supervisor_id = u.id
        JOIN team_members tm ON tm.supervisor_id = sd.from_supervisor_id
        LEFT JOIN job_roles jr ON tm.job_role_id = jr.id
        LEFT JOIN worker_sizes ws ON ws.team_member_id = tm.id
        WHERE sd.to_supervisor_id = %s
          AND sd.start_date <= CURDATE() AND sd.end_date >= CURDATE()
        GROUP BY sd.id, u.full_name, tm.id, tm.full_name, tm.employee_number, jr.name
        ORDER BY u.full_name, tm.full_name
    """, (uid,))
    delegated_rows = cursor.fetchall()
    # Group by supervisor
    from collections import defaultdict
    delegated = defaultdict(list)
    for row in delegated_rows:
        delegated[row["supervisor_name"]].append(row)
    delegated = dict(delegated)

    cursor.execute("SELECT id, name FROM job_roles ORDER BY name")
    job_roles = cursor.fetchall()
    return render_template("team.html", team=team, job_roles=job_roles, delegated=delegated)


@app.route("/team/add", methods=["GET", "POST"])
def add_team_member():
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        full_name = request.form["full_name"]
        employee_number = request.form["employee_number"]
        job_role_id = request.form["job_role_id"]

        cursor.execute("""
                    INSERT INTO team_members (supervisor_id, full_name, employee_number, job_role_id)
                    VALUES (%s, %s, %s, %s)
                """, (session["user_id"], full_name, employee_number, job_role_id))
        db.commit()
        team_member_id = cursor.lastrowid

        for size_type in [("shirt_size", "SHIRT"), ("pants_size", "PANTS"), ("shoe_size", "SHOES")]:
            val = request.form.get(size_type[0])
            if val:
                cursor.execute("""
                    INSERT INTO worker_sizes (team_member_id, product_type, size)
                    VALUES (%s, %s, %s)
                """, (team_member_id, size_type[1], val))
        db.commit()
        flash("Team member added.", "success")
        return redirect(url_for("view_team"))

    cursor.execute("SELECT id, name FROM job_roles")
    roles = cursor.fetchall()
    return render_template("add_team_member.html", roles=roles)


@app.route("/team/<int:member_id>/edit", methods=["POST"])
def edit_team_member(member_id):
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT id FROM team_members WHERE id=%s AND supervisor_id=%s", (member_id, session["user_id"]))
    if not cursor.fetchone():
        flash("Not authorised.", "error")
        return redirect(url_for("view_team"))
    full_name = request.form.get("full_name", "").strip()
    employee_number = request.form.get("employee_number", "").strip()
    if full_name:
        cursor.execute("UPDATE team_members SET full_name=%s, employee_number=%s WHERE id=%s",
                       (full_name, employee_number or None, member_id))
    # Update sizes
    for field, product_type in [("shirt_size","SHIRT"), ("pants_size","PANTS"), ("shoe_size","SHOES")]:
        val = request.form.get(field, "").strip()
        if val:
            cursor.execute("""
                INSERT INTO worker_sizes (team_member_id, product_type, size)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE size=%s
            """, (member_id, product_type, val, val))
        else:
            cursor.execute("DELETE FROM worker_sizes WHERE team_member_id=%s AND product_type=%s",
                           (member_id, product_type))
    db.commit()
    flash("Member updated.", "success")
    return redirect(url_for("view_team"))


@app.route("/delete_team_member/<int:member_id>", methods=["POST"])
def delete_team_member(member_id):
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("DELETE FROM team_members WHERE id = %s AND supervisor_id = %s",
                   (member_id, session["user_id"]))
    db.commit()
    flash("Team member removed.", "success")
    return redirect(url_for("view_team"))


@app.route("/team/<int:member_id>/sizes", methods=["GET", "POST"])
def manage_worker_sizes(member_id):
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        product_type = request.form["product_type"]
        size = request.form["size"]
        cursor.execute("""
            INSERT INTO worker_sizes (team_member_id, product_type, size)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE size = VALUES(size)
        """, (member_id, product_type, size))
        db.commit()
        flash("Size updated.", "success")
    cursor.execute("SELECT product_type, size FROM worker_sizes WHERE team_member_id = %s", (member_id,))
    sizes = cursor.fetchall()
    return render_template("worker_sizes.html", sizes=sizes, member_id=member_id)


@app.route("/my-team")
def my_team():
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    supervisor_ids = get_effective_supervisors(session["user_id"])
    placeholders = ",".join(["%s"] * len(supervisor_ids))
    cursor.execute(f"""
        SELECT id, full_name, employee_number
        FROM team_members WHERE supervisor_id IN ({placeholders})
    """, supervisor_ids)
    workers = cursor.fetchall()
    return render_template("my_team.html", workers=workers)


# ─────────────────────────────────────────────
# SUPERVISOR DELEGATION
# ─────────────────────────────────────────────
@app.route("/supervisor/delegation", methods=["GET", "POST"])
def supervisor_delegation():
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    uid = session["user_id"]

    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
            del_id = request.form.get("delegation_id")
            cursor.execute("DELETE FROM supervisor_delegations WHERE id=%s AND from_supervisor_id=%s",
                           (del_id, uid))
            flash("Delegation removed.", "success")
        elif action == "extend":
            del_id = request.form.get("delegation_id")
            new_end = request.form.get("new_end_date")
            cursor.execute("UPDATE supervisor_delegations SET end_date=%s WHERE id=%s AND from_supervisor_id=%s",
                           (new_end, del_id, uid))
            flash("End date updated.", "success")
        else:
            delegate_id = request.form["delegate_id"]
            start_date = request.form["start_date"]
            end_date = request.form["end_date"]
            cursor.execute("""
                SELECT id FROM supervisor_delegations
                WHERE from_supervisor_id=%s AND to_supervisor_id=%s
                  AND start_date=%s AND end_date=%s
            """, (uid, delegate_id, start_date, end_date))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO supervisor_delegations (from_supervisor_id, to_supervisor_id, start_date, end_date)
                    VALUES (%s, %s, %s, %s)
                """, (uid, delegate_id, start_date, end_date))
                flash("Delegation created.", "success")
            else:
                flash("A delegation with those exact dates already exists.", "error")
        db.commit()
        return redirect(url_for("supervisor_delegation"))

    # Supervisors I can delegate TO
    cursor.execute("""
        SELECT id, full_name FROM users
        WHERE system_role = 'supervisor' AND id != %s
    """, (uid,))
    supervisors = cursor.fetchall()

    # My outgoing delegations
    cursor.execute("""
        SELECT sd.*, u.full_name AS delegate_name
        FROM supervisor_delegations sd
        JOIN users u ON sd.to_supervisor_id = u.id
        WHERE sd.from_supervisor_id = %s ORDER BY sd.start_date DESC
    """, (uid,))
    delegations = cursor.fetchall()

    # Incoming delegations — teams I'm currently covering
    cursor.execute("""
        SELECT sd.id, sd.start_date, sd.end_date,
               u.full_name AS owner_name, u.id AS owner_id
        FROM supervisor_delegations sd
        JOIN users u ON sd.from_supervisor_id = u.id
        WHERE sd.to_supervisor_id = %s
          AND sd.start_date <= CURDATE()
          AND sd.end_date >= CURDATE()
        ORDER BY sd.start_date DESC
    """, (uid,))
    incoming_raw = cursor.fetchall()

    incoming_delegations = []
    for d in incoming_raw:
        cursor.execute("""
            SELECT full_name, employee_number FROM team_members
            WHERE supervisor_id = %s ORDER BY full_name
        """, (d["owner_id"],))
        members = cursor.fetchall()
        incoming_delegations.append({**d, "members": members})

    return render_template("supervisor_delegation.html",
                           supervisors=supervisors,
                           delegations=delegations,
                           incoming_delegations=incoming_delegations,
                           now_date=date.today())


# ─────────────────────────────────────────────
# SUPERVISOR DASHBOARD
# ─────────────────────────────────────────────
@app.route("/dashboard")
def supervisor_dashboard():
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    uid = session["user_id"]

    cursor.execute("""
        SELECT COUNT(*) as active_orders FROM order_carts
        WHERE supervisor_id = %s AND status IN ('created','submitted','packed')
    """, (uid,))
    active_orders = cursor.fetchone()["active_orders"]

    cursor.execute("SELECT COUNT(*) as team_size FROM team_members WHERE supervisor_id = %s", (uid,))
    team_size = cursor.fetchone()["team_size"]

    cursor.execute("SELECT monthly_budget FROM users WHERE id = %s", (uid,))
    budget_row = cursor.fetchone()
    budget = float(budget_row["monthly_budget"]) if budget_row and budget_row["monthly_budget"] else None
    used = get_supervisor_month_usage(uid) if budget else 0

    # Team uniforms
    cursor.execute("""
        SELECT uu.id, uu.status, uu.issued_at, uu.returned_at,
               p.name AS product_name, ps.size,
               tm.full_name AS worker_name
        FROM user_uniforms uu
        JOIN product_sizes ps ON uu.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        JOIN team_members tm ON uu.team_member_id = tm.id
        WHERE tm.supervisor_id = %s
        ORDER BY uu.issued_at DESC
        LIMIT 10
    """, (uid,))
    recent_uniforms = cursor.fetchall()

    # Recent orders
    cursor.execute("""
        SELECT oc.id, oc.status, oc.created_at, oc.total_price,
               tm.full_name AS worker_name
        FROM order_carts oc
        LEFT JOIN team_members tm ON oc.team_member_id = tm.id
        WHERE oc.supervisor_id = %s
        ORDER BY oc.created_at DESC LIMIT 5
    """, (uid,))
    recent_orders = cursor.fetchall()

    # Low stock items relevant to team
    cursor.execute("""
        SELECT p.name, ps.size, ps.stock
        FROM product_sizes ps
        JOIN products p ON ps.product_id = p.id
        WHERE ps.stock <= %s AND ps.stock > 0
        ORDER BY ps.stock ASC LIMIT 5
    """, (LOW_STOCK_THRESHOLD,))
    low_stock = cursor.fetchall()

    return render_template("supervisor_dashboard.html",
                           active_orders=active_orders, team_size=team_size,
                           budget=budget, used=used,
                           recent_uniforms=recent_uniforms,
                           recent_orders=recent_orders,
                           low_stock=low_stock)


# ─────────────────────────────────────────────
# PRODUCTS (Admin)
# ─────────────────────────────────────────────
@app.route("/admin/products")
def admin_products():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT * FROM products ORDER BY article_number")
    products = cursor.fetchall()
    for p in products:
        sc = get_cursor()
        sc.execute("SELECT id, size, stock FROM product_sizes WHERE product_id=%s", (p["id"],))
        p["sizes"] = sc.fetchall()
    return render_template("admin_products.html", products=products)


@app.route("/add-product", methods=["GET", "POST"])
def add_product():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()

    if request.method == "POST":
        article_number = request.form.get("article_number", "").strip()
        name = request.form.get("name", "").strip()
        description = request.form.get("description") or None
        product_type = request.form.get("type")
        price = request.form.get("price", "").strip() or None
        max_quantity = request.form.get("max_quantity", "").strip() or None
        job_role_ids = request.form.getlist("job_role_ids")

        # Duplicate checks
        cursor.execute("SELECT id FROM products WHERE name = %s", (name,))
        if cursor.fetchone():
            flash("A product with this name already exists.", "error")
            return redirect(url_for("add_product"))
        cursor.execute("SELECT id FROM products WHERE article_number = %s", (article_number,))
        if cursor.fetchone():
            flash("A product with this article number already exists.", "error")
            return redirect(url_for("add_product"))

        image = None
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename != "":
                filename = str(uuid.uuid4()) + "_" + secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                image = filename

        try:
            gender = request.form.get("gender") or None

            cursor.execute("""
                            INSERT INTO products (article_number, name, type, image, description, price, max_quantity, gender)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (article_number, name, product_type, image, description, price, max_quantity, gender))
            db.commit()
        except IntegrityError:
            flash("Article number already exists.", "error")
            return redirect(url_for("add_product"))

        product_id = cursor.lastrowid

        for role_id in job_role_ids:
            cursor.execute("INSERT INTO product_job_roles (product_id, job_role_id) VALUES (%s, %s)",
                           (product_id, role_id))

        for key, value in request.form.items():
            if key.startswith("size_"):
                size_name = key.replace("size_", "")
                stock = int(value) if value else 0
                cursor.execute("INSERT INTO product_sizes (product_id, size, stock) VALUES (%s, %s, %s)",
                               (product_id, size_name, stock))

        db.commit()
        flash("Product added successfully.", "success")
        return redirect(url_for("admin_products"))

    cursor.execute("SELECT id, name FROM job_roles ORDER BY name")
    job_roles = cursor.fetchall()
    return render_template("add_product.html", job_roles=job_roles)


@app.route("/admin/products/edit/<int:product_id>", methods=["GET", "POST"])
def edit_product(product_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    if not product:
        return "Product not found", 404

    if request.method == "POST":
        name = request.form["name"]
        description = request.form["description"]
        price = request.form["price"].strip() or None
        max_quantity = request.form["max_quantity"].strip() or None
        image = request.files.get("image")
        image_path = product["image"]
        if image and image.filename != "":
            filename = str(uuid.uuid4()) + "_" + secure_filename(image.filename)
            image.save(os.path.join("static", "uploads", filename))
            image_path = filename

        gender = request.form.get("gender") or None

        cursor.execute("""
                    UPDATE products SET name=%s, description=%s, price=%s, max_quantity=%s, image=%s, gender=%s
                    WHERE id=%s
                """, (name, description, price, max_quantity, image_path, gender, product_id))
        db.commit()
        flash("Product updated.", "success")
        return redirect(url_for("shop"))

    # Sizes
    cursor.execute("SELECT id, size, stock FROM product_sizes WHERE product_id=%s", (product_id,))
    sizes = cursor.fetchall()
    return render_template("edit_product.html", product=product, sizes=sizes)

@app.route("/stock")
def view_stock():
    return redirect(url_for("admin_products"))

@app.route("/delete-product/<int:product_id>", methods=["POST"])
def delete_product(product_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    # Delete order_items referencing this product's sizes first
    cursor.execute("""
        DELETE oi FROM order_items oi
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        WHERE ps.product_id = %s
    """, (product_id,))
    cursor.execute("DELETE FROM product_job_roles WHERE product_id=%s", (product_id,))
    cursor.execute("DELETE FROM product_sizes WHERE product_id=%s", (product_id,))
    cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
    db.commit()
    flash("Product removed.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/products/<int:product_id>/sizes", methods=["GET", "POST"])
def manage_product_sizes(product_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
            size_id = request.form.get("size_id")
            cursor.execute("DELETE FROM product_sizes WHERE id=%s AND product_id=%s", (size_id, product_id))
        else:
            size = request.form["size"]
            stock = request.form["stock"]
            cursor.execute("INSERT INTO product_sizes (product_id, size, stock) VALUES (%s, %s, %s)",
                           (product_id, size, stock))
        db.commit()

    cursor.execute("SELECT * FROM product_sizes WHERE product_id=%s", (product_id,))
    sizes = cursor.fetchall()
    cursor.execute("SELECT name FROM products WHERE id=%s", (product_id,))
    product = cursor.fetchone()
    return render_template("manage_product_sizes.html", sizes=sizes, product_id=product_id, product=product)


@app.route("/update-stock/<int:product_id>", methods=["POST"])
def update_stock(product_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT id FROM product_sizes WHERE product_id=%s", (product_id,))
    for size in cursor.fetchall():
        field_name = f"size_{size['id']}"
        add_amount = request.form.get(field_name)
        if add_amount and str(add_amount).isdigit():
            cursor.execute("UPDATE product_sizes SET stock = stock + %s WHERE id=%s",
                           (int(add_amount), size["id"]))
    db.commit()
    flash("Stock updated.", "success")
    return redirect(url_for("shop"))


@app.route("/add-stock/<int:size_id>", methods=["POST"])
def add_stock(size_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    amount = request.form.get("amount", 0)
    cursor = get_cursor()
    cursor.execute("UPDATE product_sizes SET stock = stock + %s WHERE id=%s", (amount, size_id))
    db.commit()
    flash("Stock updated.", "success")
    return redirect(url_for("admin_products"))


@app.route("/get-sizes/<int:product_id>")
def get_sizes(product_id):
    cursor = get_cursor()
    cursor.execute("SELECT id, size, stock FROM product_sizes WHERE product_id=%s", (product_id,))
    return jsonify(cursor.fetchall())


# ─────────────────────────────────────────────
# UNIFORM RETURNS
# ─────────────────────────────────────────────
@app.route("/my-uniforms")
def my_uniforms():
    if "user_id" not in session:
        return redirect(url_for("login"))
    cursor = get_cursor()
    # Show uniforms for all team members under this supervisor
    if session["system_role"] == "supervisor":
        cursor.execute("""
            SELECT uu.id, uu.status, uu.issued_at, uu.returned_at,
                   p.name AS product_name, ps.size,
                   tm.full_name AS worker_name
            FROM user_uniforms uu
            JOIN product_sizes ps ON uu.product_size_id = ps.id
            JOIN products p ON ps.product_id = p.id
            JOIN team_members tm ON uu.team_member_id = tm.id
            WHERE tm.supervisor_id = %s
            ORDER BY uu.issued_at DESC
        """, (session["user_id"],))
    else:
        cursor.execute("""
            SELECT uu.id, uu.status, uu.issued_at, uu.returned_at,
                   p.name AS product_name, ps.size
            FROM user_uniforms uu
            JOIN product_sizes ps ON uu.product_size_id = ps.id
            JOIN products p ON ps.product_id = p.id
            WHERE uu.user_id = %s
            ORDER BY uu.issued_at DESC
        """, (session["user_id"],))
    raw = cursor.fetchall()
    uniforms = []
    for u in raw:
        status = u["status"] or ""
        u["returned"] = status != "active"
        u["return_reason"] = status.replace("returned_", "") if status.startswith("returned_") else status
        uniforms.append(u)
    return render_template("my_uniforms.html", uniforms=uniforms)


@app.route("/return-uniform/<int:uniform_id>", methods=["POST"])
def return_uniform(uniform_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    reason = request.form.get("reason", "worn_out")  # worn_out | damaged | lost
    cursor = get_cursor()
    cursor.execute("""
        UPDATE user_uniforms SET status=%s, returned_at=NOW()
        WHERE id=%s
    """, (f"returned_{reason}", uniform_id))
    # Restore stock if not lost
    if reason != "lost":
        cursor.execute("""
            UPDATE product_sizes ps
            JOIN user_uniforms uu ON uu.product_size_id = ps.id
            SET ps.stock = ps.stock + 1
            WHERE uu.id = %s
        """, (uniform_id,))
    if reason == "lost":
        flash("⚠️ Glöm inte att polisanmäla plagg som försvunnit innan ersättning begärs!", "warning")
    else:
        flash("Uniform return recorded. Stock has been updated.", "success")
    db.commit()
    return redirect(url_for("my_uniforms"))


@app.route("/request-replacement/<int:uniform_id>", methods=["POST"])
def request_replacement(uniform_id):
    if session.get("system_role") not in ("supervisor", "admin"):
        return redirect(url_for("shop"))
    flash("⚠️ Glöm inte att polisanmäla plagg innan ersättning!", "warning")
    cursor = get_cursor()
    cursor.execute("UPDATE user_uniforms SET status='lost' WHERE id=%s", (uniform_id,))
    db.commit()
    return redirect(url_for("my_uniforms"))


# ─────────────────────────────────────────────
# ADMIN — USERS
# ─────────────────────────────────────────────
@app.route("/admin/users")
def admin_users():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("""
        SELECT u.id, u.email, u.system_role, u.full_name,
               u.supervisor_id, u.country,
               jr.name AS job_role,
               s.full_name AS supervisor_name,
               f.name AS facility_name
        FROM users u
        LEFT JOIN job_roles jr ON u.job_role_id = jr.id
        LEFT JOIN users s ON u.supervisor_id = s.id
        LEFT JOIN facilities f ON u.facility_id = f.id
        ORDER BY u.id DESC
    """)
    users = cursor.fetchall()
    cursor.execute("SELECT id, name FROM job_roles ORDER BY name")
    job_roles = cursor.fetchall()
    cursor.execute("SELECT id, full_name FROM users WHERE system_role='supervisor' ORDER BY full_name")
    supervisors = cursor.fetchall()
    cursor.execute("SELECT id, name FROM facilities ORDER BY name")
    facilities = cursor.fetchall()
    cursor.execute("SELECT id, name FROM sites ORDER BY name")
    sites = cursor.fetchall()
    return render_template("admin_users.html", users=users, job_roles=job_roles,
                           supervisors=supervisors, facilities=facilities, sites=sites)


@app.route("/admin/create-user", methods=["POST"])
def create_user():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    email = request.form["email"]
    password = request.form["password"]
    system_role = request.form["system_role"]
    full_name = request.form["full_name"]
    job_role_id = request.form.get("job_role_id") or None
    supervisor_id = request.form.get("supervisor_id") or None
    facility_id = request.form.get("facility_id") or None
    country = request.form.get("country") or None
    site_ids = request.form.getlist("site_ids")

    cursor = get_cursor()

    if system_role == "packer":
        cursor.execute("SELECT id FROM job_roles WHERE name='Packer'")
        pr = cursor.fetchone()
        if pr:
            job_role_id = pr["id"]

    try:

        cursor.execute("""
                    INSERT INTO users (full_name, email, password, system_role, job_role_id,
                                    supervisor_id, facility_id, country)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (full_name, email, password, system_role, job_role_id,
                    supervisor_id, facility_id, country))
        db.commit()
        new_user_id = cursor.lastrowid

        # Link sites
        for site_id in site_ids:
            cursor.execute("INSERT IGNORE INTO user_sites (user_id, site_id) VALUES (%s, %s)",
                           (new_user_id, site_id))
        db.commit()

        # Send welcome email
        send_welcome_email(email, full_name, system_role)

        flash(f"User '{full_name}' created successfully. A confirmation email has been sent.", "success")
    except IntegrityError as e:
        db.rollback()
        if "email" in str(e).lower():
            flash("A user with this email already exists.", "error")
        else:
            flash("Database error: " + str(e), "error")

    return redirect(url_for("admin_users"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_users"))
    cursor = get_cursor()
    cursor.execute("SELECT system_role FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))
    if user["system_role"] == "admin":
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE system_role='admin'")
        if cursor.fetchone()["cnt"] <= 1:
            flash("Cannot delete the last admin.", "error")
            return redirect(url_for("admin_users"))
    # Delete related data first to avoid FK constraint errors
    # If supervisor, remove their team members' data
    cursor.execute("SELECT id FROM team_members WHERE supervisor_id=%s", (user_id,))
    member_ids = [r["id"] for r in cursor.fetchall()]
    for mid in member_ids:
        cursor.execute("DELETE FROM worker_sizes WHERE team_member_id=%s", (mid,))
        cursor.execute("DELETE FROM order_items WHERE team_member_id=%s", (mid,))
        cursor.execute("DELETE FROM user_uniforms WHERE team_member_id=%s", (mid,))
    if member_ids:
        cursor.execute("DELETE FROM team_members WHERE supervisor_id=%s", (user_id,))
    # Remove order carts owned by this user
    cursor.execute("DELETE FROM order_items WHERE cart_id IN (SELECT id FROM order_carts WHERE supervisor_id=%s)", (user_id,))
    cursor.execute("DELETE FROM order_carts WHERE supervisor_id=%s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    db.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/edit-user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    system_role = request.form.get("system_role")
    job_role_id = request.form.get("job_role_id") or None
    country = request.form.get("country") or None
    monthly_budget = request.form.get("monthly_budget", "").strip() or None
    new_password = request.form.get("password", "").strip()

    if new_password:
        cursor.execute("""
            UPDATE users SET full_name=%s, email=%s, system_role=%s, job_role_id=%s,
            country=%s, monthly_budget=%s, password=%s WHERE id=%s
        """, (full_name, email, system_role, job_role_id, country, monthly_budget, new_password, user_id))
    else:
        cursor.execute("""
            UPDATE users SET full_name=%s, email=%s, system_role=%s, job_role_id=%s,
            country=%s, monthly_budget=%s WHERE id=%s
        """, (full_name, email, system_role, job_role_id, country, monthly_budget, user_id))
    db.commit()
    flash("User updated.", "success")
    return redirect(url_for("admin_users"))


def admin_view_supervisor_team(supervisor_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT id, full_name FROM users WHERE id=%s AND system_role='supervisor'", (supervisor_id,))
    supervisor = cursor.fetchone()
    if not supervisor:
        flash("Supervisor not found.", "error")
        return redirect(url_for("admin_users"))
    cursor.execute("""
        SELECT tm.full_name, tm.employee_number, jr.name AS job_role
        FROM team_members tm
        LEFT JOIN job_roles jr ON tm.job_role_id = jr.id
        WHERE tm.supervisor_id=%s
    """, (supervisor_id,))
    workers = cursor.fetchall()
    return render_template("admin_supervisor_team.html", supervisor=supervisor, workers=workers)


# ─────────────────────────────────────────────
# ADMIN — SITES & FACILITIES
# ─────────────────────────────────────────────
@app.route("/admin/sites", methods=["GET", "POST"])
def admin_sites():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
            site_id = request.form.get("site_id")
            try:
                cursor.execute("DELETE FROM sites WHERE id=%s", (site_id,))
                db.commit()
                flash("Site deleted.", "success")
            except Exception:
                flash("Cannot delete site (may be in use).", "error")
        else:
            name = request.form["name"]
            cursor.execute("INSERT INTO sites (name) VALUES (%s)", (name,))
            db.commit()
            flash("Site added.", "success")
    cursor.execute("SELECT * FROM sites ORDER BY name")
    sites = cursor.fetchall()
    return render_template("admin_sites.html", sites=sites)


@app.route("/admin/facilities", methods=["GET", "POST"])
def admin_facilities():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
            fac_id = request.form.get("facility_id")
            try:
                cursor.execute("DELETE FROM facilities WHERE id=%s", (fac_id,))
                db.commit()
                flash("Facility deleted.", "success")
            except Exception:
                flash("Cannot delete facility (may be in use).", "error")
        else:
            name = request.form["name"]
            cursor.execute("INSERT INTO facilities (name) VALUES (%s)", (name,))
            db.commit()
            flash("Facility added.", "success")
    cursor.execute("SELECT * FROM facilities ORDER BY name")
    facilities = cursor.fetchall()
    return render_template("admin_facilities.html", facilities=facilities)


# ─────────────────────────────────────────────
# ADMIN — JOB ROLES
# ─────────────────────────────────────────────
@app.route("/admin/job-roles", methods=["GET", "POST"])
def admin_job_roles():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        name = request.form["name"]
        cursor.execute("INSERT INTO job_roles (name) VALUES (%s)", (name,))
        db.commit()
        flash("Job role added.", "success")
    cursor.execute("SELECT * FROM job_roles ORDER BY name")
    roles = cursor.fetchall()
    return render_template("admin_job_roles.html", roles=roles)


@app.route("/admin/job-roles/delete/<int:role_id>", methods=["POST"])
def delete_job_role(role_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    try:
        cursor.execute("DELETE FROM job_roles WHERE id=%s", (role_id,))
        db.commit()
        flash("Job role deleted.", "success")
    except Exception:
        flash("Cannot delete role (it may be in use).", "error")
    return redirect(url_for("admin_job_roles"))


# ─────────────────────────────────────────────
# ADMIN — ANALYTICS & STOCK
# ─────────────────────────────────────────────
@app.route("/admin/analytics")
def admin_analytics():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = cursor.fetchone()["total_users"]
    cursor.execute("SELECT COUNT(*) as total_orders FROM order_carts WHERE status='completed'")
    total_orders = cursor.fetchone()["total_orders"]
    cursor.execute("""
        SELECT COALESCE(SUM(total_price),0) as revenue FROM order_carts
        WHERE status='completed'
          AND MONTH(created_at)=MONTH(CURRENT_DATE())
          AND YEAR(created_at)=YEAR(CURRENT_DATE())
    """)
    revenue = float(cursor.fetchone()["revenue"])
    cursor.execute("""
        SELECT u.full_name, COALESCE(SUM(oc.total_price),0) as total_spent
        FROM order_carts oc
        JOIN users u ON oc.supervisor_id = u.id
        WHERE oc.status='completed'
        GROUP BY u.id ORDER BY total_spent DESC
    """)
    supervisor_ranking = cursor.fetchall()
    cursor.execute("""
        SELECT p.name, SUM(oi.quantity) as total_quantity
        FROM order_items oi
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        GROUP BY p.id ORDER BY total_quantity DESC LIMIT 5
    """)
    top_products = cursor.fetchall()
    cursor.execute("""
        SELECT shoe_size, COUNT(*) as count FROM user_measurements GROUP BY shoe_size
    """)
    size_distribution = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) as low_stock FROM product_sizes WHERE stock <= 2")
    low_stock = cursor.fetchone()["low_stock"]
    return render_template("admin_analytics.html",
                           total_users=total_users, total_orders=total_orders,
                           revenue=revenue, top_products=top_products,
                           size_distribution=size_distribution, low_stock=low_stock,
                           supervisor_ranking=supervisor_ranking)


@app.route("/admin/reorder-engine")
def admin_reorder_engine():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("""
        SELECT p.name, ps.size, ps.stock, COALESCE(SUM(oi.quantity),0) as total_sold
        FROM product_sizes ps
        JOIN products p ON ps.product_id = p.id
        LEFT JOIN order_items oi ON oi.product_size_id = ps.id
        LEFT JOIN order_carts oc ON oi.cart_id = oc.id AND oc.status='completed'
        GROUP BY ps.id
    """)
    suggestions = []
    for product in cursor.fetchall():
        monthly_usage = product["total_sold"] or 0
        if monthly_usage == 0:
            continue
        projected_days = (product["stock"] / monthly_usage) * 30
        if projected_days < 30:
            suggested = max(0, int((monthly_usage * 2) - product["stock"]))
            suggestions.append({**product, "monthly_usage": monthly_usage, "suggested_reorder": suggested})
    return render_template("admin_reorder_engine.html", suggestions=suggestions)


@app.route("/admin/stock-risk")
def admin_stock_risk():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("""
        SELECT p.name, ps.size, ps.stock
        FROM product_sizes ps
        JOIN products p ON ps.product_id = p.id
        WHERE ps.stock <= 2 ORDER BY ps.stock ASC
    """)
    return render_template("admin_stock_risk.html", risk_items=cursor.fetchall())


@app.route("/admin")
def admin_dashboard():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT COUNT(*) as count FROM users")
    users_count = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM team_members")
    team_count = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM products")
    product_count = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM order_carts")
    orders_count = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM order_carts WHERE status IN ('submitted','created')")
    pending_orders = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE system_role='supervisor'")
    supervisor_count = cursor.fetchone()["count"]
    cursor.execute("""
        SELECT p.name, ps.size, ps.stock FROM product_sizes ps
        JOIN products p ON ps.product_id = p.id
        WHERE ps.stock <= 2 ORDER BY ps.stock ASC
    """)
    low_stock = cursor.fetchall()
    return render_template("admin_dashboard.html", low_stock=low_stock,
                           users_count=users_count, team_count=team_count,
                           product_count=product_count, orders_count=orders_count,
                           pending_orders=pending_orders, supervisor_count=supervisor_count)


@app.route("/admin/stats")
def admin_stats():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM order_carts GROUP BY status")
    status_stats = cursor.fetchall()
    cursor.execute("""
        SELECT u.full_name, COUNT(*) as total
        FROM order_carts oc
        JOIN users u ON oc.supervisor_id = u.id
        GROUP BY oc.supervisor_id
    """)
    supervisor_stats = cursor.fetchall()
    return render_template("admin_stats.html", status_stats=status_stats, supervisor_stats=supervisor_stats)


@app.route("/admin/export-orders")
def export_orders():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("""
        SELECT oc.id, u.full_name, oc.total_price, oc.status, oc.created_at
        FROM order_carts oc JOIN users u ON oc.supervisor_id = u.id
    """)
    df = pd.DataFrame(cursor.fetchall())
    file_path = "static/reports/orders_export.xlsx"
    df.to_excel(file_path, index=False)
    return send_from_directory("static/reports", "orders_export.xlsx", as_attachment=True)


# ─────────────────────────────────────────────
# ADMIN — SIZE GUIDES
# ─────────────────────────────────────────────
@app.route("/admin/size-guides", methods=["GET", "POST"])
def admin_size_guides():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        brand = request.form.get("brand")
        file = request.files.get("image")
        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("admin_size_guides"))
        filename = str(uuid.uuid4()) + "_" + secure_filename(file.filename)
        filepath = os.path.join("static", "uploads", filename)
        file.save(filepath)
        cursor.execute("INSERT INTO size_guides (brand_name, image_path) VALUES (%s, %s)",
                       (brand, f"uploads/{filename}"))
        db.commit()
        flash("Size guide uploaded.", "success")
        return redirect(url_for("admin_size_guides"))
    cursor.execute("SELECT * FROM size_guides ORDER BY created_at DESC")
    guides = cursor.fetchall()
    return render_template("admin_size_guides.html", guides=guides)


@app.route("/size-guide")
def size_guide():
    cursor = get_cursor()
    cursor.execute("SELECT * FROM size_guides ORDER BY created_at DESC")
    return render_template("size_guide.html", guides=cursor.fetchall())


@app.route("/admin/size-analytics")
def size_analytics():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("""
        SELECT product_type, size, COUNT(*) AS frequency
        FROM worker_sizes GROUP BY product_type, size ORDER BY product_type, frequency DESC
    """)
    distribution = cursor.fetchall()
    cursor.execute("""
        SELECT tm.facility_id, ws.product_type, ws.size, COUNT(*) AS frequency
        FROM worker_sizes ws
        JOIN team_members tm ON ws.team_member_id = tm.id
        GROUP BY tm.facility_id, ws.product_type, ws.size
    """)
    facility_distribution = cursor.fetchall()
    return render_template("size_analytics.html", distribution=distribution,
                           facility_distribution=facility_distribution)


# ─────────────────────────────────────────────
# NEWS
# ─────────────────────────────────────────────
@app.route("/news", methods=["GET", "POST"])
def news():
    if "user_id" not in session:
        return redirect(url_for("login"))
    cursor = get_cursor()
    os.makedirs(os.path.join("static", "uploads"), exist_ok=True)

    if request.method == "POST" and session.get("system_role") == "admin":
        title = request.form["title"]
        content = request.form["content"]
        target_role = request.form.get("target_role", "all")
        image = request.files.get("image")
        image_path = None
        if image and image.filename != "":
            filename = str(uuid.uuid4()) + "_" + secure_filename(image.filename)
            image.save(os.path.join("static", "uploads", filename))
            image_path = f"uploads/{filename}"
        cursor.execute("""
            INSERT INTO news_posts (title, content, created_by, target_role, image_path)
            VALUES (%s, %s, %s, %s, %s)
        """, (title, content, session["user_id"], target_role, image_path))
        db.commit()
        flash("Post created.", "success")
        return redirect(url_for("news"))

    cursor.execute("""
        SELECT np.*,
            u.full_name,
            (SELECT id FROM news_reads
                WHERE post_id=np.id AND user_id=%s LIMIT 1) IS NOT NULL AS is_read,
            COALESCE((SELECT COUNT(*) FROM news_likes WHERE post_id=np.id), 0) AS like_count,
            (SELECT id FROM news_likes
                WHERE post_id=np.id AND user_id=%s LIMIT 1) IS NOT NULL AS user_liked
        FROM news_posts np
        LEFT JOIN users u ON np.created_by = u.id
        WHERE np.target_role = 'all' OR np.target_role = %s
        ORDER BY COALESCE(np.pinned, 0) DESC, np.created_at DESC
    """, (session["user_id"], session["user_id"], session.get("system_role")))
    posts = cursor.fetchall()

    for post in posts:
        cc = get_cursor()
        cc.execute("""
            SELECT nc.*, u.full_name FROM news_comments nc
            JOIN users u ON nc.user_id = u.id
            WHERE nc.post_id=%s ORDER BY nc.created_at ASC
        """, (post["id"],))
        post["comments"] = cc.fetchall()

    return render_template("news.html", posts=posts)


@app.route("/news/comment/delete/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    if session.get("system_role") != "admin":
        return jsonify({"error": "unauthorized"}), 401
    cursor = get_cursor()
    cursor.execute("DELETE FROM news_comments WHERE id=%s", (comment_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/news/comment/<int:post_id>", methods=["POST"])
def add_comment(post_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    comment = request.form.get("comment", "").strip()
    if not comment:
        return jsonify({"error": "empty"}), 400
    cursor = get_cursor()
    cursor.execute("INSERT INTO news_comments (post_id, user_id, comment) VALUES (%s, %s, %s)",
                   (post_id, session["user_id"], comment))
    db.commit()
    comment_id = cursor.lastrowid
    cursor.execute("SELECT u.full_name, nc.created_at FROM news_comments nc JOIN users u ON nc.user_id=u.id WHERE nc.id=%s", (comment_id,))
    row = cursor.fetchone()
    return jsonify({"id": comment_id, "comment": comment, "full_name": row["full_name"],
                    "created_at": str(row["created_at"])[:10] if row["created_at"] else ""})

@app.route("/news/like/<int:post_id>", methods=["POST"])
def like_post(post_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    cursor = get_cursor()
    cursor.execute("SELECT id FROM news_likes WHERE post_id=%s AND user_id=%s",
                   (post_id, session["user_id"]))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("DELETE FROM news_likes WHERE post_id=%s AND user_id=%s",
                       (post_id, session["user_id"]))
        liked = False
    else:
        cursor.execute("INSERT IGNORE INTO news_likes (post_id, user_id) VALUES (%s, %s)",
                       (post_id, session["user_id"]))
        liked = True
    db.commit()
    cursor.execute("SELECT COUNT(*) as cnt FROM news_likes WHERE post_id=%s", (post_id,))
    count = cursor.fetchone()["cnt"]
    return jsonify({"liked": liked, "count": count})

@app.route("/admin/size-guides/edit/<int:guide_id>", methods=["POST"])
def edit_size_guide(guide_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    brand = request.form.get("brand_name", "").strip()
    if brand:
        cursor = get_cursor()
        cursor.execute("UPDATE size_guides SET brand_name=%s WHERE id=%s", (brand, guide_id))
        db.commit()
        flash("Size guide updated.", "success")
    return redirect(url_for("admin_size_guides"))


@app.route("/admin/size-guides/delete/<int:guide_id>", methods=["POST"])
def delete_size_guide(guide_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("DELETE FROM size_guides WHERE id=%s", (guide_id,))
    db.commit()
    flash("Size guide deleted.", "success")
    return redirect(url_for("size_guide"))

@app.route("/news/delete/<int:post_id>", methods=["POST"])
def delete_news(post_id):
    if session.get("system_role") != "admin":
        return "Unauthorized", 403
    cursor = get_cursor()
    # Delete comments and likes first
    cursor.execute("DELETE FROM news_comments WHERE post_id=%s", (post_id,))
    cursor.execute("DELETE FROM news_likes WHERE post_id=%s", (post_id,))
    cursor.execute("DELETE FROM news_reads WHERE post_id=%s", (post_id,))
    cursor.execute("DELETE FROM news_posts WHERE id=%s", (post_id,))
    db.commit()
    # Stay on whichever page triggered the delete
    ref = request.referrer or ''
    if 'admin/news' in ref:
        return redirect(url_for("admin_news"))
    return redirect(url_for("news"))


@app.route("/news/edit/<int:post_id>", methods=["POST"])
def edit_news(post_id):
    if session.get("system_role") != "admin":
        return "Unauthorized", 403
    cursor = get_cursor()
    cursor.execute("SELECT * FROM news_posts WHERE id=%s", (post_id,))
    post = cursor.fetchone()
    if not post:
        flash("Post not found.", "error")
        return redirect(url_for("admin_news"))

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    target_role = request.form.get("target_role", "all")
    image_path = post["image_path"]

    image = request.files.get("image")
    if image and image.filename != "":
        filename = str(uuid.uuid4()) + "_" + secure_filename(image.filename)
        os.makedirs(os.path.join("static", "uploads"), exist_ok=True)
        image.save(os.path.join("static", "uploads", filename))
        image_path = f"uploads/{filename}"

    cursor.execute("""
        UPDATE news_posts SET title=%s, content=%s, target_role=%s, image_path=%s WHERE id=%s
    """, (title, content, target_role, image_path, post_id))
    db.commit()
    flash("Post updated.", "success")
    return redirect(url_for("admin_news"))


@app.route("/news/read/<int:post_id>", methods=["GET","POST"])
def mark_news_read(post_id):
    cursor = get_cursor()
    cursor.execute("INSERT IGNORE INTO news_reads (post_id, user_id) VALUES (%s, %s)",
                   (post_id, session.get("user_id")))
    db.commit()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True})
    return redirect(url_for("news"))


# ─────────────────────────────────────────────
# ADMIN — NEWS
# ─────────────────────────────────────────────
@app.route("/admin/news", methods=["GET", "POST"])
def admin_news():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    cursor = get_cursor()
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        target_role = request.form.get("target_role", "all")
        image_path = None
        image = request.files.get("image")
        if image and image.filename != "":
            filename = str(uuid.uuid4()) + "_" + secure_filename(image.filename)
            os.makedirs(os.path.join("static", "uploads"), exist_ok=True)
            image.save(os.path.join("static", "uploads", filename))
            image_path = f"uploads/{filename}"
        cursor.execute("""
            INSERT INTO news_posts (title, content, created_by, target_role, image_path)
            VALUES (%s, %s, %s, %s, %s)
        """, (title, content, session["user_id"], target_role, image_path))
        db.commit()
        flash("News post created.", "success")
        return redirect(url_for("admin_news"))
    cursor.execute("SELECT * FROM news_posts ORDER BY created_at DESC")
    posts = cursor.fetchall()
    return render_template("admin_news.html", posts=posts)


# ─────────────────────────────────────────────
# MISC / STATIC
# ─────────────────────────────────────────────
@app.route("/measurements")
def measurements():
    return render_template("placeholder.html", title="Size Guide", message="Under development...")


@app.route("/my-uniforms-legacy")
def my_uniforms_legacy():
    return redirect(url_for("my_uniforms"))


@app.route('/static/<path:filename>')
def custom_static(filename):
    return send_from_directory('static', filename)


@app.after_request
def add_cache_headers(response):
    if "static" in request.path:
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response

@app.route("/api/currency")
def currency_api():
    """Proxy for currency conversion — uses frankfurter.app (free, no key needed)."""
    from_currency = request.args.get("from", "SEK")
    to_currency = request.args.get("to", "EUR")
    try:
        import urllib.request, json
        url = f"https://api.frankfurter.app/latest?from={from_currency}&to={to_currency}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            rate = data.get("rates", {}).get(to_currency)
            return jsonify({"rate": rate, "from": from_currency, "to": to_currency})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/products")
def get_products():
    cursor = get_cursor()
    cursor.execute("SELECT * FROM products")
    return jsonify(cursor.fetchall())


# ─────────────────────────────────────────────
# BULK ORDER
# ─────────────────────────────────────────────
@app.route("/bulk-order", methods=["GET", "POST"])
def bulk_order():
    if session.get("system_role") not in ("supervisor", "admin"):
        return redirect(url_for("shop"))
    cursor = get_cursor()
    uid = session["user_id"]

    # Get team members
    if session["system_role"] == "supervisor":
        cursor.execute("SELECT id, full_name, employee_number FROM team_members WHERE supervisor_id=%s ORDER BY full_name", (uid,))
    else:
        cursor.execute("SELECT id, full_name, employee_number FROM team_members ORDER BY full_name")
    team = cursor.fetchall()

    # Get products with sizes
    cursor.execute("SELECT * FROM products ORDER BY name")
    products = cursor.fetchall()
    for p in products:
        cursor.execute("SELECT id, size, stock FROM product_sizes WHERE product_id=%s", (p["id"],))
        p["sizes"] = cursor.fetchall()

    if request.method == "POST":
        # Format: member_id[], product_size_id[], quantity[]
        member_ids = request.form.getlist("member_id")
        size_ids = request.form.getlist("product_size_id")
        quantities = request.form.getlist("quantity")

        if not member_ids or not size_ids:
            flash("Please select at least one worker and one item.", "error")
            return redirect(url_for("bulk_order"))

        # Create one cart
        cursor.execute("INSERT INTO order_carts (supervisor_id, status) VALUES (%s, 'created')", (uid,))
        db.commit()
        cart_id = cursor.lastrowid

        for member_id in member_ids:
            for i, size_id in enumerate(size_ids):
                qty = int(quantities[i]) if i < len(quantities) and quantities[i] else 1
                if qty <= 0:
                    continue
                cursor.execute("SELECT p.price FROM product_sizes ps JOIN products p ON ps.product_id=p.id WHERE ps.id=%s", (size_id,))
                price_row = cursor.fetchone()
                price = float(price_row["price"]) if price_row and price_row.get("price") else 0.0
                cursor.execute("""
                    INSERT INTO order_items (cart_id, product_size_id, quantity, price_at_time, team_member_id)
                    VALUES (%s, %s, %s, %s, %s)
                """, (cart_id, size_id, qty, price, member_id))

        # Update cart total
        cursor.execute("""
            UPDATE order_carts SET total_price=(
                SELECT COALESCE(SUM(quantity*price_at_time),0) FROM order_items WHERE cart_id=%s
            ) WHERE id=%s
        """, (cart_id, cart_id))
        db.commit()
        flash(f"Bulk order created for {len(member_ids)} worker(s).", "success")
        return redirect(url_for("view_cart"))

    return render_template("bulk_order.html", team=team, products=products)


# ─────────────────────────────────────────────
# WORKER UNIFORM HISTORY
# ─────────────────────────────────────────────
@app.route("/worker/<int:member_id>/history")
def worker_history(member_id):
    if session.get("system_role") not in ("supervisor", "admin"):
        return redirect(url_for("shop"))
    cursor = get_cursor()
    cursor.execute("SELECT * FROM team_members WHERE id=%s", (member_id,))
    member = cursor.fetchone()
    if not member:
        flash("Worker not found.", "error")
        return redirect(url_for("view_team"))

    cursor.execute("""
        SELECT oc.id AS order_id, oc.created_at AS order_date, oc.status,
               p.name AS product_name, ps.size, oi.quantity
        FROM order_items oi
        JOIN order_carts oc ON oi.cart_id = oc.id
        JOIN product_sizes ps ON oi.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        WHERE oi.team_member_id = %s
        ORDER BY oc.created_at DESC
    """, (member_id,))
    uniforms = cursor.fetchall()

    return render_template("worker_history.html", member=member, uniforms=uniforms)


# ─────────────────────────────────────────────
# PROFILE
# ─────────────────────────────────────────────
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    cursor = get_cursor()
    uid = session["user_id"]

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")

        cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))
        user = cursor.fetchone()

        if new_password:
            if current_password != user["password"]:
                flash("Current password is incorrect.", "error")
                return redirect(url_for("profile"))
            cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_password, uid))

        # Handle photo upload
        photo = request.files.get("photo")
        photo_path = None
        if photo and photo.filename:
            filename = str(uuid.uuid4()) + "_" + secure_filename(photo.filename)
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            photo_path = f"uploads/{filename}"
            cursor.execute("UPDATE users SET profile_photo=%s WHERE id=%s", (photo_path, uid))

        cursor.execute("UPDATE users SET full_name=%s, email=%s WHERE id=%s", (full_name, email, uid))
        db.commit()
        session["full_name"] = full_name
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))

    cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cursor.fetchone()
    return render_template("profile.html", user=user)


# ─────────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────────
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        cursor = get_cursor()
        cursor.execute("SELECT id, full_name FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        if user:
            token = str(uuid.uuid4())
            expires = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE users SET reset_token=%s, reset_token_expires=DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id=%s",
                           (token, user["id"]))
            db.commit()
            site_url = os.environ.get("SITE_URL", "http://localhost:5000")
            reset_link = f"{site_url}/reset-password/{token}"
            send_reset_email(email, user["full_name"], reset_link)
        # Always show same message to prevent email enumeration
        flash("If that email exists, a reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    cursor = get_cursor()
    cursor.execute("SELECT id FROM users WHERE reset_token=%s AND reset_token_expires > NOW()", (token,))
    user = cursor.fetchone()
    if not user:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        cursor.execute("UPDATE users SET password=%s, reset_token=NULL, reset_token_expires=NULL WHERE id=%s",
                       (new_password, user["id"]))
        db.commit()
        flash("Password reset successfully. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


def send_reset_email(to_email, full_name, reset_link):
    import ssl, threading
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_port = int(os.environ.get("SMTP_PORT", 465))
    from_addr = os.environ.get("SMTP_FROM", smtp_user)
    if not smtp_host or not smtp_user:
        # No SMTP configured — print link to console for local dev
        print(f"[PASSWORD RESET] Link for {to_email}: {reset_link}")
        return
    subject = "Reset your DHL Corporate Wear password"
    body = f"""Hi {full_name},

You requested a password reset. Click the link below to set a new password:

{reset_link}

This link expires in 1 hour. If you didn't request this, ignore this email.

Best regards,
DHL Corporate Wear Team"""

    def _send():
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import smtplib
            msg = MIMEMultipart()
            msg["From"] = from_addr
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, to_email, msg.as_string())
        except Exception as e:
            print(f"[EMAIL] Reset email failed: {e}")
            print(f"[PASSWORD RESET] Fallback link for {to_email}: {reset_link}")
    threading.Thread(target=_send, daemon=True).start()


# ─────────────────────────────────────────────
# PIN NEWS
# ─────────────────────────────────────────────
@app.route("/news/pin/<int:post_id>", methods=["POST"])
def pin_news(post_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("news"))
    cursor = get_cursor()
    cursor.execute("SELECT pinned FROM news_posts WHERE id=%s", (post_id,))
    post = cursor.fetchone()
    if post:
        new_val = 0 if post.get("pinned") else 1
        cursor.execute("UPDATE news_posts SET pinned=%s WHERE id=%s", (new_val, post_id))
        db.commit()
    return redirect(url_for("news"))

@app.route('/debug-db')
def debug_db():
    try:
        conn = mysql.connector.connect(**get_db_config())
        conn.close()
        return "DB Connected OK!"
    except Exception as e:
        return f"DB Connection FAILED: {str(e)}"

@app.route("/admin/returns")
def admin_returns():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    return render_template("admin_returns.html")


if __name__ == "__main__":
    app.run(debug=True)
