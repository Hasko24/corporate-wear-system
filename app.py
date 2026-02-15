import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from flask import session
from flask import send_from_directory

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
print("RUNNING CORRECT APP.PY")

db = mysql.connector.connect(
    host=os.environ.get("DB_HOST"),
    user=os.environ.get("DB_USER"),
    password=os.environ.get("DB_PASSWORD"),
    database=os.environ.get("DB_NAME"),
    port=int(os.environ.get("DB_PORT", 3306))
)

@app.route('/static/<path:filename>')
def custom_static(filename):
    return send_from_directory('static', filename)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM users WHERE email=%s AND password=%s",
            (email, password)
        )
        user = cursor.fetchone()

        if user:
            session["user_id"] = user["id"]
            session["system_role"] = user["system_role"]
            session["job_role_id"] = user["job_role_id"]
            session["user_id"] = user["id"]
            if user["system_role"] == "packer":
                return redirect(url_for("view_orders"))
            elif user["system_role"] == "supervisor":
                return redirect(url_for("view_orders"))
            elif user["system_role"] == "admin":
                return redirect(url_for("shop"))
            else:  # worker
                return redirect(url_for("shop"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/products")
def get_products():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    return jsonify(products)

@app.route("/shop")
def shop():
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor = db.cursor(dictionary=True)

    selected_role = request.args.get("role")

    # =========================
    # ADMIN VIEW
    # =========================
    if session["system_role"] == "admin":

        if selected_role:
            cursor.execute("""
                SELECT DISTINCT p.*
                FROM products p
                JOIN product_job_roles pj ON p.id = pj.product_id
                JOIN job_roles jr ON pj.job_role_id = jr.id
                WHERE pj.job_role_id = %s
                OR pj.job_role_id = (
                    SELECT id FROM job_roles WHERE name='Everyone'
                )
                OR jr.name = 'All'
                ORDER BY p.article_number
            """, (selected_role,))
        else:
            cursor.execute("""
                SELECT *
                FROM products
                ORDER BY article_number
            """)

        products = cursor.fetchall()

        cursor.execute("SELECT id, name FROM job_roles ORDER BY name")
        job_roles = cursor.fetchall()

    # =========================
    # NON-ADMIN VIEW
    # =========================
    else:
        cursor.execute("""
            SELECT DISTINCT p.*
            FROM products p
            JOIN product_job_roles pj ON p.id = pj.product_id
            WHERE pj.job_role_id = %s
            OR pj.job_role_id = (
                SELECT id FROM job_roles WHERE name='Everyone'
            )
            ORDER BY p.article_number
        """, (session["job_role_id"],))

        products = cursor.fetchall()
        job_roles = []
        selected_role = None

    # =========================
    # WORKER ORDERS
    # =========================
    worker_orders = []

    if session.get("system_role") == "worker":
        cursor.execute("""
            SELECT o.id,
                p.name,
                ps.size,
                o.status,
                o.created_at
            FROM orders o
            JOIN product_sizes ps ON o.product_size_id = ps.id
            JOIN products p ON ps.product_id = p.id
            WHERE o.user_id = %s
            ORDER BY o.created_at DESC
        """, (session["user_id"],))

    worker_orders = cursor.fetchall()

    for product in products:
        size_cursor = db.cursor(dictionary=True)

        size_cursor.execute("""
            SELECT id, size, stock
            FROM product_sizes
            WHERE product_id = %s
        """, (product["id"],))

        product["sizes"] = size_cursor.fetchall()

    # =========================
    # RETURN RESPONSE (AFTER LOOP)
    # =========================
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return render_template(
            "_product_grid.html",
            products=products
        )

    return render_template(
        "shop.html",
        products=products,
        worker_orders=worker_orders,
        job_roles=job_roles,
        selected_role=selected_role
    )

from flask import jsonify

@app.route("/get-sizes/<int:product_id>")
def get_sizes(product_id):
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, size, stock
        FROM product_sizes
        WHERE product_id = %s
    """, (product_id,))
    sizes = cursor.fetchall()
    return jsonify(sizes)

@app.route("/update-stock/<int:product_id>", methods=["POST"])
def update_stock(product_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT id FROM product_sizes
        WHERE product_id = %s
    """, (product_id,))
    sizes = cursor.fetchall()

    for size in sizes:
        field_name = f"size_{size['id']}"
        add_amount = request.form.get(field_name)

        if add_amount and add_amount.isdigit():
            cursor.execute("""
                UPDATE product_sizes
                SET stock = stock + %s
                WHERE id = %s
            """, (int(add_amount), size["id"]))

    db.commit()

    flash("Stock updated successfully.", "success")
    return redirect(url_for("shop"))

@app.after_request
def add_cache_headers(response):
    if "static" in request.path:
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response

@app.route("/add-product", methods=["GET", "POST"])
def add_product():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))
    
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":

        article_number = request.form.get("article_number").strip()
        name = request.form.get("name").strip()
        description = request.form.get("description") or None
        product_type = request.form.get("type")
        job_role_ids = request.form.getlist("job_role_ids")

        # 🔹 CHECK DUPLICATES FIRST
        cursor.execute("SELECT id FROM products WHERE name = %s", (name,))
        if cursor.fetchone():
            flash("A product with this name already exists.", "error")
            return redirect(url_for("add_product"))

        cursor.execute("SELECT id FROM products WHERE article_number = %s", (article_number,))
        if cursor.fetchone():
            flash("A product with this article number already exists.", "error")
            return redirect(url_for("add_product"))

        # 🔹 Handle image
        image = None
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename != "":
                image = file.filename
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], image))

        # 🔹 Insert product FIRST
        cursor.execute("""
            INSERT INTO products (article_number, name, type, image, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (article_number, name, product_type, image, description))

        db.commit()

        # 🔹 Get product_id immediately after insert
        product_id = cursor.lastrowid

        # 🔹 Assign job roles AFTER product exists
        for role_id in job_role_ids:
            cursor.execute("""
                INSERT INTO product_job_roles (product_id, job_role_id)
                VALUES (%s, %s)
            """, (product_id, role_id))

        # 🔹 Insert sizes
        for key, value in request.form.items():
            if key.startswith("size_"):
                size_name = key.replace("size_", "")
                stock = int(value) if value else 0

                cursor.execute("""
                    INSERT INTO product_sizes (product_id, size, stock)
                    VALUES (%s, %s, %s)
                """, (product_id, size_name, stock))

        db.commit()

        flash("Product added successfully.", "success")
        return redirect(url_for("shop"))

    # GET
    cursor.execute("SELECT id, name FROM job_roles ORDER BY name")
    job_roles = cursor.fetchall()

    return render_template("add_product.html", job_roles=job_roles)

@app.route("/delete-product/<int:product_id>", methods=["POST"])
def delete_product(product_id):
    cursor = db.cursor()

    cursor.execute("DELETE FROM product_job_roles WHERE product_id=%s", (product_id,))
    cursor.execute("DELETE FROM product_sizes WHERE product_id=%s", (product_id,))
    cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))

    db.commit()

    flash("Product removed", "success")
    return redirect(url_for("shop"))

@app.route("/order", methods=["POST"])
def order_product():

    role = session.get("system_role")

    if role not in ["worker", "supervisor"]:
        return redirect(url_for("shop"))

    product_size_id = request.form.get("product_size_id")

    if not product_size_id:
        flash("Please select a size.", "error")
        return redirect(url_for("shop"))

    if role == "worker":
        status = "pending_approval"
    elif role == "supervisor":
        status = "pending_admin"

    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO orders (product_size_id, user_id, status)
        VALUES (%s, %s, %s)
    """, (product_size_id, session["user_id"], status))

    db.commit()

    flash("Order created successfully.", "success")
    return redirect(url_for("shop"))

@app.route("/orders")
def view_orders():
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor = db.cursor(dictionary=True)

    role = session.get("system_role")
    user_id = session.get("user_id")

    base_query = """
        SELECT 
            o.id,
            o.status,
            o.created_at,
            p.name AS product_name,
            ps.size AS size_name,
            u.full_name AS user_name,
            packer.full_name AS packed_by_name
        FROM orders o
        JOIN product_sizes ps ON o.product_size_id = ps.id
        JOIN products p ON ps.product_id = p.id
        JOIN users u ON o.user_id = u.id
        LEFT JOIN users packer ON o.packed_by = packer.id
    """

    if role == "worker":
        cursor.execute(base_query + """
            WHERE o.user_id = %s
            ORDER BY o.created_at DESC
        """, (user_id,))

    elif role == "supervisor":
        cursor.execute(base_query + """
            WHERE u.supervisor_id = %s
            ORDER BY o.created_at DESC
        """, (user_id,))

    elif role == "packer":
        cursor.execute(base_query + """
            WHERE o.status IN ('approved', 'packed')
            ORDER BY o.created_at DESC
        """)

    elif role == "admin":
        cursor.execute(base_query + """
            ORDER BY o.created_at DESC
        """)

    else:
        return redirect(url_for("shop"))

    orders = cursor.fetchall()
    cursor.close()

    return render_template("orders.html", orders=orders)

@app.route("/approve-order/<int:order_id>", methods=["POST"])
def approve_order(order_id):

    role = session.get("system_role")
    user_id = session.get("user_id")

    if role not in ["supervisor", "admin"]:
        return redirect(url_for("shop"))

    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT o.product_size_id, o.status, u.supervisor_id
        FROM orders o
        JOIN users u ON o.user_id = u.id
        WHERE o.id = %s
    """, (order_id,))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("view_orders"))

    # Supervisor approves worker orders
    if role == "supervisor":

        if order["status"] != "pending_approval":
            flash("Not waiting for supervisor approval.", "error")
            return redirect(url_for("view_orders"))

        # Make sure supervisor only approves their own workers
        if order["supervisor_id"] != user_id:
            flash("You can only approve your own team orders.", "error")
            return redirect(url_for("view_orders"))

        cursor.execute("""
            UPDATE orders
            SET status = 'approved'
            WHERE id = %s
        """, (order_id,))

    # Admin approves supervisor orders
    elif role == "admin":

        if order["status"] != "pending_admin":
            flash("Not waiting for admin approval.", "error")
            return redirect(url_for("view_orders"))

        cursor.execute("""
            UPDATE orders
            SET status = 'approved'
            WHERE id = %s
        """, (order_id,))

    # Reduce stock only after final approval
    cursor.execute("""
        UPDATE product_sizes
        SET stock = stock - 1
        WHERE id = %s
    """, (order["product_size_id"],))

    db.commit()

    flash("Order approved.", "success")
    return redirect(url_for("view_orders"))

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    # Prevent deleting yourself
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_users"))

    cursor = db.cursor(dictionary=True)

    # Check if user exists
    cursor.execute("SELECT system_role FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))

    # Optional safety: prevent deleting last admin
    if user["system_role"] == "admin":
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE system_role='admin'")
        admin_count = cursor.fetchone()["count"]

        if admin_count <= 1:
            flash("Cannot delete the last admin.", "error")
            return redirect(url_for("admin_users"))

    # Delete user
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()

    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_users"))

@app.route("/pack-order/<int:order_id>", methods=["POST"])
def pack_order(order_id):
    if session.get("system_role") != "packer":
        return redirect(url_for("view_orders"))

    cursor = db.cursor()
    cursor.execute("""
        UPDATE orders
        SET status='packed',
            packed_at=NOW(),
            packed_by=%s
        WHERE id=%s
    """, (session["user_id"], order_id))
    db.commit()

    return redirect(url_for("view_orders"))

@app.route("/undo-pack/<int:order_id>", methods=["POST"])
def undo_pack(order_id):
    if session.get("system_role") != "packer":
        return redirect(url_for("view_orders"))

    cursor = db.cursor()
    cursor.execute("""
        UPDATE orders
        SET status='approved',
            packed_at=NULL,
            packed_by=NULL
        WHERE id=%s AND status='packed'
    """, (order_id,))

    db.commit()
    return redirect(url_for("view_orders"))


@app.route("/send-order/<int:order_id>", methods=["POST"])
def send_order(order_id):
    if session.get("system_role") != "packer":
        return redirect(url_for("view_orders"))

    cursor = db.cursor()
    cursor.execute("""
        UPDATE orders
        SET status='sent'
        WHERE id=%s
    """, (order_id,))
    db.commit()

    return redirect(url_for("view_orders"))

@app.route("/add-stock/<int:size_id>", methods=["POST"])
def add_stock(size_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    amount = request.form.get("amount", 0)

    cursor = db.cursor()
    cursor.execute("""
        UPDATE product_sizes
        SET stock = stock + %s
        WHERE id = %s
    """, (amount, size_id))

    db.commit()

    flash("Stock updated successfully.", "success")
    return redirect(url_for("shop"))

@app.route("/reject-order/<int:order_id>", methods=["POST"])
def reject_order(order_id):

    role = session.get("system_role")

    if role not in ["supervisor", "admin"]:
        return redirect(url_for("view_orders"))

    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT status
        FROM orders
        WHERE id = %s
    """, (order_id,))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("view_orders"))

    # Supervisor rejects worker orders
    if role == "supervisor" and order["status"] != "pending_approval":
        flash("Not waiting for supervisor approval.", "error")
        return redirect(url_for("view_orders"))

    # Admin rejects supervisor orders
    if role == "admin" and order["status"] != "pending_admin":
        flash("Not waiting for admin approval.", "error")
        return redirect(url_for("view_orders"))

    cursor.execute("""
        UPDATE orders
        SET status = 'rejected'
        WHERE id = %s
    """, (order_id,))

    db.commit()

    flash("Order rejected.", "success")
    return redirect(url_for("view_orders"))

@app.route("/create-supervisor", methods=["POST"])
def create_supervisor():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    email = request.form["email"]
    password = request.form["password"]

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO users (email, password, system_role)
        VALUES (%s, %s, 'supervisor')
    """, (email, password))

    db.commit()

    flash("Supervisor created.", "success")
    return redirect(url_for("shop"))

@app.route("/my-uniforms")
def my_uniforms():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "placeholder.html",
        title="My Uniforms",
        message="Under development..."
    )

@app.route("/request-replacement/<int:uniform_id>", methods=["POST"])
def request_replacement(uniform_id):
    if session.get("system_role") not in ["worker", "supervisor"]:
        return redirect(url_for("shop"))

    flash("Glöm inte att polisanmäla plagg innan ersättning!", "error")

    # mark old one as lost
    cursor = db.cursor()
    cursor.execute("""
        UPDATE user_uniforms
        SET status='lost'
        WHERE id=%s
    """, (uniform_id,))
    db.commit()

    return redirect(url_for("my_uniforms"))

@app.route("/news")
def news():
    return render_template(
        "placeholder.html",
        title="News",
        message="Under development..."
    )

@app.route("/create-post", methods=["POST"])
def create_post():
    if session.get("system_role") != "admin":
        return redirect(url_for("news"))

    title = request.form["title"]
    content = request.form["content"]

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO news_posts (title, content, created_by)
        VALUES (%s, %s, %s)
    """, (title, content, session["user_id"]))

    db.commit()
    return redirect(url_for("news"))

def recommend_size(height, chest):
    if chest < 95:
        return "S"
    elif chest < 105:
        return "M"
    elif chest < 115:
        return "L"
    else:
        return "XL"

@app.route("/measurements")
def measurements():
    return render_template(
        "placeholder.html",
        title="Size Guide",
        message="Under development..."
    )

@app.route("/my-team")
def my_team():
    if session.get("system_role") != "supervisor":
        return redirect(url_for("shop"))

    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, full_name, email
        FROM users
        WHERE supervisor_id = %s
    """, (session["user_id"],))

    workers = cursor.fetchall()
    return render_template("my_team.html", workers=workers)

@app.route("/admin/users")
def admin_users():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    cursor = db.cursor(dictionary=True)

    # All users
    cursor.execute("""
        SELECT 
            u.id,
            u.email,
            u.system_role,
            u.full_name,
            u.supervisor_id,
            jr.name AS job_role,
            s.full_name AS supervisor_name
        FROM users u
        LEFT JOIN job_roles jr ON u.job_role_id = jr.id
        LEFT JOIN users s ON u.supervisor_id = s.id
        ORDER BY u.id DESC
    """)

    users = cursor.fetchall()

    # Job roles
    cursor.execute("SELECT id, name FROM job_roles ORDER BY name")
    job_roles = cursor.fetchall()

    # Supervisors
    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE system_role = 'supervisor'
    """)
    supervisors = cursor.fetchall()

    return render_template(
        "admin_users.html",
        users=users,
        job_roles=job_roles,
        supervisors=supervisors
    )

from mysql.connector import IntegrityError

@app.route("/admin/create-user", methods=["POST"])
def create_user():
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    email = request.form["email"]
    password = request.form["password"]
    system_role = request.form["system_role"]
    full_name = request.form["full_name"]
    job_role_id = request.form.get("job_role_id")
    supervisor_id = request.form.get("supervisor_id")

    if supervisor_id == "":
        supervisor_id = None

    cursor = db.cursor()

    # 🔹 Automatically assign Packer job role
    if system_role == "packer":
        cursor.execute("SELECT id FROM job_roles WHERE name = 'Packer'")
        packer_role = cursor.fetchone()
        if packer_role:
            job_role_id = packer_role[0]
        else:
            flash("Packer job role not found in job_roles table.", "error")
            cursor.close()
            return redirect(url_for("admin_users"))

    # 🔹 Validate job role for non-packers
    if system_role != "packer" and not job_role_id:
        flash("This role requires a job role.", "error")
        cursor.close()
        return redirect(url_for("admin_users"))

    # 🔹 Workers must have supervisor
    if system_role == "worker" and supervisor_id is None:
        flash("Workers must be assigned to a supervisor.", "error")
        cursor.close()
        return redirect(url_for("admin_users"))

    try:
        cursor.execute("""
            INSERT INTO users (full_name, email, password, system_role, job_role_id, supervisor_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (full_name, email, password, system_role, job_role_id, supervisor_id))

        db.commit()
        flash("User created successfully.", "success")

    except IntegrityError as e:
        db.rollback()
        if "users.email" in str(e):
            flash("A user with this email already exists.", "error")
        else:
            flash("Database error occurred.", "error")

    finally:
        cursor.close()

    return redirect(url_for("admin_users"))

@app.route("/admin/supervisor/<int:supervisor_id>")
def admin_view_supervisor_team(supervisor_id):
    if session.get("system_role") != "admin":
        return redirect(url_for("shop"))

    cursor = db.cursor(dictionary=True)

    # Get supervisor info
    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE id = %s AND system_role = 'supervisor'
    """, (supervisor_id,))
    supervisor = cursor.fetchone()

    if not supervisor:
        flash("Supervisor not found.", "error")
        return redirect(url_for("admin_users"))

    # Get workers assigned to supervisor
    cursor.execute("""
        SELECT u.full_name,
               u.email,
               jr.name AS job_role
        FROM users u
        LEFT JOIN job_roles jr ON u.job_role_id = jr.id
        WHERE u.supervisor_id = %s
    """, (supervisor_id,))
    workers = cursor.fetchall()

    return render_template(
        "admin_supervisor_team.html",
        supervisor=supervisor,
        workers=workers
    )

if __name__ == "__main__":
    app.run()