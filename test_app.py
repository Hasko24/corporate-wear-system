"""
DHL Corporate Wear — Automated smoke tests
Run with: python test_app.py
Requires the Flask app running locally on http://localhost:5000
"""
import requests
import sys

BASE = "http://localhost:5000"
PASS = "✓"
FAIL = "✗"

results = []

def test(label, ok, detail=""):
    status = PASS if ok else FAIL
    results.append((ok, label, detail))
    print(f"  {status}  {label}" + (f"  ({detail})" if detail else ""))

def login(email, password):
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"email": email, "password": password}, allow_redirects=True)
    return s, r

def check(s, url, expect=200, contains=None, label=None):
    r = s.get(f"{BASE}{url}", allow_redirects=True)
    ok = r.status_code == expect
    if contains and ok:
        ok = contains.lower() in r.text.lower()
    test(label or url, ok, f"status={r.status_code}" if r.status_code != expect else "")
    return r

# ─────────────────────────────────────────────
print("\n── LOGIN PAGE ──")
# ─────────────────────────────────────────────
r = requests.get(f"{BASE}/login")
test("Login page loads", r.status_code == 200)
test("Login page has form", "email" in r.text.lower())

# ─────────────────────────────────────────────
print("\n── ADMIN FLOWS ──")
# ─────────────────────────────────────────────
s_admin, r = login("admin@test.com", "test123")  # ← update credentials
test("Admin login", "/admin" in r.url or "admin" in r.text.lower(), r.url)

admin_pages = [
    ("/admin",               "Admin Panel"),
    ("/admin/products",      "Products"),
    ("/admin/users",         "Users"),
    ("/admin/news",          "News"),
    ("/admin/size-guides",   "Size"),
    ("/admin/analytics",     "Analytics"),
    ("/admin/stock-risk",    "Stock"),
    ("/admin/reorder-engine","Reorder"),
    ("/admin/sites",         "Sites"),
    ("/admin/facilities",    "Facilities"),
    ("/admin/job-roles",     "Job Roles"),
    ("/admin/stats",         "Statistics"),
    ("/orders",              "Orders"),
    ("/shop",                "Shop"),
    ("/news",                "News"),
    ("/size-guide",          "Size"),
    ("/stock",               "Stock"),
]
for url, contains in admin_pages:
    check(s_admin, url, contains=contains, label=f"Admin: {url}")

# ─────────────────────────────────────────────
print("\n── SUPERVISOR FLOWS ──")
# ─────────────────────────────────────────────
s_sup, r = login("John@test.com", "test123")  # ← update credentials
test("Supervisor login", "news" in r.url or "shop" in r.url or "dashboard" in r.url, r.url)

sup_pages = [
    ("/shop",                 "Shop"),
    ("/news",                 "News"),
    ("/dashboard",            "Dashboard"),
    ("/orders",               "Orders"),
    ("/team",                 "Team"),
    ("/cart",                 "Cart"),
    ("/size-guide",           "Size"),
    ("/bulk-order",           "Bulk"),
    ("/supervisor/delegation","Delegation"),
    ("/my-uniforms",          "Uniform"),
]
for url, contains in sup_pages:
    check(s_sup, url, contains=contains, label=f"Supervisor: {url}")

# Check shop with a team member (first team member)
r = s_sup.get(f"{BASE}/team")
import re
member_ids = re.findall(r'/worker/(\d+)/history', r.text)
if member_ids:
    mid = member_ids[0]
    check(s_sup, f"/shop?team_member_id={mid}", contains="shop", label=f"Supervisor: shop with member {mid}")
    check(s_sup, f"/worker/{mid}/history", contains="Uniform", label=f"Supervisor: worker history {mid}")

# ─────────────────────────────────────────────
print("\n── PACKER FLOWS ──")
# ─────────────────────────────────────────────
s_packer, r = login("packer@test.com", "test123")  # ← update credentials
test("Packer login", "orders" in r.url or "packer" in r.text.lower(), r.url)

packer_pages = [
    ("/orders",               "Orders"),
    ("/orders/export/excel",  None),   # just check 200
    ("/orders/export/pdf",    None),
]
for url, contains in packer_pages:
    check(s_packer, url, contains=contains, label=f"Packer: {url}")

# ─────────────────────────────────────────────
print("\n── ACCESS CONTROL ──")
# ─────────────────────────────────────────────
# Supervisor should NOT reach admin pages
r = s_sup.get(f"{BASE}/admin", allow_redirects=True)
test("Supervisor blocked from /admin", "/admin" not in r.url or "login" in r.url or r.status_code in (302,403))

# Admin should not be able to add to cart
r = s_admin.post(f"{BASE}/add-to-cart", data={"product_size_id": "1", "team_member_id": "1"}, allow_redirects=True)
test("Admin blocked from add-to-cart", "admins cannot" in r.text.lower() or r.url != f"{BASE}/add-to-cart")

# Unauthenticated access should redirect to login
s_anon = requests.Session()
r = s_anon.get(f"{BASE}/shop", allow_redirects=True)
test("Unauthenticated redirected to login", "login" in r.url)
r = s_anon.get(f"{BASE}/admin", allow_redirects=True)
test("Unauthenticated /admin redirected", "login" in r.url)

# ─────────────────────────────────────────────
print("\n── KEY FORMS ──")
# ─────────────────────────────────────────────
# Check news page loads with like/comment elements
r = s_sup.get(f"{BASE}/news")
test("News: like button present", "like-btn" in r.text)
test("News: comment form present", "comment-form" in r.text)

# Check order detail page (first order)
r = s_sup.get(f"{BASE}/orders")
order_ids = re.findall(r'order/(\d+)', r.text)
if order_ids:
    oid = order_ids[0]
    r2 = s_sup.get(f"{BASE}/order/{oid}")
    test(f"Order detail #{oid} loads", r2.status_code == 200)
    test(f"Order detail has employee column", "employee" in r2.text.lower())

# ─────────────────────────────────────────────
print("\n── SUMMARY ──")
# ─────────────────────────────────────────────
passed = sum(1 for ok, _, _ in results if ok)
failed = sum(1 for ok, _, _ in results if not ok)
total = len(results)
print(f"\n  {passed}/{total} passed", end="")
if failed:
    print(f"  — {failed} FAILED:")
    for ok, label, detail in results:
        if not ok:
            print(f"    {FAIL}  {label}" + (f" ({detail})" if detail else ""))
else:
    print("  — all good 🟢")

sys.exit(0 if failed == 0 else 1)
