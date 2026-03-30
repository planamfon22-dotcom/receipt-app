import csv
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, date
from functools import wraps
from pathlib import Path
from random import SystemRandom

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
    Response,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"
UPLOAD_DIR = BASE_DIR / "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf"}
MAX_CONTENT_LENGTH = 8 * 1024 * 1024
RNG = SystemRandom()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret-before-production")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv(
    "ADMIN_PASSWORD_HASH",
    generate_password_hash(os.getenv("ADMIN_PASSWORD", "admin1234")),
)

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ---------- Database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    with closing(db.cursor()) as cur:
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                email TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                receipt_code TEXT NOT NULL UNIQUE,
                purchase_date TEXT NOT NULL,
                amount_submitted REAL NOT NULL,
                amount_approved REAL,
                store_name TEXT,
                note TEXT,
                file_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                admin_note TEXT,
                submitted_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by TEXT,
                FOREIGN KEY(customer_id) REFERENCES customers(id)
            );
            """
        )
        db.commit()
    db.close()


# ---------- Utility ----------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


def get_or_create_customer(full_name: str, phone: str, email: str | None):
    db = get_db()
    row = db.execute("SELECT * FROM customers WHERE phone = ?", (phone,)).fetchone()
    if row:
        db.execute(
            "UPDATE customers SET full_name = ?, email = COALESCE(?, email) WHERE id = ?",
            (full_name, email or None, row["id"]),
        )
        db.commit()
        return row["id"]

    cur = db.execute(
        "INSERT INTO customers (full_name, phone, email, created_at) VALUES (?, ?, ?, ?)",
        (full_name, phone, email or None, datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()
    return cur.lastrowid


def month_bounds(month_str: str):
    start = datetime.strptime(month_str, "%Y-%m").date().replace(day=1)
    if start.month == 12:
        end = date(start.year + 1, 1, 1)
    else:
        end = date(start.year, start.month + 1, 1)
    return start.isoformat(), end.isoformat()


def tier_from_total(total: float):
    if total > 5000 and total <= 10000:
        return "กลุ่ม 10,000 บาท"
    if total > 1000 and total <= 5000:
        return "กลุ่ม 5,000 บาท"
    if total <= 1000:
        return "กลุ่มไม่เกิน 1,000 บาท"
    if total > 10000:
        return "มากกว่า 10,000 บาท (นอกเงื่อนไขปัจจุบัน)"
    return "-"


def monthly_totals(month_str: str):
    start, end = month_bounds(month_str)
    db = get_db()
    rows = db.execute(
        """
        SELECT
            c.id as customer_id,
            c.full_name,
            c.phone,
            c.email,
            COUNT(r.id) as receipt_count,
            ROUND(COALESCE(SUM(r.amount_approved), 0), 2) as total_amount
        FROM customers c
        LEFT JOIN receipts r
            ON r.customer_id = c.id
            AND r.status = 'approved'
            AND r.purchase_date >= ?
            AND r.purchase_date < ?
        GROUP BY c.id, c.full_name, c.phone, c.email
        HAVING COUNT(r.id) > 0
        ORDER BY total_amount DESC, c.full_name ASC
        """,
        (start, end),
    ).fetchall()

    result = []
    for row in rows:
        total = float(row["total_amount"] or 0)
        result.append(
            {
                "customer_id": row["customer_id"],
                "full_name": row["full_name"],
                "phone": row["phone"],
                "email": row["email"],
                "receipt_count": row["receipt_count"],
                "total_amount": total,
                "tier": tier_from_total(total),
            }
        )
    return result


def eligible_customers(month_str: str, tier_name: str):
    return [r for r in monthly_totals(month_str) if r["tier"] == tier_name]


def generate_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def verify_csrf():
    session_token = session.get("csrf_token")
    form_token = request.form.get("csrf_token")
    if not session_token or not form_token or session_token != form_token:
        abort(400, description="CSRF token ไม่ถูกต้อง")


@app.context_processor

def inject_helpers():
    return {
        "csrf_token": generate_csrf_token,
        "today_month": date.today().strftime("%Y-%m"),
        "tier_from_total": tier_from_total,
    }


# ---------- Public routes ----------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/submit", methods=["GET", "POST"])
def submit_receipt():
    if request.method == "POST":
        verify_csrf()
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        purchase_date = request.form.get("purchase_date", "").strip()
        amount = request.form.get("amount", "").strip()
        store_name = request.form.get("store_name", "").strip()
        note = request.form.get("note", "").strip()
        file = request.files.get("receipt_file")

        errors = []
        if not full_name:
            errors.append("กรุณากรอกชื่อผู้ซื้อ")
        if not phone:
            errors.append("กรุณากรอกเบอร์โทร")
        if not purchase_date:
            errors.append("กรุณาเลือกวันที่ซื้อ")
        if not amount:
            errors.append("กรุณากรอกยอดซื้อ")
        if file is None or file.filename == "":
            errors.append("กรุณาอัปโหลดรูปหรือไฟล์ใบเสร็จ")
        elif not allowed_file(file.filename):
            errors.append("รองรับเฉพาะไฟล์ PNG, JPG, JPEG, WEBP หรือ PDF")

        try:
            amount_value = float(amount)
            if amount_value <= 0:
                errors.append("ยอดซื้อต้องมากกว่า 0")
        except ValueError:
            errors.append("ยอดซื้อไม่ถูกต้อง")
            amount_value = 0

        try:
            datetime.strptime(purchase_date, "%Y-%m-%d")
        except ValueError:
            errors.append("วันที่ซื้อไม่ถูกต้อง")

        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("submit.html")

        customer_id = get_or_create_customer(full_name, phone, email)
        ext = secure_filename(file.filename).rsplit(".", 1)[1].lower()
        receipt_code = f"MG{datetime.now().strftime('%Y%m%d%H%M%S')}{secrets.randbelow(900)+100}"
        stored_name = f"{receipt_code}.{ext}"
        file.save(UPLOAD_DIR / stored_name)

        db = get_db()
        db.execute(
            """
            INSERT INTO receipts (
                customer_id, receipt_code, purchase_date, amount_submitted, store_name, note,
                file_name, submitted_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                customer_id,
                receipt_code,
                purchase_date,
                amount_value,
                store_name or None,
                note or None,
                stored_name,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        db.commit()

        return render_template("submit_success.html", receipt_code=receipt_code)

    return render_template("submit.html")


# ---------- Admin routes ----------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["admin_logged_in"] = True
            next_url = request.args.get("next") or url_for("admin_dashboard")
            flash("เข้าสู่ระบบสำเร็จ", "success")
            return redirect(next_url)
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout")
@login_required
def admin_logout():
    session.clear()
    flash("ออกจากระบบแล้ว", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@login_required
def admin_dashboard():
    db = get_db()
    stats = {
        "pending": db.execute("SELECT COUNT(*) FROM receipts WHERE status='pending'").fetchone()[0],
        "approved": db.execute("SELECT COUNT(*) FROM receipts WHERE status='approved'").fetchone()[0],
        "rejected": db.execute("SELECT COUNT(*) FROM receipts WHERE status='rejected'").fetchone()[0],
        "customers": db.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
    }
    recent = db.execute(
        """
        SELECT r.*, c.full_name, c.phone
        FROM receipts r
        JOIN customers c ON c.id = r.customer_id
        ORDER BY r.submitted_at DESC
        LIMIT 8
        """
    ).fetchall()
    return render_template("admin_dashboard.html", stats=stats, recent=recent)


@app.route("/admin/reviews")
@login_required
def admin_reviews():
    status = request.args.get("status", "pending")
    db = get_db()
    rows = db.execute(
        """
        SELECT r.*, c.full_name, c.phone, c.email
        FROM receipts r
        JOIN customers c ON c.id = r.customer_id
        WHERE r.status = ?
        ORDER BY
            CASE WHEN r.status='pending' THEN r.submitted_at END ASC,
            r.submitted_at DESC
        """,
        (status,),
    ).fetchall()
    return render_template("admin_reviews.html", rows=rows, status=status)


@app.route("/admin/review/<int:receipt_id>", methods=["GET", "POST"])
@login_required
def admin_review_detail(receipt_id: int):
    db = get_db()
    row = db.execute(
        """
        SELECT r.*, c.full_name, c.phone, c.email
        FROM receipts r
        JOIN customers c ON c.id = r.customer_id
        WHERE r.id = ?
        """,
        (receipt_id,),
    ).fetchone()
    if not row:
        abort(404)

    if request.method == "POST":
        verify_csrf()
        action = request.form.get("action")
        admin_note = request.form.get("admin_note", "").strip()
        approved_amount = request.form.get("amount_approved", "").strip()
        reviewed_at = datetime.now().isoformat(timespec="seconds")

        if action == "approve":
            try:
                approved_value = float(approved_amount)
                if approved_value <= 0:
                    raise ValueError
            except ValueError:
                flash("ยอดอนุมัติไม่ถูกต้อง", "error")
                return render_template("admin_review_detail.html", row=row)

            db.execute(
                """
                UPDATE receipts
                SET status='approved', amount_approved=?, admin_note=?, reviewed_at=?, reviewed_by=?
                WHERE id=?
                """,
                (approved_value, admin_note or None, reviewed_at, ADMIN_USERNAME, receipt_id),
            )
            db.commit()
            flash("อนุมัติรายการแล้ว", "success")
            return redirect(url_for("admin_reviews", status="pending"))

        if action == "reject":
            db.execute(
                """
                UPDATE receipts
                SET status='rejected', amount_approved=NULL, admin_note=?, reviewed_at=?, reviewed_by=?
                WHERE id=?
                """,
                (admin_note or None, reviewed_at, ADMIN_USERNAME, receipt_id),
            )
            db.commit()
            flash("ปฏิเสธรายการแล้ว", "success")
            return redirect(url_for("admin_reviews", status="pending"))

    return render_template("admin_review_detail.html", row=row)


@app.route("/admin/monthly-summary")
@login_required
def admin_monthly_summary():
    month = request.args.get("month") or date.today().strftime("%Y-%m")
    rows = monthly_totals(month)
    return render_template("admin_monthly_summary.html", rows=rows, month=month)


@app.route("/admin/export-monthly.csv")
@login_required
def export_monthly_csv():
    month = request.args.get("month") or date.today().strftime("%Y-%m")
    rows = monthly_totals(month)

    def generate():
        output = []
        header = ["month", "customer_name", "phone", "email", "receipt_count", "total_amount", "tier"]
        output.append(header)
        for row in rows:
            output.append([
                month,
                row["full_name"],
                row["phone"],
                row["email"] or "",
                row["receipt_count"],
                f"{row['total_amount']:.2f}",
                row["tier"],
            ])
        sio = []
        for record in output:
            sio.append(",".join('"{}"'.format(str(x).replace('"', '""')) for x in record) + "\n")
        return "".join(sio)

    filename = f"monthly_summary_{month}.csv"
    return Response(
        generate(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/admin/draw", methods=["GET", "POST"])
@login_required
def admin_draw():
    month = request.values.get("month") or date.today().strftime("%Y-%m")
    tier_name = request.values.get("tier_name") or "กลุ่ม 5,000 บาท"
    winner_count_raw = request.values.get("winner_count") or "1"
    winners = []
    pool = eligible_customers(month, tier_name)

    if request.method == "POST":
        verify_csrf()
        try:
            winner_count = max(1, int(winner_count_raw))
        except ValueError:
            winner_count = 1
        if pool:
            winners = RNG.sample(pool, k=min(winner_count, len(pool)))
        else:
            flash("ยังไม่มีผู้มีสิทธิ์ในกลุ่มที่เลือก", "error")

    return render_template(
        "admin_draw.html",
        month=month,
        tier_name=tier_name,
        pool=pool,
        winners=winners,
        winner_count=winner_count_raw,
        tiers=["กลุ่มไม่เกิน 1,000 บาท", "กลุ่ม 5,000 บาท", "กลุ่ม 10,000 บาท"],
    )


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.errorhandler(413)
def too_large(_e):
    flash("ไฟล์มีขนาดใหญ่เกินกำหนด (สูงสุด 8 MB)", "error")
    return redirect(request.referrer or url_for("submit_receipt"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
