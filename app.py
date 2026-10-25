from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import os
from werkzeug.utils import secure_filename
from flask import current_app
from flask import send_from_directory, abort

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB total per request

# Required for login sessions #
app.secret_key = os.environ.get("SECRET_KEY")

DATABASE = "time_capsule.db"

# Temporary password reset codes for local development #
reset_codes = {}

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def home():
    return render_template("index.html")

# ----- REGISTER ----- #

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        connection = get_db_connection()

        try:
            connection.execute(
                """
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
                """,
                (username, email, hashed_password)
            )

            connection.commit()

        except sqlite3.IntegrityError:
            connection.close()
            return "This email is already registered!"

        connection.close()

        return redirect(url_for("login"))

    return render_template("register.html")

# ----- LOGIN ----- #

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        connection = get_db_connection()

         
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()


        connection.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["user_id"]
            session["username"] = user["username"]

            return redirect(url_for("home"))

        return "Invalid email or password!"

    return render_template("login.html")

# ----- FORGOT PASSWORD ----- #

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        connection = get_db_connection()
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        connection.close()
        
        if user:
            
            code = secrets.token_urlsafe(16)

            reset_codes[code] = {
                "user_id": user["user_id"],
                "created_at": __import__("time").time()
            }

        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")

# ----- RESET PASSWORD ----- #

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if request.method == "POST":

        code = request.form["code"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        reset_data = reset_codes.get(code)

        if not reset_data:
            return "Invalid or expired reset code!"

        # Expire reset codes after 15 minutes #
        import time

        if time.time() - reset_data["created_at"] > 900:
            reset_codes.pop(code, None)
            return "Reset code has expired. Please request a new one."

        # Check password confirmation #
        if password != confirm_password:
            return "Passwords do not match!"

        if len(password) < 8:
            return "Password must be at least 8 characters long!"

        # Update the password securely #
        from werkzeug.security import generate_password_hash

        connection = get_db_connection()
        connection.execute(
            "UPDATE users SET password = ? WHERE user_id = ?",
            (
                generate_password_hash(password),
                reset_data["user_id"]
            )
        )
        connection.commit()
        connection.close()

        # Prevent reuse of the reset code #
        reset_codes.pop(code, None)

        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ----- CREATE CAPSULE -----#

@app.route("/create-capsule", methods=["GET", "POST"])
def create_capsule():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        title = request.form["title"]
        description = request.form["description"]
        message = request.form["message"]
        unlock_date = request.form["unlock_date"]

        uploaded_files = request.files.getlist("capsule_files")

        allowed_extensions = {
            ".pdf", ".jpg", ".jpeg", ".png",
            ".gif", ".webp", ".mp4", ".webm", ".mov"
        }

        # Check file types before saving anything #
        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename:
                extension = os.path.splitext(
                    uploaded_file.filename
                )[1].lower()

                if extension not in allowed_extensions:
                    return "Unsupported file type!", 400

        connection = get_db_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO capsules
                (user_id, title, description, message, unlock_date)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session["user_id"],
                    title,
                    description,
                    message,
                    unlock_date
                )
            )

            capsule_id = cursor.lastrowid

            for uploaded_file in uploaded_files:
                if uploaded_file and uploaded_file.filename:

                    original_name = secure_filename(
                        uploaded_file.filename
                    )

                    if not original_name:
                        raise ValueError("Invalid filename")

                    # Give each stored file a unique name #
                    stored_name = f"{__import__('uuid').uuid4().hex}_{original_name}"

                    file_path = os.path.join(
                        app.config["UPLOAD_FOLDER"],
                        stored_name
                    )

                    uploaded_file.save(file_path)

                    extension = os.path.splitext(
                        original_name
                    )[1].lower()

                    if extension == ".pdf":
                        file_type = "pdf"
                    elif extension in {
                        ".jpg", ".jpeg", ".png", ".gif", ".webp"
                    }:
                        file_type = "image"
                    else:
                        file_type = "video"

                    connection.execute(
                        """
                        INSERT INTO files
                        (capsule_id, file_name, file_path, file_type)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            capsule_id,
                            original_name,
                            f"uploads/{stored_name}",
                            file_type
                        )
                    )

            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

        return redirect(url_for("my_capsules"))

    return render_template("create_capsule.html")

# ----- MY CAPSULES ----- #

@app.route("/my-capsules")
def my_capsules():

    if "user_id" not in session:
        return redirect(url_for("login"))

    from datetime import date

    connection = get_db_connection()

    capsules = connection.execute(
        """
        SELECT * FROM capsules
        WHERE user_id = ?
        ORDER BY unlock_date
        """,
        (session["user_id"],)
    ).fetchall()

    capsule_list = []

    for capsule in capsules:
        files = connection.execute(
            """
            SELECT file_id, file_name, file_path, file_type
            FROM files
            WHERE capsule_id = ?
            ORDER BY uploaded_at
            """,
            (capsule["capsule_id"],)
        ).fetchall()

        capsule_data = dict(capsule)
        capsule_data["files"] = files

        unlock_date = date.fromisoformat(
            str(capsule["unlock_date"])[:10]
        )

        capsule_data["is_locked"] = date.today() < unlock_date

        capsule_list.append(capsule_data)

    connection.close()

    return render_template(
        "my_capsules.html",
        capsules=capsule_list
    )

# ----- DELETE CAPSULE ----- #

@app.route("/delete-capsule/<int:capsule_id>", methods=["POST"])
def delete_capsule(capsule_id):

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    # Delete only a capsule belonging to the logged-in user #
    connection.execute(
        """
        DELETE FROM capsules
        WHERE capsule_id = ? AND user_id = ?
        """,
        (capsule_id, session["user_id"])
    )

    connection.commit()
    connection.close()

    return redirect(url_for("my_capsules"))

# ----- VIEW CAPSULE ----- #

@app.route("/capsule/<int:capsule_id>")
def view_capsule(capsule_id):

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    capsule = connection.execute(
        """
        SELECT * FROM capsules
        WHERE capsule_id = ? AND user_id = ?
        """,
        (capsule_id, session["user_id"])
    ).fetchone()

    if capsule is None:
        connection.close()
        return "Capsule not found!", 404

    # Capsule unlock #
    from datetime import date

    today = date.today()
    unlock_date = date.fromisoformat(str(capsule["unlock_date"])[:10])

    if today < unlock_date:
        connection.close()
        return render_template(
            "capsule_locked.html",
            capsule=capsule
        )

    files = connection.execute(
        """
        SELECT file_id, file_name, file_path, file_type
        FROM files
        WHERE capsule_id = ?
        ORDER BY uploaded_at
        """,
        (capsule["capsule_id"],)
    ).fetchall()

    connection.close()

    return render_template(
        "view_capsule.html",
        capsule=capsule,
        files=files
    )

# ----- SECURE CAPSULE ATTACHMENTS ----- #

@app.route("/capsule-file/<int:file_id>")
def capsule_file(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    from datetime import date

    connection = get_db_connection()

    file = connection.execute(
        """
        SELECT files.file_name, files.file_path,
               capsules.user_id, capsules.unlock_date
        FROM files
        JOIN capsules
          ON files.capsule_id = capsules.capsule_id
        WHERE files.file_id = ?
          AND capsules.user_id = ?
        """,
        (file_id, session["user_id"])
    ).fetchone()

    connection.close()

    if file is None:
        abort(404)

    unlock_date = date.fromisoformat(
        str(file["unlock_date"])[:10]
    )

    if date.today() < unlock_date:
        abort(403)

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        os.path.basename(file["file_path"]),
        as_attachment=False,
        download_name=file["file_name"]
    )

if __name__ == "__main__":
    app.run(debug=True)
