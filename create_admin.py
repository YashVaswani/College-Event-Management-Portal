# create_admin.py

from app import app, db, User
from werkzeug.security import generate_password_hash

# --- SET YOUR ADMIN CREDENTIALS HERE ---
ADMIN_USERNAME = "Yash"
ADMIN_PASSWORD = "Admin@21"
# -------------------------------------

def create_first_admin():
    """Creates the first admin user in the database."""
    with app.app_context():
        # Check if an admin already exists
        if User.query.filter_by(is_admin=True).first():
            print(f"An admin user already exists. Aborting.")
            return

        # Check if the username is taken
        if User.query.filter_by(username=ADMIN_USERNAME).first():
            print(f"Username '{ADMIN_USERNAME}' is already taken. Please choose another one.")
            return

        # Create and save the new admin user
        hashed_password = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256')
        new_admin = User(username=ADMIN_USERNAME, password=hashed_password, is_admin=True)
        
        db.session.add(new_admin)
        db.session.commit()
        
        print(f"✅ Admin user '{ADMIN_USERNAME}' created successfully!")
        print("You can now run your main app and log in.")

# This makes the script runnable
if __name__ == "__main__":
    create_first_admin()