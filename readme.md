# College Event Management Portal

A comprehensive web application built with Flask for managing college events, announcements, and student interactions. This portal allows students to view and register for events, while a secure admin panel provides full control over the content.

---
## Features

This application includes a wide range of features for both students and administrators:

### Student Features
* **User Registration & Login:** Secure student account creation with password hashing.
* **Event Dashboard:** View a list of all upcoming events with details like date, time, location, and category.
* **Search & Filter:** Easily find events by searching for keywords or filtering by category.
* **Event Registration:** Logged-in students can register and unregister for events with a single click.
* **My Events Page:** A dedicated page for students to see all the events they are registered for.
* **View Announcements:** See the latest important notices from the administration on the homepage.
* **Contact Form:** A public query form for anyone to ask questions.
* **Feedback System:** Logged-in students can submit ratings and comments to provide feedback.

### Admin Features
* **Secure Admin Role:** Admin access is protected and tied to specific user accounts in the database.
* **Event Management (CRUD):** Admins can **C**reate, **R**ead, **U**pdate (Edit), and **D**elete events.
* **Notice Management (CRUD):** Admins can **C**reate, **R**ead, **U**pdate (Edit), and **D**elete announcements.
* **View Student Queries:** All submissions from the contact form are displayed in the admin panel.
* **View Feedback:** All feedback submitted by students is visible to the admin.
* **View Event Attendees:** Admins can see a list of all students registered for any specific event.

---
## How to Set Up and Run the Project

Follow these steps to get the application running on your local machine.

### 1. Prerequisites
* Python 3.x installed.
* `pip` for installing packages.

### 2. Installation
1.  **Clone/Download the project** into a new folder.
2.  **Open a terminal** (like PowerShell) in the project folder.
3.  **Install the required packages:**
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Werkzeug
    ```

### 3. Database and Admin Setup
The first time you run the app, you need to create the database and the first admin account.

1.  **Build the Database Tables:** Run the main application once to create the `events.db` file with all the necessary tables.
    ```bash
    python app.py
    ```
    Once the server starts, stop it immediately by pressing `Ctrl+C`.

2.  **Create the First Admin User:** This project uses a script to create the first admin.
    * Create a new file in your project folder named `create_admin.py`.
    * Paste the following code into it, changing the `ADMIN_USERNAME` and `ADMIN_PASSWORD` to your desired credentials.
        ```python
        # create_admin.py
        from app import app, db, User
        from werkzeug.security import generate_password_hash

        ADMIN_USERNAME = "YourAdminUsername"
        ADMIN_PASSWORD = "YourSecurePassword"

        def create_first_admin():
            with app.app_context():
                if User.query.filter_by(is_admin=True).first():
                    print("An admin user already exists.")
                    return
                hashed_password = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256')
                new_admin = User(username=ADMIN_USERNAME, password=hashed_password, is_admin=True)
                db.session.add(new_admin)
                db.session.commit()
                print(f"✅ Admin user '{ADMIN_USERNAME}' created successfully!")

        if __name__ == "__main__":
            create_first_admin()
        ```
    * Run the script from your terminal:
        ```bash
        python create_admin.py
        ```
    You should see a success message.

### 4. Run the Application
You are now ready to run the main application.
```bash
python app.py