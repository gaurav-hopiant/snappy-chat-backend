# Quick-meeting-sticky - Backend API

This is the backend API for the Quick-meeting-sticky application, built with Node.js and Express. It manages user authentication, sticky note data, and real-time task sharing functionalities.

-----

## ⚙️ Prerequisites

You'll need the following installed on your machine:

  * **Node.js**: [Download & Install Node.js](https://nodejs.org/)
  * **Git**: [Download & Install Git](https://git-scm.com/downloads)
  * **MySQL**: [suspicious link removed] or use a service like XAMPP or Docker.

-----

## 💻 Local Setup Steps

Follow these steps to get a local copy of the project up and running.

### 1\. Clone the repository

```sh
git clone git@github.com:gaurav-hopiant/snappy-chat-backend.git
cd your-repo-directory
```

### 2\. Install dependencies

```sh
npm install
```

### 3\. Database setup

Connect to your MySQL database and run the following SQL commands to create the required tables:

```sql
CREATE TABLE users (
    id INT(11) NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    reset_token VARCHAR(255) DEFAULT NULL,
    reset_token_expires TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE user_data (
    user_id INT(11) NOT NULL,
    tasks_json LONGTEXT COLLATE utf8mb4_bin NOT NULL DEFAULT '[]',
    tags_json LONGTEXT COLLATE utf8mb4_bin NOT NULL DEFAULT '[]',
    operators_json LONGTEXT COLLATE utf8mb4_bin NOT NULL DEFAULT '[]',
    show_tags_on_notes TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    shared_tasks_json LONGTEXT COLLATE utf8mb4_bin NOT NULL DEFAULT '[]',
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE shared_tasks (
    id INT(11) NOT NULL AUTO_INCREMENT,
    task_id BIGINT(20) NOT NULL,
    owner_user_id INT(11) NOT NULL,
    shared_with_user_id INT(11) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY unique_share (task_id, owner_user_id, shared_with_user_id),
    KEY idx_owner_user_id (owner_user_id),
    KEY idx_shared_with_user_id (shared_with_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

### 4\. Create `.env` file

Create a file named `.env` in the `server` directory and add the following content, replacing the placeholder values with your own:

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_database_password
DB_NAME=sticky_notes_db

JWT_SECRET=your_jwt_secret_key
PORT=3000
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
APP_URL=http://localhost:5173
```

-----

### 5\. Run the application

To start the server, run the following command from the root directory:

```sh
node index.js
```

The server will now be running at **`http://localhost:3000`**.

-----

## ☁️ Deployment to Render

Follow these steps to deploy your application to Render.

### 1\. Create a Git repository

If you haven't already, push your code to a new Git repository on GitHub, GitLab, or Bitbucket.

### 2\. Connect Render to your Git repository

1.  Log in to your [Render dashboard](https://dashboard.render.com/).
2.  Click **"New"** and select **"Web Service"**.
3.  Connect your Git provider and select the repository for this project.

### 3\. Configure your service

On the configuration page, set the following values:

  * **Name:** `quick-meeting-sticky` (or any name you prefer)
  * **Environment:** `Node`
  * **Build Command:** `npm install`
  * **Start Command:** `node index.js`
  * **Plan:** Select the **Free** plan.

### 4\. Add Environment Variables

Go to **"Advanced"** and click **"Add Environment Variable"** to add all the key-value pairs from your local `.env` file. Do **not** commit your `.env` file to Git.

| Key | Value |
| --- | --- |
| `DB_HOST` | `your_database_host` |
| `DB_USER` | `your_database_user` |
| `DB_PASSWORD` | `your_database_password` |
| `DB_NAME` | `your_database_name` |
| `JWT_SECRET` | `your_jwt_secret_key` |
| `PORT` | `3000` |
| `EMAIL_USER` | `your_email@gmail.com` |
| `EMAIL_PASS` | `your_app_password` |
| `APP_URL` | `https://your-frontend-app.com` (your deployed frontend URL) |

### 5\. Deploy

Click **"Create Web Service"**. Render will automatically pull your code, install dependencies, and deploy your application. The deployment will be live at the URL provided by Render.
