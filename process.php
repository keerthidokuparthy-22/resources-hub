<?php
session_start();
require "db.php";

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // LOGIN
    if (isset($_POST['action']) && $_POST['action'] == "login") {
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        if (empty($username) || empty($password)) {
            $_SESSION['message'] = "⚠ Please fill in all fields.";
            header("Location: index.php");
            exit();
        }

        // Check user
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $_SESSION['message'] = "✅ Login successful!";
        } else {
            $_SESSION['message'] = "❌ Incorrect username or password.";
        }
        header("Location: index.php");
        exit();
    }

    // REGISTER
    if (isset($_POST['action']) && $_POST['action'] == "register") {
        $username = trim($_POST['username']);
        $email = trim($_POST['email']);
        $password = trim($_POST['password']);

        if (empty($username) || empty($email) || empty($password)) {
            $_SESSION['message'] = "⚠ All fields are required.";
            header("Location: index.php");
            exit();
        }

        // Check if user exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=? OR email=?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $_SESSION['message'] = "⚠ Username or email already exists.";
            header("Location: index.php");
            exit();
        }

        // Insert new user
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $password);
        if ($stmt->execute()) {
            $_SESSION['message'] = "✅ Registration successful. Please login!";
        } else {
            $_SESSION['message'] = "❌ Registration failed.";
        }
        header("Location: index.php");
        exit();
    }
}
?>
