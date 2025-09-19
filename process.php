<?php
session_start();
require 'config.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['login'])) {
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        // Fetch user by username
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['message'] = "Login successful!";
            $_SESSION['message_type'] = "success";
            $_SESSION['username'] = $user['username'];
        } else {
            $_SESSION['message'] = "Invalid username or password.";
            $_SESSION['message_type'] = "error";
        }
        header("Location: login.php");
        exit();
    }

    if (isset($_POST['signup'])) {
        $username = trim($_POST['username']);
        $email = trim($_POST['email']);
        $password = trim($_POST['password']);

        // Validate fields
        if (empty($username) || empty($email) || empty($password)) {
            $_SESSION['message'] = "All fields are required.";
            $_SESSION['message_type'] = "error";
            header("Location: login.php");
            exit();
        }

        // Check if username or email already exists
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        if ($stmt->fetch()) {
            $_SESSION['message'] = "Username or Email already exists.";
            $_SESSION['message_type'] = "error";
        } else {
            // Hash password and insert new user
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $hashedPassword);

            if ($stmt->execute()) {
                $_SESSION['message'] = "Signup successful! Please log in.";
                $_SESSION['message_type'] = "success";
            } else {
                $_SESSION['message'] = "Something went wrong during signup.";
                $_SESSION['message_type'] = "error";
            }
        }

        header("Location: login.php");
        exit();
    }
}
?>

