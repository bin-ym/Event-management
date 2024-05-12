<?php
session_start();

// Include the database connection file
require_once "db_connection.php";

// Define variables and initialize with empty values
$username_email = $password = "";
$username_email_err = $password_err = "";

// Process login form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate username or email
    if (empty(trim($_POST["username_email"]))) {
        $username_email_err = "Please enter username or email.";
    } else {
        $username_email = trim($_POST["username_email"]);
    }

    // Validate password
    if (empty(trim($_POST["password"]))) {
        $password_err = "Please enter your password.";
    } else {
        $password = trim($_POST["password"]);
    }

    // Check if there are no errors before querying the database
    if (empty($username_email_err) && empty($password_err)) {
        // Prepare a SELECT statement to retrieve user information
        $sql = "SELECT user_id, username, email, password, role FROM users WHERE username = ? OR email = ?";
        if ($stmt = $conn->prepare($sql)) {
            // Bind variables to the prepared statement as parameters
            $stmt->bind_param("ss", $param_username_email, $param_username_email);
            // Set parameters
            $param_username_email = $username_email;
            // Attempt to execute the prepared statement
            if ($stmt->execute()) {
                // Store result
                $stmt->store_result();
                // Check if username or email exists, if yes then verify password
                if ($stmt->num_rows == 1) {
                    // Bind result variables
                    $stmt->bind_result($user_id, $username, $email, $hashed_password, $role);
                    if ($stmt->fetch()) {
                        if (password_verify($password, $hashed_password)) {
                            // Password is correct, so start a new session
                            session_start();
                            // Store data in session variables
                            $_SESSION["user_id"] = $user_id;
                            $_SESSION["username"] = $username;
                            $_SESSION["email"] = $email;
                            $_SESSION["role"] = $role;
                            // Redirect user based on role
                            if ($role == "admin") {
                                header("Location: ./Admin/admin.php");
                            } elseif ($role == "manager") {
                                header("Location: ./Manager/manager.php");
                            } elseif ($role == "user") {
                                header("Location: ./User/user.php");
                            }
                        } else {
                            // Display an error message if password is not valid
                            $password_err = "The password you entered is not valid.";
                        }
                    }
                } else {
                    // Display an error message if username or email doesn't exist
                    $username_email_err = "No account found with that username or email.";
                }
            } else {
                echo "Oops! Something went wrong. Please try again later.";
            }
            // Close statement
            $stmt->close();
        }
    }
    // Close connection
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <!-- Bootstrap CSS -->
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Add your custom CSS styles here */
    </style>
</head>
<body>
    <div class="container">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username or Email</label>
                <input type="text" name="username_email" class="form-control <?php echo (!empty($username_email_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username_email; ?>">
                <span class="invalid-feedback"><?php echo $username_email_err; ?></span>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>
