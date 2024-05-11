<?php
	require_once 'db_connect.php';
	session_start();

	// Sanitize and escape user input
	$username = mysqli_real_escape_string($conn, $_POST['username']);
	$password = mysqli_real_escape_string($conn, $_POST['password']);

	// Use prepared statement to prevent SQL injection
	$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
	$stmt->bind_param("ss", $username, $password);
	$stmt->execute();
	$result = $stmt->get_result();

	if ($result->num_rows > 0) {
		$login = $result->fetch_array();

		foreach ($login as $k => $v) {
			if (!is_numeric($k) && $k != 'password') {
				$_SESSION['login_'.$k] = $v;
			}
		}

		echo json_encode(array('status' => true));
	} else {
		echo json_encode(array('status' => false, 'message' => 'Incorrect username or password. Please try again.'));
	}

	$stmt->close();
	$conn->close();
?>