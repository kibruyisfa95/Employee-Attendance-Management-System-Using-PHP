<!DOCTYPE html>
<?php
	session_start();
	if(isset($_SESSION['login_id'])){
		header('location: home.php');
	}
?>
<html lang="eng">
<head>
	<title>Employee Attendance Management System</title>
	<?php include 'header.php'; ?>
</head>
<body>
	<div id="main" class="bg-info">
		<div class="container">
			<div class="col-lg-12">
				<div class="row">
					<div class="col-md-6 offset-md-3">
						<div class="card login-field">
							<div class="card-header">
								<h4>Login</h4>
							</div>
							<div class="card-body">
								<form id="login-frm">
									<div class="form-group">
										<label class="control-label">Username:</label>
										<input type="text" name="username" class="form-control" required/>
									</div>
									<div class="form-group">
										<label class="control-label">Password:</label>
										<input type="password" maxlength="20" name="password" class="form-control" required/>
									</div>
									<br/>
									<button type="submit" class="btn btn-primary btn-block">Login <i class="fa fa-arrow-right"></i></button>
								</form>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>

	<script src="../assets/js/jquery.js"></script>
	<script src="../assets/js/bootstrap.js"></script>

	<script>
		$(document).ready(function(){
			$('#login-frm').submit(function(e){
				e.preventDefault();
				$.ajax({
					url: 'login.php',
					method: 'POST',
					data: $(this).serialize(),
					error: function(err){
						console.log(err);
					},
					success: function(resp){
						var response = JSON.parse(resp);
						if(response.status === true){
							location.href = 'home.php';
						} else {
							alert(response.message);
						}
					}
				});
			});
		});
	</script>
</body>
</html>