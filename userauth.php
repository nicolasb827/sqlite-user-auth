<?php
	require 'vendor/autoload.php'; // I am using Flight Framework .. adapt as needed
	
	session_start();

	// Choose a unique salt. The longer and more complex it is, the better.
	// Since the database is being stored in an unencrypted file, we need
	// strong protection on the passwords.
	private $salt = "ThisIsADummySalt";
	private $dbfile = null;
	private $pdo = null;
	private $db = null;
	private $dbpersistent = false;
	public function __construct() {
		$this->dbfile = Flight::get ( 'pdo.local.path' );
		$this->pdo = Flight::get ( 'pdo.local.scheme' ) . Flight::get ( 'pdo.local.path' );
	}
	public function dbinit() {
		if ($this->db == null) {
			try {
				$this->db = new PDO ( $this->pdo, '', '', array (
						PDO::ATTR_PERSISTENT => $this->dbpersistent
				) );
			} catch ( PDOException $e ) {
				die ( $e->getMessage () );
			}
		}
	}
	public function dbclose() {
		if ($this->db != null) {
			$this->db = null;
		}
	}
	public function createTables() {
		$ret = true;
		try {
			$stmt = $this->db->query ( "SELECT * FROM users LIMIT 1" );
			if ($stmt === false)
				$ret = false;
		} catch ( PDOException $e ) {
			$ret = false;
		}
		if ($ret)
			return;
		$q = "CREATE TABLE users
							(	uid INTEGER PRIMARY KEY,
								username varchar(255),
								password varchar(32),
								lastlogin int
							);";
		try {
			$stmt = $this->db->prepare ( $q );
			$stmt->execute ();
		} catch ( PDOException $e ) {
			die ( "Failed to create the database table: " . $e->getMessage () );
		}
		$this->newUser ( "admin", "adminDefaultPassword" );
	}
	public function login($user, $password, $stayloggedin = false) {
		$stmt = $this->db->prepare ( "SELECT * FROM users WHERE username = :user AND password = :password LIMIT 1" );
		$password = md5 ( $this->salt . $password );
		$stmt->bindValue ( ':user', $user, PDO::PARAM_STR );
		$stmt->bindValue ( ':password', $password, PDO::PARAM_STR );
		$cnt = 0;
		$r = array ();
		if ($stmt->execute ()) {
			$r = $stmt->fetchAll ();
			$cnt = count ( $r );
			// $row = $stmt->fetch();
		} else {
			$error = $stmt->errorInfo ();
			return false;
		}

		if ($cnt > 0) {
			if ($stayloggedin) {
				setcookie ( "userid", $r ['uid'], time () + 60 * 60 * 24 * 30 );
				setcookie ( "pass", $password, time () + 60 * 60 * 24 * 30 );
			}
			$_SESSION ['uid'] = $r [0] ['uid'];
			$_SESSION ['uname'] = $r [0] ['username'];
			$time = time ();
			$id = $r [0] ['uid'];
			$stmt = $this->db->prepare ( "UPDATE users SET lastlogin = :time WHERE uid = :id" );
			$stmt->bindValue ( ':time', $time, PDO::PARAM_INT );
			$stmt->bindValue ( ':id', $id, PDO::PARAM_INT );
			try {
				$stmt->execute ();
				return true;
			} catch ( PDOException $e ) {
				return false;
			}
		}
		return false;
	}

	// Returns false if username is taken
	public function newUser($username, $password) {
		$user = $username;
		$pass = md5 ( $this->salt . $password );
		$time = time ();
		$stmt = $this->db->prepare ( "SELECT uid FROM users WHERE username = :username" );
		$stmt->bindValue ( ':username', $user, PDO::PARAM_STR );
		if ($stmt->execute ()) {
			$res = $stmt->fetchAll ();
			$cnt = count ( $res );
			// $row = $stmt->fetch();
		} else {
			$error = $stmt->errorInfo ();
			return false;
		}
		if ($res > 0)
			return false;

		$stmt = $this->db->prepare ( "INSERT INTO users ('username', 'password', 'lastlogin') VALUES (:username, :pass, :time)" );
		$stmt->bindValue ( ':time', $time, PDO::PARAM_INT );
		$stmt->bindValue ( ':username', $user, PDO::PARAM_STR );
		$stmt->bindValue ( ':pass', $pass, PDO::PARAM_STR );
		try {
			$stmt->execute ();
		} catch ( PDOException $e ) {
			return false;
		}
		return true;
	}
	public function updatePassword($username, $cpass, $newpass) {
		if (! $this->login ( $username, $cpass ))
			return false;
		$id = $_SESSION ['uid'];
		$stmt = $this->db->prepare ( "UPDATE users SET password = :newpass WHERE uid = :id AND password = :cpass" );
		$stmt->bindParam ( ':cpass', $cpass, PDO::PARAM_STR );
		$stmt->bindParam ( ':id', $id, PDO::PARAM_INT );
		$stmt->bindParam ( ':newpass', $newpass, PDO::PARAM_STR );
		try {
			$stmt->execute ();
		} catch ( PDOException $e ) {
			return false;
		}
		return true;
	}
	public function cookielogin() {
		if (isset ( $_COOKIE ['userid'] ) && isset ( $_COOKIE ['pass'] )) {
			$id = $_COOKIE ['userid'];
			$pass = $_COOKIE ['pass'];

			$stmt = $this->db->prepare ( "SELECT * FROM users WHERE uid = :id AND password = :pass LIMIT 1" );
			$stmt->bindParam ( ':id', $id, PDO::PARAM_INT );
			$stmt->bindParam ( ':pass', $pass, PDO::PARAM_STR );
			try {
				$stmt->execute ();
			} catch ( PDOException $e ) {
				return false;
			}

			$r = $stmt->fetchAll ();
			$cnt = count ( $r );
			if ($r > 0) {
				$_SESSION ['uid'] = $r [0] ['uid'];
				$_SESSION ['uname'] = $r [0] ['username'];
			}
		}
	}
	public function isloggedin() {
		return isset ( $_SESSION ['uid'] );
	}
	public function logout() {
		unset ( $_SESSION ['uid'] );
		session_destroy ();
		setcookie ( "userid", "", time () - 60 * 60 * 24 * 30 );
		setcookie ( "pass", "", time () - 60 * 60 * 24 * 30 );
	}
	public function uname() {
		if ($this->isloggedin ())
			return $_SESSION ['uname'];
		else
			return "NO LOGIN.";
	}
}
$user = new userauth ();
$user->dbinit ();
$user->createTables ();
	
?>
