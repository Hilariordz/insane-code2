<?php
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/conexion.php';
require_once __DIR__ . '/config/functions.php';

session_start();
$_SESSION = [];
session_unset();
session_destroy();

// Limpiar cookie de sesión (opcional y recomendado)
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Redirigir a index con mensaje
header('Location: index.php?logout=1');
exit;
