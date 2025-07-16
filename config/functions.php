<?php
// config/functions.php

// ─── PROTECCIÓN DE ACCESO DIRECTO ───────────────────────
if (basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    http_response_code(403);
    exit("Access Denied");
}

// ─── SANITIZAR Y ESCAPAR DATOS ──────────────────────────
function limpiar($dato) {
    return htmlspecialchars(trim($dato), ENT_QUOTES, 'UTF-8');
}

function e($string) {
    return htmlentities($string, ENT_QUOTES, 'UTF-8');
}

// ─── VALIDACIONES ───────────────────────────────────────
function email_valido($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function username_valido($username) {
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username);
}

// ─── CONTRASEÑAS ────────────────────────────────────────
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verificarPassword($password, $hash) {
    return password_verify($password, $hash);
}

// ─── GESTIÓN DE SESIÓN ──────────────────────────────────
function cerrar_sesion() {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit();
}

function regenerar_sesion() {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

// ─── CONTROL DE ACCESO ──────────────────────────────────
function usuario_autenticado() {
    return isset($_SESSION['user_id']);
}

function requiereLogin() {
    if (!usuario_autenticado()) {
        session_destroy();
        header('Location: login.php');
        exit();
    }
}

// ─── REDIRECCIÓN SEGURA ─────────────────────────────────
function redirigir($ruta = 'login.php') {
    header("Location: $ruta");
    exit();
}

// ─── TOKEN ALEATORIO ────────────────────────────────────
function generar_token($long = 32) {
    return bin2hex(random_bytes($long));
}

// ─── LOGGER GENERAL ─────────────────────────────────────
function logger($msg) {
    $logfile = __DIR__ . '/../logs/general.log';
    $date = date('Y-m-d H:i:s');
    file_put_contents($logfile, "[$date] $msg\n", FILE_APPEND | LOCK_EX);
}
?>
