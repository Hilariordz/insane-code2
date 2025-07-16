<?php
// config/seguridad.php

if (basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    http_response_code(403);
    exit("Access Forbidden");
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ─── BLOQUEO DE IP ──────────────────────────────────────
function ip_bloqueada($ip) {
    $archivo = __DIR__ . '/../logs/ips_bloqueadas.txt';
    if (!file_exists($archivo)) return false;
    $bloqueadas = file($archivo, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return in_array($ip, $bloqueadas);
}

function bloquear_ip($ip) {
    $archivo = __DIR__ . '/../logs/ips_bloqueadas.txt';
    if (!is_dir(dirname($archivo))) {
        mkdir(dirname($archivo), 0755, true);
    }
    file_put_contents($archivo, $ip . "\n", FILE_APPEND | LOCK_EX);
}

// ─── HEADERS DE SEGURIDAD ───────────────────────────────
// CSP corregido en una sola línea para evitar errores de sintaxis
$csp = "default-src 'self'; "
     . "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; "
     . "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
     . "img-src 'self' https://images.unsplash.com https://randomuser.me https://avatars.githubusercontent.com data:; "
     . "font-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com data:; "
     . "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';";

function aplicar_headers() {
    global $csp;
    header("X-Frame-Options: SAMEORIGIN");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: no-referrer");
    header("Permissions-Policy: geolocation=(), microphone=()");
    header("X-XSS-Protection: 1; mode=block");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
    header("Content-Security-Policy: $csp");
}
aplicar_headers();

// ─── CSRF ───────────────────────────────────────────────
function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validar_csrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ─── HONEYPOT ────────────────────────────────────────────
function honeypot_check() {
    if (isset($_POST['hp_email']) && !empty(trim($_POST['hp_email']))) {
        log_attack('Honeypot activado');
        bloquear_ip($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        session_destroy();
        header('Location: login.php');
        exit();
    }
}

// ─── DETECCIÓN Y BLOQUEO DE AGENTES ─────────────────────
function bloquear_agentes_sospechosos() {
    $sospechosos = ['sqlmap','curl','httpie','fuzz','nmap','dirbuster','nikto','postman','acunetix','wget'];
    $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');

    if (!$ua) {
        log_attack("User-Agent ausente");
        bloquear_ip($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        session_destroy();
        header('Location: login.php');
        exit();
    }

    foreach ($sospechosos as $bad) {
        if (strpos($ua, $bad) !== false) {
            log_attack("User-Agent sospechoso detectado: $ua");
            bloquear_ip($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            session_destroy();
            header('Location: login.php');
            exit();
        }
    }
}
bloquear_agentes_sospechosos();

// ─── RATE LIMITING ──────────────────────────────────────
function rate_limit() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = 'rate_' . md5($ip);
    $time = time();

    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 1, 'time' => $time];
    } else {
        $elapsed = $time - $_SESSION[$key]['time'];
        if ($elapsed < 60) {
            $_SESSION[$key]['count']++;
            if ($_SESSION[$key]['count'] > 20) {
                log_attack("Rate limiting activado para IP $ip");
                bloquear_ip($ip);
                session_destroy();
                header("Location: login.php");
                exit();
            }
        } else {
            $_SESSION[$key] = ['count' => 1, 'time' => $time];
        }
    }
}
rate_limit();

// ─── REGISTRO DE ATAQUES ────────────────────────────────
function log_attack($motivo = 'Desconocido') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'N/A';
    $hora = date('Y-m-d H:i:s');
    $linea = "[$hora] IP: $ip - UA: $ua - Motivo: $motivo\n";
    $logFile = __DIR__ . '/../logs/ataques.log';
    if (!is_dir(dirname($logFile))) {
        mkdir(dirname($logFile), 0755, true);
    }
    file_put_contents($logFile, $linea, FILE_APPEND | LOCK_EX);
}

// ─── BLOQUEAR SI LA IP YA ESTÁ EN LISTA NEGRA ───────────
$mi_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (ip_bloqueada($mi_ip)) {
    log_attack("Acceso bloqueado desde IP previamente marcada: $mi_ip");
    http_response_code(403);
    exit("Tu IP ha sido bloqueada por actividad sospechosa.");
}

// ─── EJECUTAR HONEYPOT ──────────────────────────────────
honeypot_check();

// ─── VERIFICAR MÉTODO POST ─────────────────────────────
function metodo_post_seguro() {
    return $_SERVER['REQUEST_METHOD'] === 'POST';
}
