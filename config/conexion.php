<?php
// config/conexion.php

// Bloquear acceso directo
if (basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    http_response_code(403);
    exit("Access Forbidden");
}

// Ruta correcta al archivo .env dentro de esta carpeta
$envPath = __DIR__ . '/.env';

// Verificar existencia del archivo .env
if (!file_exists($envPath)) {
    error_log("Error: Archivo de configuración .env no encontrado en $envPath");
    http_response_code(500);
    exit('Error interno: configuración no encontrada.');
}

// Cargar variables de entorno (formato INI simple)
$env = parse_ini_file($envPath, false, INI_SCANNER_TYPED);

if (!$env || !isset($env['DB_HOST'], $env['DB_NAME'], $env['DB_USER'], $env['DB_PASS'])) {
    error_log("Error: Archivo .env incompleto o malformado");
    http_response_code(500);
    exit('Error interno: configuración inválida.');
}

// Variables de conexión con valores por defecto en caso de faltar
$host = $env['DB_HOST'] ?? 'localhost';
$db   = $env['DB_NAME'] ?? '';
$user = $env['DB_USER'] ?? '';
$pass = $env['DB_PASS'] ?? '';
$charset = 'utf8mb4';

// Opciones PDO recomendadas
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // Lanza excepciones en errores
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       // Fetch asociativo por defecto
    PDO::ATTR_EMULATE_PREPARES   => false,                  // Preparación nativa de sentencias
    PDO::ATTR_PERSISTENT         => true,                   // Conexión persistente (usar con cuidado)
];

try {
    $dsn = "mysql:host=$host;dbname=$db;charset=$charset";
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    error_log("Error conexión DB: " . $e->getMessage());
    http_response_code(500);
    exit('Error interno: no se pudo conectar a la base de datos.');
}
