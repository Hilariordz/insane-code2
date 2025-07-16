<?php
session_start();
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/functions.php';

requiereLogin();

$logFile = __DIR__ . '/logs/ataques.log';
$bloqueadasFile = __DIR__ . '/logs/ips_bloqueadas.txt';

if (isset($_POST['accion'])) {
    if ($_POST['accion'] === 'limpiar_logs') {
        file_put_contents($logFile, '');
        $msg = 'Logs limpiados';
    } elseif ($_POST['accion'] === 'desbloquear_ip' && isset($_POST['ip'])) {
        $ip = trim($_POST['ip']);
        $lineas = file($bloqueadasFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $nuevas = array_filter($lineas, fn($l) => trim($l) !== $ip);
        file_put_contents($bloqueadasFile, implode("\n", $nuevas) . "\n");
        $msg = "IP desbloqueada: $ip";
    }
}

$logs = file_exists($logFile) ? file($logFile, FILE_IGNORE_NEW_LINES) : [];
$ipsBloqueadas = file_exists($bloqueadasFile) ? file($bloqueadasFile, FILE_IGNORE_NEW_LINES) : [];
?><!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Firewall | INSANE CODE</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
  <style>
    body {
      background: black;
      color: #00ff00;
      font-family: 'JetBrains Mono', monospace;
      padding: 2rem;
    }
    h1 {
      font-size: 2.5rem;
      text-align: center;
      margin-bottom: 2rem;
      text-shadow: 0 0 10px #00ff00aa;
    }
    .section {
      margin-bottom: 2rem;
      padding: 1rem;
      border: 1px solid #00ff00;
      border-radius: 10px;
      background: rgba(0,255,0,0.05);
    }
    .logs, .ips {
      max-height: 300px;
      overflow-y: auto;
      white-space: pre-wrap;
      background: black;
      padding: 1rem;
      border: 1px solid #00ff00aa;
    }
    form.inline {
      display: inline-block;
    }
    input[type=text] {
      background: black;
      border: 1px solid #00ff00;
      color: #00ff00;
      padding: 6px;
    }
    button {
      background: black;
      color: #00ff00;
      border: 1px solid #00ff00;
      padding: 6px 12px;
      margin-left: 6px;
      cursor: pointer;
    }
    button:hover {
      background: #00ff00;
      color: black;
    }
  </style>
</head>
<body>
  <h1>🛡️ Firewall INSANE CODE</h1>

  <?php if (isset($msg)): ?>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
      Swal.fire({ icon: 'success', title: 'OK', text: <?= json_encode($msg) ?>, confirmButtonColor: '#00ff00' });
    </script>
  <?php endif; ?>

  <div class="section">
    <h2>📜 Logs de Ataques</h2>
    <div class="logs"><?php foreach ($logs as $line) echo htmlspecialchars($line) . "\n"; ?></div>
    <form method="POST">
      <input type="hidden" name="accion" value="limpiar_logs">
      <button>🧹 Limpiar Logs</button>
    </form>
  </div>

  <div class="section">
    <h2>🚫 IPs Bloqueadas</h2>
    <div class="ips"><?php foreach ($ipsBloqueadas as $ip) echo htmlspecialchars($ip) . "\n"; ?></div>
    <form method="POST" class="inline">
      <input type="text" name="ip" placeholder="IP a desbloquear" required>
      <input type="hidden" name="accion" value="desbloquear_ip">
      <button>🔓 Desbloquear IP</button>
    </form>
  </div>
</body>
</html>
