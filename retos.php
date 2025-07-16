<?php
session_start();
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/conexion.php';
require_once __DIR__ . '/config/functions.php';

requiereLogin();
$user_id = $_SESSION['user_id'];
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reto_id'], $_POST['respuesta_usuario']) && isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    $reto_id = (int) $_POST['reto_id'];
    $respuesta_usuario = trim($_POST['respuesta_usuario']);

    $stmt = $pdo->prepare("SELECT respuesta_correcta, puntos_max FROM retos WHERE id = :id");
    $stmt->execute(['id' => $reto_id]);
    $reto = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($reto) {
        $es_correcta = strcasecmp($respuesta_usuario, trim($reto['respuesta_correcta'])) === 0;
        $puntaje = $es_correcta ? (int)$reto['puntos_max'] : 0;

        $stmt = $pdo->prepare("REPLACE INTO resultados (user_id, reto_id, respuesta_usuario, puntaje, fecha_resuelto) VALUES (:user_id, :reto_id, :respuesta_usuario, :puntaje, NOW())");
        $stmt->execute([
            'user_id' => $user_id,
            'reto_id' => $reto_id,
            'respuesta_usuario' => $respuesta_usuario,
            'puntaje' => $puntaje
        ]);

        echo json_encode(['success' => true, 'respuesta_guardada' => true]);
        exit;
    }
    echo json_encode(['success' => false]);
    exit;
}

// Obtener retos
$stmt = $pdo->prepare("SELECT r.*, res.respuesta_usuario, res.puntaje FROM retos r LEFT JOIN resultados res ON res.reto_id = r.id AND res.user_id = :user_id ORDER BY FIELD(r.nivel, 'Fácil','Medio','Difícil'), r.id");
$stmt->execute(['user_id' => $user_id]);
$retos = $stmt->fetchAll(PDO::FETCH_ASSOC);

$todos_contestados = count(array_filter($retos, fn($r) => $r['respuesta_usuario'] !== null));
$puntaje_total = 0;
if ($todos_contestados === count($retos)) {
    $stmt = $pdo->prepare("SELECT SUM(puntaje) FROM resultados WHERE user_id = :user_id");
    $stmt->execute(['user_id' => $user_id]);
    $puntaje_total = $stmt->fetchColumn() ?: 0;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Retos | INSANE CODE</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body {
      margin: 0;
      background-color: black;
      color: #00ff00;
      font-family: 'JetBrains Mono', monospace;
    }
    #matrix-canvas {
      position: fixed;
      top: 0; left: 0;
      width: 100vw; height: 100vh;
      z-index: -1;
      background: black;
    }
    nav {
      background: #001100;
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 0 10px #00ff00;
      z-index: 10;
      position: relative;
    }
    nav a {
      color: #00ff00;
      margin-left: 1rem;
      text-decoration: none;
      font-weight: bold;
    }
    nav a:hover {
      color: #88ff88;
    }
    main {
      max-width: 900px;
      margin: 2rem auto;
      background: rgba(0, 255, 0, 0.08);
      padding: 2rem;
      border-radius: 12px;
      box-shadow: 0 0 20px #00ff00;
    }
    .reto {
      background: rgba(0,255,0,0.05);
      border: 1px solid #00ff00;
      padding: 1.5rem;
      border-radius: 10px;
      margin-bottom: 2rem;
    }
    .titulo { font-size: 1.4rem; font-weight: bold; }
    .descripcion { margin: 0.5rem 0; color: #b5ffb5; }
    .nivel { font-size: 0.9rem; color: #66ff66; }
    textarea {
      width: 100%; margin-top: 1rem;
      padding: 10px; font-size: 1rem;
      background: #001f00; color: #00ff00;
      border: 1px solid #00ff00; border-radius: 8px;
    }
    button {
      margin-top: 1rem; padding: 8px 20px;
      background: transparent; color: #00ff00;
      border: 2px solid #00ff00; border-radius: 25px;
      font-weight: bold; cursor: pointer;
    }
    button:hover {
      background: #00ff00; color: black;
    }
    .respuesta-guardada {
      margin-top: 1rem;
      font-weight: bold;
      color: #55ff55;
    }
    .puntaje-final {
      background: #001100;
      padding: 1rem;
      text-align: center;
      font-size: 1.3rem;
      border: 1px solid #00ff00;
      border-radius: 10px;
      box-shadow: 0 0 10px #00ff00aa;
      margin-top: 3rem;
    }
  </style>
</head>
<body>
<canvas id="matrix-canvas"></canvas>
<nav>
  <div><i class="fas fa-code"></i> INSANE CODE</div>
  <div>
    <a href="perfil.php"><i class="fas fa-user"></i> Perfil</a>
    <a href="ranking.php"><i class="fas fa-trophy"></i> Ranking</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Cerrar sesión</a>
  </div>
</nav>

<main>
  <h1>Retos de Programación</h1>
  <?php foreach ($retos as $reto): ?>
    <div class="reto" id="reto-<?= $reto['id'] ?>">
      <div class="titulo"><?= htmlspecialchars($reto['titulo']) ?></div>
      <div class="descripcion"><?= htmlspecialchars($reto['descripcion']) ?></div>
      <div class="nivel">Nivel: <?= htmlspecialchars($reto['nivel']) ?> | Máx: <?= $reto['puntos_max'] ?> pts</div>

      <div id="respuesta-estado-<?= $reto['id'] ?>">
        <?php if ($reto['respuesta_usuario']): ?>
          <div class="respuesta-guardada" id="mensaje-<?= $reto['id'] ?>">
            <i class="fas fa-check-circle"></i> Respuesta guardada
          </div>
          <button onclick="mostrarFormulario(<?= $reto['id'] ?>)">Intentar de nuevo</button>
        <?php endif; ?>
      </div>

      <form id="form-<?= $reto['id'] ?>" onsubmit="return enviarRespuesta(event, <?= $reto['id'] ?>)" style="<?= $reto['respuesta_usuario'] ? 'display:none;' : '' ?>">
        <input type="hidden" name="reto_id" value="<?= $reto['id'] ?>">
        <textarea name="respuesta_usuario" required></textarea>
        <button type="submit">Enviar</button>
      </form>
    </div>
  <?php endforeach; ?>

  <?php if ($todos_contestados === count($retos)): ?>
    <div class="puntaje-final">
      🌟 Has completado todos los retos.<br>
      <strong>Puntaje total: <?= $puntaje_total ?> puntos</strong>
    </div>
  <?php endif; ?>
</main>
<footer style="text-align:center; padding:1rem; color:#008800aa;">
  INSANE CODE &copy; 2025
</footer>
<script>
function enviarRespuesta(event, id) {
  event.preventDefault();
  const form = document.getElementById('form-' + id);
  const formData = new FormData(form);

  fetch('retos.php', {
    method: 'POST',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: formData
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      form.style.display = 'none';
      const estado = document.getElementById('respuesta-estado-' + id);
      estado.innerHTML = `<div class='respuesta-guardada'><i class='fas fa-check-circle'></i> Respuesta guardada</div><button onclick='mostrarFormulario(${id})'>Intentar de nuevo</button>`;
    }
  });
  return false;
}

function mostrarFormulario(id) {
  document.getElementById('form-' + id).style.display = 'block';
  document.getElementById('respuesta-estado-' + id).innerHTML = '';
}

// Matrix Animation
const canvas = document.getElementById('matrix-canvas');
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
const letters = '01'.split('');
const fontSize = 16;
const columns = canvas.width / fontSize;
const drops = Array.from({ length: columns }).map(() => 1);
function drawMatrix() {
  ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#0F0';
  ctx.font = fontSize + 'px JetBrains Mono';
  drops.forEach((y, i) => {
    const text = letters[Math.floor(Math.random() * letters.length)];
    ctx.fillText(text, i * fontSize, y * fontSize);
    drops[i] = y * fontSize > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
  });
}
setInterval(drawMatrix, 50);
</script>
</body>
</html>