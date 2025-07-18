<?php
session_start();
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/conexion.php';
require_once __DIR__ . '/config/functions.php';

requiereLogin();

$user_id = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT username, email FROM usuarios WHERE id = :id");
$stmt->execute(['id' => $user_id]);
$usuario = $stmt->fetch(PDO::FETCH_ASSOC);

$puntosStmt = $pdo->prepare("SELECT COALESCE(SUM(puntaje),0) AS total_puntos FROM resultados WHERE user_id = :user_id");
$puntosStmt->execute(['user_id' => $user_id]);
$puntos = $puntosStmt->fetchColumn();

$retosCompletadosStmt = $pdo->prepare("SELECT COUNT(*) FROM resultados WHERE user_id = :user_id AND puntaje > 0");
$retosCompletadosStmt->execute(['user_id' => $user_id]);
$retosCompletados = $retosCompletadosStmt->fetchColumn();

$nivel = floor($puntos / 100);
$siguienteNivelPuntos = ($nivel + 1) * 100;
$progreso = ($puntos % 100);
$progresoPorcentaje = ($progreso / 100) * 100;
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Perfil | INSANE CODE</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free/css/all.min.css" />
  <script src="https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.6.0/dist/confetti.browser.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body {
      margin: 0;
      font-family: 'JetBrains Mono', monospace;
      background-color: #050505;
      color: #00ffcc;
      overflow-x: hidden;
    }
    nav {
      position: fixed;
      top: 0; left: 0; right: 0;
      background: rgba(0, 255, 255, 0.08);
      padding: 1rem;
      display: flex;
      justify-content: center;
      gap: 40px;
      z-index: 1000;
      border-bottom: 1px solid #00fff055;
    }
    nav a {
      color: #00ffee;
      text-decoration: none;
      font-weight: bold;
      transition: 0.3s;
    }
    nav a:hover {
      color: #00ffcc;
      text-shadow: 0 0 10px #00ffee;
    }
    main {
      max-width: 850px;
      margin: 7rem auto;
      background: rgba(0, 255, 255, 0.07);
      padding: 2rem;
      border-radius: 20px;
      box-shadow: 0 0 20px #00fff0a4, inset 0 0 30px #00ffee50;
      position: relative;
      z-index: 10;
    }
    h1 {
      font-size: 3rem;
      text-align: center;
      margin-bottom: 2rem;
      text-shadow: 0 0 15px #00ffee;
    }
    .barra-progreso {
      background: #002222;
      border-radius: 25px;
      overflow: hidden;
      height: 26px;
      margin-bottom: 1.5rem;
    }
    .progreso {
      height: 100%;
      background: linear-gradient(90deg, #00ffee, #00ff88);
      width: 0;
      transition: width 1.5s ease;
    }
    .reto {
      background: #003333;
      color: #00ffee;
      padding: 1rem;
      border-radius: 12px;
      margin: 5px;
      width: 50px;
      text-align: center;
      transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .reto:hover {
      transform: scale(1.15);
      box-shadow: 0 0 20px #00ffee;
    }
    .reto.completado {
      background: linear-gradient(to right, #00ffcc, #00ff88);
      color: #001f1f;
      font-weight: bold;
    }
    footer {
      text-align: center;
      margin: 3rem auto 1rem;
      color: #00ffee88;
    }
    #tsparticles {
      position: fixed;
      top: 0; left: 0;
      width: 100vw;
      height: 100vh;
      z-index: 0;
    }
  </style>
</head>
<body>

<nav>
  <div><i class="fas fa-code"></i> INSANE CODE</div>
  <div>
    <a href="retos.php"><i class="fas fa-terminal"></i> Retos</a>
    <a href="ranking.php"><i class="fas fa-trophy"></i> Ranking</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Cerrar sesión</a>
  </div>
</nav>

<div id="tsparticles"></div>

<main>
  <h1>Bienvenido <?= htmlspecialchars($usuario['username']) ?> 🚀</h1>
  <p><strong>Email:</strong> <?= htmlspecialchars($usuario['email']) ?></p>
  <p><strong>Puntos totales:</strong> <span id="puntos-total"><?= $puntos ?></span></p>
  <p><strong>Nivel:</strong> <?= $nivel ?> | <span>XP: <?= $progreso ?>/100</span></p>

  <div class="barra-progreso">
    <div class="progreso" id="barra-progreso"></div>
  </div>

  <p>Retos completados: <?= $retosCompletados ?> de 31</p>
  <div style="display: flex; flex-wrap: wrap; justify-content: center;">
    <?php
    for ($i = 1; $i <= 31; $i++) {
      $stmt = $pdo->prepare("SELECT COUNT(*) FROM resultados WHERE user_id = :uid AND reto_id = :rid AND puntaje > 0");
      $stmt->execute(['uid' => $user_id, 'rid' => $i]);
      $completado = $stmt->fetchColumn() > 0;
      echo '<div class="reto ' . ($completado ? 'completado' : '') . '">' . $i . '</div>';
    }
    ?>
  </div>
</main>

<footer>INSANE CODE &copy; 2025 — ¡Sigue rompiendo el código! 🧠</footer>

<script>
  document.addEventListener('DOMContentLoaded', () => {
    const barra = document.getElementById('barra-progreso');
    const progreso = <?= json_encode($progresoPorcentaje) ?>;
    barra.style.width = progreso + '%';

    if (progreso === 0 && <?= $puntos ?> > 0) {
      confetti({ particleCount: 100, spread: 80, origin: { y: 0.6 } });
    }
  });

  tsParticles.load("tsparticles", {
    fullScreen: { enable: true },
    particles: {
      number: { value: 60 },
      color: { value: "#00ffee" },
      shape: { type: "circle" },
      opacity: { value: 0.5 },
      size: { value: { min: 1, max: 5 } },
      move: {
        enable: true,
        speed: 1,
        direction: "top",
        outModes: "out"
      }
    },
    interactivity: {
      events: {
        onHover: { enable: true, mode: "repulse" }
      },
      modes: {
        repulse: { distance: 100 }
      }
    },
    background: {
      color: "#050505"
    }
  });
</script>

</body>
</html>
