<?php
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/conexion.php';
require_once __DIR__ . '/config/functions.php';

$errors = [];
$success = false;

if (metodo_post_seguro()) {
    honeypot_check();

    if (!isset($_POST['csrf_token']) || !validar_csrf($_POST['csrf_token'])) {
        $errors[] = "Token CSRF inválido.";
    }

    $email = limpiar($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $errors[] = "Todos los campos son obligatorios.";
    } elseif (!email_valido($email)) {
        $errors[] = "Correo no válido.";
    }

    if (empty($errors)) {
        $stmt = $pdo->prepare("SELECT id, username, password, nivel, xp FROM usuarios WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !verificarPassword($password, $user['password'])) {
            $errors[] = "Credenciales incorrectas.";
            log_attack("Login fallido: $email");
        } else {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['nivel'] = $user['nivel'];
            $_SESSION['xp'] = $user['xp'];
            $success = true;
        }
    }
}

$csrf = csrf_token();
?>

<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login | INSANE CODE</title>
  <link href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css" rel="stylesheet" />
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js"></script>
  <style>
    html, body {
      margin: 0; padding: 0; height: 100%;
      font-family: 'JetBrains Mono', monospace;
      background: #0f0f0f;
      overflow: hidden;
      color: #ff4444;
    }
    #tsparticles {
      position: absolute;
      width: 100%;
      height: 100%;
      z-index: 0;
    }
    form {
      position: relative;
      z-index: 1;
      background: rgba(255, 0, 0, 0.05);
      border: 1px solid rgba(255, 0, 0, 0.2);
      backdrop-filter: blur(15px);
      padding: 2.5rem 3rem;
      width: 400px;
      margin: auto;
      margin-top: 5vh;
      border-radius: 20px;
      box-shadow: 0 0 20px #ff000044, inset 0 0 20px #ff000022;
      color: #ff4444;
    }
    h2 {
      text-align: center;
      margin-bottom: 1.5rem;
      text-shadow: 0 0 10px #ff444499;
    }
    label {
      display: block;
      margin-bottom: 0.3rem;
      font-weight: 600;
    }
    input[type="email"],
    input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 1.2rem;
      border-radius: 10px;
      border: none;
      background: rgba(255, 0, 0, 0.1);
      color: #ff4444;
      font-size: 1rem;
      box-shadow: inset 0 0 5px #ff444466;
    }
    input[type="submit"] {
      width: 100%;
      padding: 12px;
      background-color: #ff4444;
      color: #111;
      font-weight: bold;
      border: none;
      border-radius: 12px;
      cursor: pointer;
      font-size: 1.1rem;
      transition: background 0.3s ease;
      box-shadow: 0 0 10px #ff4444aa;
    }
    input[type="submit"]:hover {
      background-color: #cc0000;
    }
    .links {
      margin-top: 1rem;
      display: flex;
      justify-content: space-between;
    }
    .links a {
      color: #ff4444cc;
      font-size: 0.9rem;
      text-decoration: none;
    }
    .links a:hover {
      text-decoration: underline;
    }
    .hp { display: none !important; }
  </style>
</head>
<body>

<div id="tsparticles"></div>

<form method="POST" autocomplete="off" novalidate>
  <h2>Ingreso INSANE CODE</h2>

  <label for="email">Correo Electrónico</label>
  <input type="email" id="email" name="email" required value="<?= e($_POST['email'] ?? '') ?>">

  <label for="password">Contraseña</label>
  <input type="password" id="password" name="password" required>

  <input type="text" name="hp_email" class="hp" tabindex="-1" autocomplete="off">

  <input type="hidden" name="csrf_token" value="<?= $csrf ?>">

  <input type="submit" value="Iniciar Sesión">

  <div class="links">
    <a href="register.php">¿No tienes cuenta? Regístrate</a>
    <a href="index.php">Inicio</a>
  </div>
</form>

<script>
tsParticles.load("tsparticles", {
  fpsLimit: 60,
  background: {
    color: "#0f0f0f"
  },
  particles: {
    number: { value: 100 },
    color: { value: "#ff4444" },
    shape: { type: "circle" },
    opacity: { value: 0.5 },
    size: { value: 3 },
    links: {
      enable: true,
      distance: 120,
      color: "#ff4444",
      opacity: 0.4,
      width: 1
    },
    move: {
      enable: true,
      speed: 1.5,
      direction: "none",
      outModes: { default: "bounce" }
    }
  },
  interactivity: {
    events: {
      onHover: { enable: true, mode: "repulse" },
      onClick: { enable: true, mode: "push" }
    },
    modes: {
      repulse: { distance: 100 },
      push: { quantity: 4 }
    }
  },
  detectRetina: true
});
</script>

<script>
document.addEventListener('DOMContentLoaded', () => {
    <?php if ($success): ?>
    Swal.fire({
        icon: 'success',
        title: '¡Bienvenido, <?= e($_SESSION['username']) ?>!',
        text: 'Acceso autorizado. Redirigiendo...',
        confirmButtonColor: '#ff4444'
    }).then(() => {
        window.location.href = 'retos.php';
    });
    <?php elseif (!empty($errors)): ?>
    Swal.fire({
        icon: 'error',
        title: 'Oops...',
        html: '<?= implode("<br>", array_map("e", $errors)) ?>',
        confirmButtonColor: '#ff4444'
    });
    <?php endif; ?>
});
</script>

</body>
</html>
