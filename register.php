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

    $username = limpiar($_POST['username'] ?? '');
    $email = limpiar($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $password2 = $_POST['password2'] ?? '';

    if (empty($username) || empty($email) || empty($password) || empty($password2)) {
        $errors[] = "Todos los campos son obligatorios.";
    } elseif (!username_valido($username)) {
        $errors[] = "Usuario inválido.";
    } elseif (!email_valido($email)) {
        $errors[] = "Correo no válido.";
    } elseif ($password !== $password2) {
        $errors[] = "Las contraseñas no coinciden.";
    }

    if (empty($errors)) {
        $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $errors[] = "El correo ya está registrado.";
        } else {
            $hash = hashPassword($password);
            $insert = $pdo->prepare("INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)");
            $insert->execute([$username, $email, $hash]);
            $success = true;
        }
    }
}

$csrf = csrf_token();
?>

<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Registro | INSANE CODE</title>
  <link href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js"></script>
  <style>
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      font-family: 'JetBrains Mono', monospace;
      background: #0f0f0f;
      overflow: hidden;
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
      background: rgba(0, 255, 255, 0.05);
      border: 1px solid rgba(0, 255, 255, 0.2);
      backdrop-filter: blur(15px);
      padding: 2.5rem 3rem;
      width: 400px;
      margin: auto;
      margin-top: 5vh;
      border-radius: 20px;
      box-shadow: 0 0 20px #00ffff44, inset 0 0 20px #00ffff22;
      color: #00ffff;
    }

    h2 {
      text-align: center;
      margin-bottom: 1.5rem;
      text-shadow: 0 0 10px #00ffff99;
    }

    label {
      display: block;
      margin-bottom: 0.3rem;
      font-weight: 600;
    }

    input[type="text"],
    input[type="email"],
    input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 1.2rem;
      border-radius: 10px;
      border: none;
      background: rgba(0,255,255,0.1);
      color: #00ffff;
      font-size: 1rem;
      box-shadow: inset 0 0 5px #00ffff66;
    }

    input[type="submit"] {
      width: 100%;
      padding: 12px;
      background-color: #00ffff;
      color: #111;
      font-weight: bold;
      border: none;
      border-radius: 12px;
      cursor: pointer;
      font-size: 1.1rem;
      transition: background 0.3s ease;
      box-shadow: 0 0 10px #00ffffaa;
    }

    input[type="submit"]:hover {
      background-color: #00cccc;
    }

    .links {
      margin-top: 1rem;
      display: flex;
      justify-content: space-between;
    }

    .links a {
      color: #00ffffcc;
      font-size: 0.9rem;
      text-decoration: none;
    }

    .hp { display: none !important; }
  </style>
</head>
<body>

<div id="tsparticles"></div>

<form method="POST" autocomplete="off" novalidate>
  <h2>Registro INSANE CODE</h2>

  <label for="username">Usuario</label>
  <input type="text" id="username" name="username" required value="<?= e($_POST['username'] ?? '') ?>">

  <label for="email">Correo Electrónico</label>
  <input type="email" id="email" name="email" required value="<?= e($_POST['email'] ?? '') ?>">

  <label for="password">Contraseña</label>
  <input type="password" id="password" name="password" required>

  <label for="password2">Confirmar Contraseña</label>
  <input type="password" id="password2" name="password2" required>

  <input type="email" name="hp_email" class="hp" tabindex="-1" autocomplete="off">

  <input type="hidden" name="csrf_token" value="<?= $csrf ?>">

  <input type="submit" value="Registrarse">

  <div class="links">
    <a href="login.php">¿Ya tienes cuenta?</a>
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
    color: { value: "#00ffff" },
    shape: { type: "circle" },
    opacity: { value: 0.5 },
    size: { value: 3 },
    links: {
      enable: true,
      distance: 120,
      color: "#00ffff",
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
        title: '¡Registro Exitoso!',
        text: 'Ya puedes iniciar sesión.',
        confirmButtonColor: '#00ffff'
    }).then(() => {
        window.location.href = 'login.php';
    });
    <?php elseif (!empty($errors)): ?>
    Swal.fire({
        icon: 'error',
        title: 'Oops...',
        html: '<?= implode("<br>", array_map("e", $errors)) ?>',
        confirmButtonColor: '#00ffff'
    });
    <?php endif; ?>
});
</script>

</body>
</html>
