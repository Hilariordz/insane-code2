<?php
session_start();
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/conexion.php';
require_once __DIR__ . '/config/functions.php';

requiereLogin();

$stmt = $pdo->prepare("
  SELECT u.id, u.username, u.email, COALESCE(SUM(r.puntaje),0) AS total_puntos,
  FLOOR(COALESCE(SUM(r.puntaje),0) / 100) AS nivel
  FROM usuarios u
  LEFT JOIN resultados r ON u.id = r.user_id
  GROUP BY u.id
  ORDER BY total_puntos DESC, u.username ASC
  LIMIT 50
");
$stmt->execute();
$ranking = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="es" data-theme="dark">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Ranking | INSANE CODE</title>

<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet" />
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

<style>
  /* Reset y base */
  * {
    margin: 0; padding: 0; box-sizing: border-box;
  }
  html, body {
    font-family: 'JetBrains Mono', monospace;
    height: 100%;
    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
    color: #ffd700;
    overflow-x: hidden;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  nav {
    position: fixed;
    top: 0; left: 0; right: 0;
    background: rgba(255, 215, 0, 0.12);
    backdrop-filter: blur(15px);
    border-bottom: 1px solid #ffd70055;
    display: flex;
    justify-content: center;
    gap: 3rem;
    padding: 1.1rem 0;
    z-index: 20;
    font-weight: 700;
    font-size: 1.15rem;
    user-select: none;
  }
  nav a {
    color: #ffd700cc;
    text-decoration: none;
    padding: 0.45rem 1.5rem;
    border-radius: 16px;
    transition: all 0.3s ease;
    box-shadow: 0 0 8px #ffd70088;
  }
  nav a:hover, nav a:focus {
    background: #ffd700ee;
    color: #111;
    box-shadow: 0 0 18px #ffd700ee;
    outline: none;
  }
  nav a[aria-current="page"] {
    background: #ffd700dd;
    color: #111;
    box-shadow: 0 0 25px #ffd700ff;
    cursor: default;
  }

  #tsparticles {
    position: fixed;
    inset: 0;
    z-index: 0;
  }

  main {
    max-width: 960px;
    margin: 6.5rem auto 4rem;
    padding: 2.5rem 3rem;
    background: rgba(255, 215, 0, 0.07);
    border-radius: 28px;
    box-shadow:
      0 0 60px #ffd70044,
      inset 0 0 80px #ffd70033;
    backdrop-filter: blur(14px);
    position: relative;
    z-index: 10;
  }

  h1 {
    text-align: center;
    font-size: 3.2rem;
    color: #fff9d0;
    text-shadow:
      0 0 15px #ffd700cc,
      0 0 25px #ffdf00aa,
      0 0 40px #ffd700aa;
    margin-bottom: 2rem;
  }

  .buscador {
    max-width: 420px;
    margin: 0 auto 2rem;
    position: relative;
  }
  .buscador input {
    width: 100%;
    padding: 0.65rem 2.8rem 0.65rem 1.2rem;
    font-family: 'JetBrains Mono';
    font-size: 1.2rem;
    border-radius: 22px;
    border: none;
    background: #222;
    color: #ffd700;
    box-shadow: inset 0 0 12px #ffd700aa;
    transition: box-shadow 0.3s ease;
  }
  .buscador input::placeholder {
    color: #ffd700aa;
    font-style: italic;
  }
  .buscador input:focus {
    outline: none;
    box-shadow: 0 0 25px #ffd700ff;
    background: #2a2a00;
    color: #fff;
  }
  .buscador svg {
    position: absolute;
    right: 1rem;
    top: 50%;
    transform: translateY(-50%);
    fill: #ffd700aa;
    width: 20px; height: 20px;
    pointer-events: none;
  }

  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0 10px;
    font-size: 1.25rem;
  }
  thead tr {
    background: transparent;
  }
  thead th {
    color: #ffd700cc;
    text-transform: uppercase;
    font-weight: 700;
    padding-bottom: 0.8rem;
    letter-spacing: 2px;
    text-align: center;
  }
  tbody tr {
    background: rgba(255, 215, 0, 0.1);
    box-shadow: 0 0 20px #ffd70055;
    border-radius: 18px;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
    cursor: default;
  }
  tbody tr:hover {
    transform: scale(1.04);
    box-shadow: 0 0 35px #ffd700dd;
    background: #ffd70044;
  }
  tbody td {
    padding: 0.95rem 1.4rem;
    text-align: center;
    vertical-align: middle;
    color: #fff9d0;
    user-select: none;
  }

  /* Posición */
  .posicion {
    font-weight: 900;
    font-size: 1.45rem;
    color: #fff;
    width: 50px;
  }

  /* Medallas */
  .medalla {
    font-size: 1.8rem;
    width: 50px;
    user-select: none;
    transition: transform 0.3s ease;
  }
  tbody tr:hover .medalla {
    transform: scale(1.3);
  }

  /* Nivel */
  .nivel {
    font-weight: 700;
    color: #fff066;
  }

  /* Responsive */
  @media (max-width: 720px) {
    main {
      margin: 6rem 1rem 3rem;
      padding: 1.5rem 2rem;
      font-size: 1rem;
    }
    h1 {
      font-size: 2.2rem;
    }
    table {
      font-size: 1rem;
    }
    .buscador input {
      font-size: 1rem;
    }
  }

  /* Gráfica */
  #chartContainer {
    margin-top: 2.8rem;
  }
</style>
</head>
<body>

<nav>
  <div><i class="fas fa-code"></i> INSANE CODE</div>
  <div>
    <a href="retos.php"><i class="fas fa-terminal"></i> Retos</a>
    <a href="perfil.php"><i class="fas fa-user"></i> Perfil</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Cerrar sesión</a>
  </div>
</nav>

<div id="tsparticles"></div>

<main>
  <h1>Ranking INSANE CODE</h1>

  <div class="buscador" role="search" aria-label="Buscar jugador">
    <input type="search" id="searchInput" placeholder="Buscar jugador..." aria-describedby="searchIcon" />
    <svg id="searchIcon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M15.5 14h-.79l-.28-.27a6.471 6.471 0 001.48-5.34C15.04 5.88 12.16 3 8.5 3S2 5.88 2 9.5 4.88 16 8.5 16a6.471 6.471 0 005.34-1.48l.27.28v.79l5 4.99L20.49 19l-4.99-5zM8.5 14C6.01 14 4 11.99 4 9.5S6.01 5 8.5 5 13 7.01 13 9.5 10.99 14 8.5 14z"/>
    </svg>
  </div>

  <table aria-label="Tabla de ranking de usuarios por puntos" id="rankingTable" role="table">
    <thead>
      <tr>
        <th scope="col">#</th>
        <th scope="col">Medalla</th>
        <th scope="col">Usuario</th>
        <th scope="col">Email</th>
        <th scope="col">Puntos</th>
        <th scope="col">Nivel</th>
      </tr>
    </thead>
    <tbody>
      <?php
      $pos = 1;
      foreach ($ranking as $user):
        $medalla = '';
        if ($pos == 1) $medalla = '🥇';
        else if ($pos == 2) $medalla = '🥈';
        else if ($pos == 3) $medalla = '🥉';
      ?>
      <tr>
        <td class="posicion"><?= $pos++ ?></td>
        <td class="medalla"><?= $medalla ?></td>
        <td><?= htmlspecialchars($user['username']) ?></td>
        <td><?= htmlspecialchars($user['email']) ?></td>
        <td><?= (int)$user['total_puntos'] ?></td>
        <td class="nivel"><?= $user['nivel'] ?></td>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>

  <div id="chartContainer">
    <canvas id="rankingChart" aria-label="Gráfica de puntos de usuarios" role="img"></canvas>
  </div>
</main>

<script>
  tsParticles.load("tsparticles", {
    fpsLimit: 60,
    background: { color: "#000" },
    particles: {
      number: { value: 100 },
      color: { value: ["#ffd700", "#fff066", "#ffaa00"] },
      shape: { type: ["circle", "triangle", "star"] },
      opacity: { value: 0.75, random: true },
      size: { value: 3, random: { enable: true, minimumValue: 1 } },
      links: {
        enable: true,
        distance: 140,
        color: "#ffd700",
        opacity: 0.25,
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
        repulse: { distance: 110 },
        push: { quantity: 4 }
      }
    },
    detectRetina: true
  });

  // Buscador: filtrar filas de tabla
  document.getElementById('searchInput').addEventListener('input', function() {
    const filtro = this.value.toLowerCase();
    const filas = document.querySelectorAll('#rankingTable tbody tr');
    filas.forEach(fila => {
      const usuario = fila.cells[2].textContent.toLowerCase();
      fila.style.display = usuario.includes(filtro) ? '' : 'none';
    });
  });

  // Gráfica con Chart.js: Top 10 usuarios
  const ctx = document.getElementById('rankingChart').getContext('2d');
  const labels = [
    <?php
    $top10 = array_slice($ranking, 0, 10);
    foreach ($top10 as $u) {
      echo '"' . addslashes($u['username']) . '",';
    }
    ?>
  ];
  const data = [
    <?php
    foreach ($top10 as $u) {
      echo (int)$u['total_puntos'] . ',';
    }
    ?>
  ];

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Puntos',
        data: data,
        backgroundColor: 'rgba(255, 215, 0, 0.85)',
        borderColor: '#ffd700',
        borderWidth: 1,
        hoverBackgroundColor: '#fff066',
        borderRadius: 8,
        barPercentage: 0.6,
      }]
    },
    options: {
      responsive: true,
      animation: { duration: 1400, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          enabled: true,
          backgroundColor: '#333',
          titleColor: '#ffd700',
          bodyColor: '#fff',
          padding: 8,
          cornerRadius: 6,
          callbacks: {
            label: ctx => ctx.parsed.y + ' puntos'
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: {
            color: '#444'
          },
          ticks: {
            color: '#ffd700cc',
            font: { family: 'JetBrains Mono', size: 13 }
          }
        },
        x: {
          grid: { display: false },
          ticks: {
            color: '#ffd700cc',
            font: { family: 'JetBrains Mono', size: 13 }
          }
        }
      }
    }
  });
</script>

</body>
</html>
