<?php
require_once __DIR__ . '/config/seguridad.php';
require_once __DIR__ . '/config/conexion.php';
require_once __DIR__ . '/config/functions.php';
?>

<!DOCTYPE html>
<html lang="es" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>INSANE CODE | Retos & Comunidad PREMIUM</title>

  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet" />

  <!-- FontAwesome -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />

  <!-- SweetAlert2 -->
  <link href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css" rel="stylesheet" />

  <!-- tsParticles -->
  <script src="https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js"></script>

  <!-- Canvas Confetti -->
  <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.6.0/dist/confetti.browser.min.js"></script>

  <!-- Glide.js CSS & JS (Carrusel Premium) -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@glidejs/glide/dist/css/glide.core.min.css" />
  <script src="https://cdn.jsdelivr.net/npm/@glidejs/glide/dist/glide.min.js"></script>

  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap');

    /* Reset & base */
    * {
      box-sizing: border-box;
    }
    html, body {
      margin: 0; padding: 0; height: 100%;
      background: linear-gradient(135deg, #000000, #0b0b0b);
      color: #f7d518;
      font-family: 'JetBrains Mono', monospace;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    /* Particles BG */
    #tsparticles {
      position: fixed;
      width: 100%;
      height: 100%;
      top: 0; left: 0;
      z-index: 0;
      background: transparent;
      user-select: none;
    }

    /* Container */
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem 1rem 8rem;
      position: relative;
      z-index: 10;
      user-select: none;
    }

    /* Header */
    header {
      text-align: center;
      margin-bottom: 3rem;
      user-select: none;
    }
    header h1 {
      font-size: clamp(3rem, 6vw, 6rem);
      font-weight: 900;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: #f7d518;
      text-shadow:
        0 0 15px #f7d518cc,
        0 0 40px #f7d518aa,
        0 0 80px #f7d51877;
      animation: neonPulse 3s ease-in-out infinite alternate;
      margin-bottom: 0.2rem;
    }
    header p {
      font-size: 1.2rem;
      color: #e8cc1aaa;
      letter-spacing: 0.07em;
      margin-top: 0;
      font-weight: 600;
    }
    @keyframes neonPulse {
      0%, 100% {
        text-shadow:
          0 0 15px #f7d518cc,
          0 0 40px #f7d518aa,
          0 0 80px #f7d51877;
      }
      50% {
        text-shadow:
          0 0 30px #fff77a,
          0 0 60px #fff77a,
          0 0 90px #fff77a;
      }
    }

    /* Buttons */
    .btn-group {
      display: flex;
      justify-content: center;
      gap: 2rem;
      margin-bottom: 4rem;
      flex-wrap: wrap;
    }
    .btn {
      background: linear-gradient(135deg, #f7d518 0%, #b49700 100%);
      border: none;
      color: #1a1a1a;
      font-weight: 900;
      padding: 1rem 3rem;
      border-radius: 20px;
      font-size: 1.4rem;
      cursor: pointer;
      box-shadow:
        0 0 30px #f7d518cc,
        inset 0 0 15px #fffbc088;
      transition: all 0.3s ease;
      text-transform: uppercase;
      letter-spacing: 1.6px;
      position: relative;
      overflow: hidden;
      outline-offset: 4px;
      outline-color: transparent;
      outline-style: solid;
      outline-width: 2px;
      user-select: none;
      display: inline-flex;
      align-items: center;
      gap: 0.8rem;
    }
    .btn i {
      font-size: 1.6rem;
    }
    .btn:hover {
      background: linear-gradient(135deg, #b49700 0%, #f7d518 100%);
      box-shadow:
        0 0 50px #fff77aff,
        inset 0 0 30px #fff77aff;
      outline-color: #fff77a;
      transform: scale(1.1);
    }
    .btn:active {
      transform: scale(0.9);
      box-shadow: none;
    }

    /* Glide.js Carrusel */
    .glide {
      max-width: 1100px;
      margin: 0 auto 5rem;
      position: relative;
      user-select: none;
    }
    .glide__slide {
      background: rgba(255, 213, 24, 0.1);
      border-radius: 20px;
      padding: 2rem 1.5rem 3rem;
      box-shadow:
        0 0 25px #f7d518aa,
        inset 0 0 40px #fffca0cc;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: 420px;
      color: #fff;
      transition: transform 0.3s ease;
      position: relative;
    }
    .glide__slide:hover {
      transform: scale(1.07);
      box-shadow:
        0 0 60px #fff77aff,
        inset 0 0 60px #fff77aff;
      cursor: pointer;
    }
    .challenge-img {
      width: 100%;
      height: 180px;
      object-fit: cover;
      border-radius: 15px;
      margin-bottom: 1.2rem;
      box-shadow: 0 0 15px #f7d518cc;
      user-select: none;
    }
    .challenge-title {
      font-size: 1.8rem;
      font-weight: 900;
      letter-spacing: 0.08em;
      color: #ffd700;
      margin-bottom: 0.6rem;
      user-select: none;
    }
    .challenge-desc {
      flex-grow: 1;
      font-size: 1rem;
      color: #eee;
      margin-bottom: 1rem;
      line-height: 1.5;
      user-select: text;
    }
    .challenge-badges {
      margin-bottom: 1rem;
      display: flex;
      gap: 1rem;
      user-select: none;
    }
    .badge {
      background: #b4970022;
      border: 1.8px solid #f7d518aa;
      border-radius: 20px;
      padding: 0.3rem 1rem;
      font-weight: 700;
      font-size: 0.9rem;
      color: #f7d518;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      box-shadow: 0 0 12px #f7d518aa;
      user-select: none;
    }
    .stars {
      color: #ffd700;
      font-size: 1.3rem;
      user-select: none;
    }
    .btn-challenge {
      background: #ffd700;
      color: #1a1a1a;
      font-weight: 900;
      padding: 0.75rem 2.2rem;
      border-radius: 15px;
      font-size: 1.1rem;
      box-shadow:
        0 0 20px #ffd700cc,
        inset 0 0 15px #fff600cc;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: 1.4px;
      align-self: flex-start;
      transition: background 0.3s ease;
      border: none;
      user-select: none;
    }
    .btn-challenge:hover {
      background: #fff600;
      box-shadow:
        0 0 40px #fff600ff,
        inset 0 0 25px #fff600ff;
    }

    /* Glide Controls */
    .glide__arrow {
      color: #f7d518;
      font-size: 2.4rem;
      background: transparent;
      border: none;
      position: absolute;
      top: 40%;
      cursor: pointer;
      z-index: 20;
      transition: color 0.3s ease;
      user-select: none;
    }
    .glide__arrow:hover {
      color: #fff77a;
    }
    .glide__arrow--left {
      left: -2rem;
    }
    .glide__arrow--right {
      right: -2rem;
    }

    /* Top Usuarios */
    .top-users {
      max-width: 1100px;
      margin: 0 auto 5rem;
      color: #fff;
      user-select: none;
    }
    .top-users h2 {
      text-align: center;
      font-size: 2.8rem;
      font-weight: 900;
      color: #f7d518;
      margin-bottom: 1rem;
      letter-spacing: 0.15em;
      text-transform: uppercase;
    }
    .users-list {
      display: flex;
      justify-content: center;
      gap: 3rem;
      flex-wrap: wrap;
    }
    .user-card {
      background: rgba(255, 213, 24, 0.1);
      border-radius: 15px;
      padding: 1rem 1.5rem;
      width: 180px;
      box-shadow:
        0 0 15px #f7d518aa,
        inset 0 0 30px #fffca0cc;
      text-align: center;
      transition: transform 0.3s ease;
      cursor: default;
    }
    .user-card:hover {
      transform: scale(1.05);
      box-shadow:
        0 0 40px #fff77aff,
        inset 0 0 40px #fff77aff;
    }
    .user-img {
      width: 110px;
      height: 110px;
      border-radius: 50%;
      object-fit: cover;
      margin-bottom: 0.8rem;
      box-shadow: 0 0 15px #f7d518cc;
      user-select: none;
    }
    .username {
      font-weight: 900;
      font-size: 1.3rem;
      color: #ffd700;
      margin-bottom: 0.3rem;
      user-select: text;
    }
    .user-rank {
      font-weight: 600;
      font-size: 0.9rem;
      color: #fff8a0aa;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      user-select: text;
    }

    /* ¿Por qué INSANE CODE? */
    .why-insane {
      max-width: 900px;
      margin: 0 auto 6rem;
      text-align: center;
      user-select: none;
    }
    .why-insane h2 {
      font-size: 2.8rem;
      font-weight: 900;
      color: #f7d518;
      margin-bottom: 2rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .benefits {
      display: flex;
      justify-content: center;
      gap: 2.8rem;
      flex-wrap: wrap;
    }
    .benefit {
      background: rgba(255, 213, 24, 0.12);
      border-radius: 15px;
      padding: 2rem 1.5rem;
      width: 260px;
      box-shadow:
        0 0 25px #f7d518cc,
        inset 0 0 45px #fffca0cc;
      user-select: none;
      transition: transform 0.3s ease;
      cursor: default;
    }
    .benefit:hover {
      transform: scale(1.05);
      box-shadow:
        0 0 50px #fff77aff,
        inset 0 0 50px #fff77aff;
    }
    .benefit i {
      font-size: 3rem;
      color: #ffd700;
      margin-bottom: 1rem;
      user-select: none;
    }
    .benefit h3 {
      font-weight: 900;
      font-size: 1.4rem;
      margin-bottom: 1rem;
      color: #fff;
      letter-spacing: 0.1em;
      user-select: text;
    }
    .benefit p {
      color: #fff8a0cc;
      line-height: 1.5;
      font-size: 1rem;
      user-select: text;
    }

    /* Comentarios */
    .comments-section {
      max-width: 900px;
      margin: 0 auto 5rem;
      background: rgba(255, 213, 24, 0.07);
      padding: 2.5rem 3rem;
      border-radius: 20px;
      box-shadow:
        0 0 40px #ffd700aa,
        inset 0 0 60px #fffec0aa;
      color: #fff;
      user-select: none;
    }
    .comments-section h2 {
      font-size: 2.4rem;
      font-weight: 900;
      color: #ffd700;
      margin-bottom: 2rem;
      text-align: center;
      text-transform: uppercase;
      letter-spacing: 0.15em;
    }
    .comment {
      border-bottom: 1.5px solid rgba(255, 215, 0, 0.3);
      padding: 1.4rem 0;
      display: flex;
      flex-direction: column;
      user-select: text;
    }
    .comment:last-child {
      border-bottom: none;
    }
    .comment .username {
      font-weight: 800;
      font-size: 1.2rem;
      color: #ffd700;
      margin-bottom: 0.3rem;
    }
    .comment .stars {
      color: #ffd700;
      font-size: 1.2rem;
      margin-bottom: 0.7rem;
      user-select: none;
    }
    .comment .text {
      font-style: italic;
      color: #eee;
      line-height: 1.5;
      font-size: 1rem;
      max-width: 800px;
      user-select: text;
    }

    /* Footer */
    footer {
      background: #111;
      padding: 2rem 1rem 3rem;
      text-align: center;
      font-size: 0.9rem;
      color: #b49f0eaa;
      border-top: 1px solid #3d3d00aa;
      user-select: none;
    }
    footer a {
      color: #f7d518;
      text-decoration: none;
      font-weight: 700;
      transition: color 0.3s ease;
    }
    footer a:hover {
      color: #fff77a;
    }
    footer .socials {
      margin-top: 1rem;
      display: flex;
      justify-content: center;
      gap: 2rem;
      font-size: 1.8rem;
    }
    footer .socials a {
      transition: color 0.4s ease;
    }
    footer .socials a:hover {
      color: #fff77a;
    }

    /* Responsive */
    @media (max-width: 992px) {
      .glide__slide {
        height: 400px;
      }
      .benefits {
        justify-content: center;
      }
      .btn-group {
        flex-direction: column;
        gap: 1.5rem;
      }
      .btn {
        width: 100%;
      }
      .users-list {
        justify-content: center;
      }
    }
    @media (max-width: 576px) {
      header h1 {
        font-size: 3rem;
      }
      .glide__slide {
        height: 370px;
        padding: 1.5rem 1rem 2.5rem;
      }
      .challenge-desc {
        font-size: 0.9rem;
      }
      .btn-group {
        padding: 0 1rem;
      }
      .comments-section {
        padding: 1.5rem 1.2rem;
      }
    }
  </style>
</head>
<body>

  <!-- tsParticles Background -->
  <div id="tsparticles" aria-hidden="true"></div>

  <main class="container" role="main" aria-label="Página principal de INSANE CODE">

    <!-- Header -->
    <header>
      <h1>INSANE CODE</h1>
      <p>Retos diarios, puntuaciones en vivo y comunidad elite de hackers 🧠</p>
    </header>

    <!-- Buttons -->
    <nav class="btn-group" role="navigation" aria-label="Navegación principal">
      <a href="register.php" role="button" tabindex="0"><button class="btn" type="button"><i class="fas fa-user-plus"></i> Crear Cuenta</button></a>
      <a href="login.php" role="button" tabindex="0"><button class="btn" type="button"><i class="fas fa-sign-in-alt"></i> Iniciar Sesión</button></a>
    </nav>

    <!-- Carrusel de retos -->
<section aria-label="Carrusel de retos de programación" tabindex="0" style="outline:none;">
  <div class="glide" id="glideChallenges" aria-live="polite">
    
    <!-- Slides -->
    <div class="glide__track" data-glide-el="track">
      <ul class="glide__slides">
        <li class="glide__slide" role="group" aria-label="Reto Invertir Cadena - Nivel Fácil">
          <h3 class="challenge-title">Invertir Cadena</h3>
          <div class="challenge-badges">
            <div class="badge">Fácil</div>
            <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="far fa-star"></i></div>
          </div>
          <p class="challenge-desc">Invierte el orden de los caracteres en un string dado. Ideal para practicar manipulación de cadenas.</p>
          <button class="btn-challenge" onclick="window.location.href='login.php'">Ver Reto</button>
        </li>
        <li class="glide__slide" role="group" aria-label="Reto Número Primo - Nivel Medio">
          <h3 class="challenge-title">Número Primo</h3>
          <div class="challenge-badges">
            <div class="badge">Medio</div>
            <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i></div>
          </div>
          <p class="challenge-desc">Determina si un número dado es primo. Practica lógica matemática y optimización.</p>
          <button class="btn-challenge" onclick="window.location.href='login.php'">Ver Reto</button>
        </li>
        <li class="glide__slide" role="group" aria-label="Reto Factorial - Nivel Difícil">
          <h3 class="challenge-title">Factorial</h3>
          <div class="challenge-badges">
            <div class="badge">Difícil</div>
            <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i></div>
          </div>
          <p class="challenge-desc">Calcula el factorial de un número de forma recursiva. Ideal para aprender recursión.</p>
          <button class="btn-challenge" onclick="window.location.href='login.php'">Ver Reto</button>
        </li>
        <li class="glide__slide" role="group" aria-label="Reto Palíndromo - Nivel Medio">
          <h3 class="challenge-title">Palíndromo</h3>
          <div class="challenge-badges">
            <div class="badge">Medio</div>
            <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star-half-alt"></i><i class="far fa-star"></i></div>
          </div>
          <p class="challenge-desc">Verifica si una palabra o frase es un palíndromo. Muy útil para practicar comparaciones de cadenas.</p>
          <button class="btn-challenge" onclick="window.location.href='login.php'">Ver Reto</button>
        </li>
        <li class="glide__slide" role="group" aria-label="Reto Fibonacci - Nivel Avanzado">
          <h3 class="challenge-title">Fibonacci</h3>
          <div class="challenge-badges">
            <div class="badge">Avanzado</div>
            <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star-half-alt"></i><i class="far fa-star"></i></div>
          </div>
          <p class="challenge-desc">Genera una secuencia Fibonacci hasta un número dado. Aprende recursividad y eficiencia.</p>
          <button class="btn-challenge" onclick="window.location.href='login.php'">Ver Reto</button>
        </li>
        <li class="glide__slide" role="group" aria-label="Reto Anagrama - Nivel Difícil">
          <h3 class="challenge-title">Anagrama</h3>
          <div class="challenge-badges">
            <div class="badge">Difícil</div>
            <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="far fa-star"></i></div>
          </div>
          <p class="challenge-desc">Determina si dos cadenas son anagramas entre sí. Reto ideal para manipulación de strings.</p>
          <button class="btn-challenge" onclick="window.location.href='login.php'">Ver Reto</button>
        </li>
      </ul>
    </div>

    <!-- Flechas funcionales -->
    <div data-glide-el="controls">
      <button class="glide__arrow glide__arrow--left bg-yellow-400 text-black rounded-full px-4 py-2" data-glide-dir="<">
        <i class="fas fa-chevron-left"></i>
      </button>
      <button class="glide__arrow glide__arrow--right bg-yellow-400 text-black rounded-full px-4 py-2" data-glide-dir=">">
        <i class="fas fa-chevron-right"></i>
      </button>
    </div>
  </div>
</section>


    <!-- Top Usuarios -->
    <section class="top-users" aria-label="Usuarios destacados">
      <h2>Top Usuarios</h2>
      <div class="users-list">
        <div class="user-card" tabindex="0" aria-label="Usuario hacker Juan, nivel experto">
          <img src="https://randomuser.me/api/portraits/men/32.jpg" alt="Foto de Juan" class="user-img" />
          <div class="username">JuanHacker</div>
          <div class="user-rank">Nivel Experto</div>
        </div>
        <div class="user-card" tabindex="0" aria-label="Usuario hacker María, nivel intermedio">
          <img src="https://randomuser.me/api/portraits/women/44.jpg" alt="Foto de María" class="user-img" />
          <div class="username">MariaCode</div>
          <div class="user-rank">Nivel Intermedio</div>
        </div>
        <div class="user-card" tabindex="0" aria-label="Usuario hacker Pedro, nivel avanzado">
          <img src="https://randomuser.me/api/portraits/men/77.jpg" alt="Foto de Pedro" class="user-img" />
          <div class="username">PedroDev</div>
          <div class="user-rank">Nivel Avanzado</div>
        </div>
      </div>
    </section>

    <!-- Por qué INSANE CODE -->
    <section class="why-insane" aria-label="Beneficios de usar INSANE CODE">
      <h2>¿Por qué INSANE CODE?</h2>
      <div class="benefits">
        <div class="benefit" tabindex="0">
          <i class="fas fa-rocket" aria-hidden="true"></i>
          <h3>Progreso Continuo</h3>
          <p>Retos diarios para que mejores tus habilidades día a día y te conviertas en un verdadero maestro del código.</p>
        </div>
        <div class="benefit" tabindex="0">
          <i class="fas fa-users" aria-hidden="true"></i>
          <h3>Comunidad Elite</h3>
          <p>Conecta con miles de programadores apasionados, comparte conocimientos y compite por los mejores puestos.</p>
        </div>
        <div class="benefit" tabindex="0">
          <i class="fas fa-trophy" aria-hidden="true"></i>
          <h3>Gamificación Real</h3>
          <p>Gana puntos, niveles y medallas que muestran tu progreso y esfuerzo en la plataforma.</p>
        </div>
      </div>
    </section>

    <!-- Comentarios 5 estrellas -->
    <section class="comments-section" aria-label="Comentarios destacados de usuarios">
      <h2>Comentarios ⭐⭐⭐⭐⭐</h2>

      <div class="comment" tabindex="0">
        <div class="username">AnaCodeMaster</div>
        <div class="stars" aria-label="5 estrellas"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i></div>
        <p class="text">"INSANE CODE me ayudó a mejorar mis habilidades rápidamente con retos desafiantes y una comunidad súper activa. ¡Recomendado!"</p>
      </div>

      <div class="comment" tabindex="0">
        <div class="username">CarlosDev</div>
        <div class="stars" aria-label="5 estrellas"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i></div>
        <p class="text">"La mejor plataforma para programadores que quieren practicar y divertirse. Los retos diarios son perfectos para mantenerme afilado."</p>
      </div>

      <div class="comment" tabindex="0">
        <div class="username">LuisaCoder</div>
        <div class="stars" aria-label="5 estrellas"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i></div>
        <p class="text">"El diseño, las animaciones y la comunidad hacen que INSANE CODE sea mi lugar favorito para aprender y competir."</p>
      </div>

    </section>

  </main>

  <!-- Footer -->
  <footer role="contentinfo">
    <p>© 2025 INSANE CODE. Todos los derechos reservados.</p>
    <p>Contacto: <a href="mailto:soporte@insanecode.com">soporte@insanecode.com</a></p>
    <div class="socials" aria-label="Redes sociales">
      <a href="#" aria-label="Facebook"><i class="fab fa-facebook-f"></i></a>
      <a href="#" aria-label="Twitter"><i class="fab fa-twitter"></i></a>
      <a href="#" aria-label="Instagram"><i class="fab fa-instagram"></i></a>
      <a href="#" aria-label="GitHub"><i class="fab fa-github"></i></a>
    </div>
  </footer>

  <!-- Scripts -->

 <script>
  // tsParticles config
  tsParticles.load("tsparticles", {
    fpsLimit: 60,
    background: { color: "transparent" },
    particles: {
      number: { value: 110 },
      color: { value: "#f7d518" },
      shape: { type: "circle" },
      opacity: { value: 0.3, random: true },
      size: { value: 3, random: { enable: true, minimumValue: 1 } },
      links: {
        enable: true,
        distance: 120,
        color: "#f7d518aa",
        opacity: 0.3,
        width: 1
      },
      move: {
        enable: true,
        speed: 1.2,
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

  // Glide.js Init (solo una vez)
  const glide = new Glide('#glideChallenges', {
    type: 'carousel',
    autoplay: 6500,
    hoverpause: true,
    perView: 3,
    gap: 32,
    animationDuration: 800,
    breakpoints: {
      992: { perView: 2 },
      576: { perView: 1 }
    }
  });

  glide.mount();

  // Confetti al cargar
  window.addEventListener("load", () => {
    confetti({
      particleCount: 300,
      spread: 180,
      origin: { y: 0.6 }
    });
  });

  // Función para abrir reto
  function openChallenge(id) {
    // Aquí puedes hacer lógica adicional si quieres
    window.location.href = 'login.php';
  }
</script>


  <!-- SweetAlert2 -->
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</body>
</html>
