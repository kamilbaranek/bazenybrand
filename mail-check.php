<?php
declare(strict_types=1);

function load_env_file(string $path): void
{
  if (!is_file($path) || !is_readable($path)) {
    return;
  }

  $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

  if ($lines === false) {
    return;
  }

  foreach ($lines as $line) {
    $line = trim($line);

    if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
      continue;
    }

    [$key, $value] = explode('=', $line, 2);
    $key = trim($key);
    $value = trim($value);

    if ($key === '' || !preg_match('/^[A-Z0-9_]+$/', $key)) {
      continue;
    }

    if (
      strlen($value) >= 2 &&
      (($value[0] === '"' && substr($value, -1) === '"') || ($value[0] === "'" && substr($value, -1) === "'"))
    ) {
      $value = substr($value, 1, -1);
    }

    $existingValue = getenv($key);

    if ($existingValue === false || $existingValue === '') {
      putenv($key . '=' . $value);
      $_ENV[$key] = $value;
      $_SERVER[$key] = $value;
    }
  }
}

function env_config_value(string $key, string $default = ''): string
{
  $value = getenv($key);

  if (is_string($value) && $value !== '') {
    return $value;
  }

  foreach ([$_ENV[$key] ?? null, $_SERVER[$key] ?? null, $_SERVER['REDIRECT_' . $key] ?? null] as $candidate) {
    if (is_string($candidate) && $candidate !== '') {
      return $candidate;
    }
  }

  return $default;
}

function h(string $value): string
{
  return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function safe_mail_header(string $value): string
{
  return trim(str_replace(["\r", "\n"], '', $value));
}

function encode_mail_subject(string $subject): string
{
  if (function_exists('mb_encode_mimeheader')) {
    return mb_encode_mimeheader($subject, 'UTF-8');
  }

  return '=?UTF-8?B?' . base64_encode($subject) . '?=';
}

load_env_file(__DIR__ . '/.env');

$toEmail = env_config_value('MAIL_CHECK_TO', env_config_value('CONTACT_TO_EMAIL', 'kamil@agenturavendi.cz'));
$fromEmail = env_config_value('MAIL_CHECK_FROM', env_config_value('CONTACT_FROM_EMAIL', 'noreply@bazenybrand.cz'));
$requiredToken = env_config_value('MAIL_CHECK_TOKEN');
$providedToken = trim((string) ($_POST['token'] ?? $_GET['token'] ?? ''));
$status = null;
$mailDisabled = stripos((string) ini_get('disable_functions'), 'mail') !== false;
$mailFunctionAvailable = function_exists('mail') && !$mailDisabled;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
  if ($requiredToken !== '' && !hash_equals($requiredToken, $providedToken)) {
    $status = [
      'type' => 'error',
      'message' => 'Neplatný diagnostický token.',
    ];
  } elseif (!$mailFunctionAvailable) {
    $status = [
      'type' => 'error',
      'message' => 'Funkce mail() není v této PHP konfiguraci dostupná.',
    ];
  } else {
    $host = safe_mail_header($_SERVER['HTTP_HOST'] ?? 'web');
    $subject = 'Test PHP mail() z webu Bazény Brand';
    $body = implode("\n", [
      'Testovací zpráva z mail-check.php',
      '',
      'Odesláno: ' . date('d.m.Y H:i:s'),
      'Web: ' . $host,
      'PHP: ' . PHP_VERSION,
    ]);
    $headers = [
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      'From: Bazény Brand <' . safe_mail_header($fromEmail) . '>',
      'X-Mailer: PHP/' . phpversion(),
    ];

    $sent = mail(safe_mail_header($toEmail), encode_mail_subject($subject), $body, implode("\r\n", $headers));
    $status = [
      'type' => $sent ? 'success' : 'error',
      'message' => $sent
        ? 'mail() vrátilo true. Zkontrolujte doručení testovací zprávy.'
        : 'mail() vrátilo false. Server zprávu nepřijal k odeslání.',
    ];
  }
}
?>
<!DOCTYPE html>
<html lang="cs">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Kontrola PHP mail()</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        line-height: 1.5;
        margin: 0;
        padding: 32px;
        color: #102a56;
        background: #f4f8ff;
      }

      main {
        max-width: 720px;
        margin: 0 auto;
        padding: 28px;
        border: 1px solid #cfe0fb;
        border-radius: 8px;
        background: #fff;
      }

      h1 {
        margin-top: 0;
      }

      dl {
        display: grid;
        grid-template-columns: 180px 1fr;
        gap: 8px 16px;
      }

      dt {
        font-weight: 700;
      }

      input,
      button {
        font: inherit;
      }

      input {
        width: 100%;
        box-sizing: border-box;
        padding: 10px 12px;
        border: 1px solid #b7c9e8;
        border-radius: 6px;
      }

      button {
        margin-top: 12px;
        padding: 10px 16px;
        border: 0;
        border-radius: 6px;
        color: #fff;
        background: #2168df;
        cursor: pointer;
      }

      .status {
        padding: 12px 14px;
        border-radius: 6px;
        margin-bottom: 18px;
      }

      .status--success {
        color: #126033;
        background: #e7f8ee;
        border: 1px solid #9fd9b7;
      }

      .status--error {
        color: #9b1c1c;
        background: #fff0f0;
        border: 1px solid #f0b4b4;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Kontrola PHP mail()</h1>

      <?php if ($status !== null): ?>
        <p class="status status--<?php echo h($status['type']); ?>"><?php echo h($status['message']); ?></p>
      <?php endif; ?>

      <dl>
        <dt>mail()</dt>
        <dd><?php echo $mailFunctionAvailable ? 'dostupné' : 'nedostupné'; ?></dd>
        <dt>disable_functions</dt>
        <dd><?php echo h((string) ini_get('disable_functions') ?: '-'); ?></dd>
        <dt>sendmail_path</dt>
        <dd><?php echo h((string) ini_get('sendmail_path') ?: '-'); ?></dd>
        <dt>SMTP</dt>
        <dd><?php echo h((string) ini_get('SMTP') ?: '-'); ?></dd>
        <dt>smtp_port</dt>
        <dd><?php echo h((string) ini_get('smtp_port') ?: '-'); ?></dd>
        <dt>Testovací příjemce</dt>
        <dd><?php echo h($toEmail); ?></dd>
        <dt>Testovací odesílatel</dt>
        <dd><?php echo h($fromEmail); ?></dd>
      </dl>

      <form method="post">
        <label>
          Diagnostický token
          <input type="password" name="token" value="<?php echo h($providedToken); ?>" autocomplete="off" />
        </label>
        <button type="submit">Odeslat test přes mail()</button>
      </form>
    </main>
  </body>
</html>
