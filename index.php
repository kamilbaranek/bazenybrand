<?php
declare(strict_types=1);

session_start();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

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

load_env_file(__DIR__ . '/.env');

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

$contactConfig = [
  'to_email' => env_config_value('CONTACT_TO_EMAIL', 'kamil@agenturavendi.cz'),
  'from_email' => env_config_value('CONTACT_FROM_EMAIL', 'noreply@bazenybrand.cz'),
  'recaptcha_site_key' => env_config_value('RECAPTCHA_SITE_KEY', '6LcBp8wsAAAAACBSogV8kNWnCePtQpKS1LDnGnvM'),
  'recaptcha_secret_key' => env_config_value('RECAPTCHA_SECRET_KEY'),
  'recaptcha_min_score' => 0.5,
  'smtp_host' => env_config_value('SMTP_HOST'),
  'smtp_port' => (int) env_config_value('SMTP_PORT', '587'),
  'smtp_username' => env_config_value('SMTP_USERNAME'),
  'smtp_password' => env_config_value('SMTP_PASSWORD'),
  'smtp_encryption' => strtolower(env_config_value('SMTP_ENCRYPTION', 'tls')),
];

$localConfigFile = __DIR__ . '/contact-config.local.php';

if (is_file($localConfigFile)) {
  $localConfig = require $localConfigFile;

  if (is_array($localConfig)) {
    $contactConfig = array_replace($contactConfig, $localConfig);
  }
}

if (empty($_SESSION['contact_csrf'])) {
  $_SESSION['contact_csrf'] = bin2hex(random_bytes(32));
}

$contactValues = [
  'name' => '',
  'phone' => '',
  'email' => '',
  'message' => '',
];
$contactErrors = [];
$contactNotice = $_SESSION['contact_notice'] ?? null;
unset($_SESSION['contact_notice']);

function h(string $value): string
{
  return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function read_post_value(string $key): string
{
  return trim((string) ($_POST[$key] ?? ''));
}

function string_length(string $value): int
{
  return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function starts_with(string $value, string $prefix): bool
{
  return substr($value, 0, strlen($prefix)) === $prefix;
}

function normalize_czech_phone(string $phone): ?string
{
  $normalized = preg_replace('/[\s().-]+/', '', $phone);

  if (!is_string($normalized) || $normalized === '') {
    return null;
  }

  if (starts_with($normalized, '00420')) {
    $normalized = '+420' . substr($normalized, 5);
  }

  if (starts_with($normalized, '+420')) {
    $digits = substr($normalized, 4);
  } elseif (starts_with($normalized, '+')) {
    return null;
  } else {
    $digits = $normalized;
  }

  if (!preg_match('/^[2-9]\d{8}$/', $digits)) {
    return null;
  }

  return '+420 ' . substr($digits, 0, 3) . ' ' . substr($digits, 3, 3) . ' ' . substr($digits, 6, 3);
}

function safe_mail_header(string $value): string
{
  return trim(str_replace(["\r", "\n"], '', $value));
}

function log_form_security_event(string $event, array $context = []): void
{
  $pairs = [];

  foreach ($context as $key => $value) {
    if (is_array($value)) {
      $value = implode(',', array_map('strval', $value));
    }

    if ($value === '' || $value === null) {
      continue;
    }

    $pairs[] = $key . '=' . safe_mail_header((string) $value);
  }

  error_log('[contact-form] ' . $event . ($pairs !== [] ? ' ' . implode(' ', $pairs) : ''));
}

function encode_mail_subject(string $subject): string
{
  if (function_exists('mb_encode_mimeheader')) {
    return mb_encode_mimeheader($subject, 'UTF-8');
  }

  return '=?UTF-8?B?' . base64_encode($subject) . '?=';
}

function smtp_read_response($socket): array
{
  $response = '';
  $code = 0;

  while (($line = fgets($socket, 515)) !== false) {
    $response .= $line;

    if (preg_match('/^(\d{3})(\s|-)/', $line, $matches)) {
      $code = (int) $matches[1];

      if ($matches[2] === ' ') {
        break;
      }
    }
  }

  return [$code, trim($response)];
}

function smtp_expect($socket, array $expectedCodes, string $step): bool
{
  [$code, $response] = smtp_read_response($socket);

  if (!in_array($code, $expectedCodes, true)) {
    log_form_security_event('smtp_failed', [
      'step' => $step,
      'code' => $code,
      'response' => $response,
    ]);

    return false;
  }

  return true;
}

function smtp_write_command($socket, string $command, array $expectedCodes, string $step): bool
{
  if (fwrite($socket, $command . "\r\n") === false) {
    log_form_security_event('smtp_write_failed', [
      'step' => $step,
    ]);

    return false;
  }

  return smtp_expect($socket, $expectedCodes, $step);
}

function smtp_send_data($socket, string $data): bool
{
  $normalized = str_replace(["\r\n", "\r"], "\n", $data);
  $lines = explode("\n", $normalized);

  foreach ($lines as $index => $line) {
    if ($line !== '' && $line[0] === '.') {
      $lines[$index] = '.' . $line;
    }
  }

  if (fwrite($socket, implode("\r\n", $lines) . "\r\n.\r\n") === false) {
    log_form_security_event('smtp_write_failed', [
      'step' => 'data_body',
    ]);

    return false;
  }

  return smtp_expect($socket, [250], 'data_body');
}

function send_smtp_email(string $toEmail, string $fromEmail, string $subject, array $headers, string $body, array $config): bool
{
  $host = safe_mail_header((string) ($config['smtp_host'] ?? ''));
  $port = (int) ($config['smtp_port'] ?? 587);
  $username = (string) ($config['smtp_username'] ?? '');
  $password = (string) ($config['smtp_password'] ?? '');
  $encryption = strtolower((string) ($config['smtp_encryption'] ?? 'tls'));

  if ($host === '') {
    return false;
  }

  $remote = $encryption === 'ssl' ? 'ssl://' . $host . ':' . $port : $host . ':' . $port;
  $socket = @stream_socket_client($remote, $errno, $error, 15, STREAM_CLIENT_CONNECT);

  if (!is_resource($socket)) {
    log_form_security_event('smtp_connect_failed', [
      'host' => $host,
      'port' => $port,
      'error' => $error,
      'errno' => $errno,
    ]);

    return false;
  }

  stream_set_timeout($socket, 15);
  $serverName = safe_mail_header($_SERVER['HTTP_HOST'] ?? 'localhost');

  if (
    !smtp_expect($socket, [220], 'connect') ||
    !smtp_write_command($socket, 'EHLO ' . $serverName, [250], 'ehlo')
  ) {
    fclose($socket);
    return false;
  }

  if ($encryption === 'tls') {
    if (!smtp_write_command($socket, 'STARTTLS', [220], 'starttls')) {
      fclose($socket);
      return false;
    }

    if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
      log_form_security_event('smtp_tls_failed', [
        'host' => $host,
      ]);
      fclose($socket);
      return false;
    }

    if (!smtp_write_command($socket, 'EHLO ' . $serverName, [250], 'ehlo_tls')) {
      fclose($socket);
      return false;
    }
  }

  if ($username !== '') {
    if (
      !smtp_write_command($socket, 'AUTH LOGIN', [334], 'auth') ||
      !smtp_write_command($socket, base64_encode($username), [334], 'auth_username') ||
      !smtp_write_command($socket, base64_encode($password), [235], 'auth_password')
    ) {
      fclose($socket);
      return false;
    }
  }

  $messageHeaders = array_merge([
    'To: ' . $toEmail,
    'Subject: ' . encode_mail_subject($subject),
    'Date: ' . date(DATE_RFC2822),
  ], $headers);
  $message = implode("\r\n", $messageHeaders) . "\r\n\r\n" . $body;

  if (
    !smtp_write_command($socket, 'MAIL FROM:<' . $fromEmail . '>', [250], 'mail_from') ||
    !smtp_write_command($socket, 'RCPT TO:<' . $toEmail . '>', [250, 251], 'rcpt_to') ||
    !smtp_write_command($socket, 'DATA', [354], 'data') ||
    !smtp_send_data($socket, $message)
  ) {
    fclose($socket);
    return false;
  }

  smtp_write_command($socket, 'QUIT', [221], 'quit');
  fclose($socket);

  return true;
}

function verify_recaptcha(string $token, array $config): array
{
  if ($config['recaptcha_site_key'] === '' || $config['recaptcha_secret_key'] === '') {
    log_form_security_event('recaptcha_not_configured', [
      'site_key' => $config['recaptcha_site_key'] === '' ? 'missing' : 'set',
      'secret_key' => $config['recaptcha_secret_key'] === '' ? 'missing' : 'set',
      'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);

    return [
      'ok' => false,
      'message' => 'Ochrana formuláře není na serveru nakonfigurovaná. Kontaktujte nás prosím telefonicky.',
    ];
  }

  if ($token === '') {
    return [
      'ok' => false,
      'message' => 'Nepodařilo se ověřit ochranu proti spamu. Zkuste formulář odeslat znovu.',
    ];
  }

  $payload = http_build_query([
    'secret' => $config['recaptcha_secret_key'],
    'response' => $token,
    'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
  ]);

  $response = false;

  if (function_exists('curl_init')) {
    $curl = curl_init('https://www.google.com/recaptcha/api/siteverify');

    if ($curl !== false) {
      curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
      ]);

      $response = curl_exec($curl);
      curl_close($curl);
    }
  }

  if ($response === false) {
    $context = stream_context_create([
      'http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => $payload,
        'timeout' => 8,
      ],
    ]);

    $response = file_get_contents('https://www.google.com/recaptcha/api/siteverify', false, $context);
  }

  $result = is_string($response) ? json_decode($response, true) : null;

  if (!is_array($result) || empty($result['success'])) {
    log_form_security_event('recaptcha_verification_failed', [
      'error_codes' => $result['error-codes'] ?? [],
      'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);

    return [
      'ok' => false,
      'message' => 'Ověření proti spamu selhalo. Zkuste to prosím znovu.',
    ];
  }

  $score = (float) ($result['score'] ?? 0);
  $action = (string) ($result['action'] ?? '');

  if ($action !== 'contact' || $score < (float) $config['recaptcha_min_score']) {
    log_form_security_event('recaptcha_rejected', [
      'action' => $action,
      'score' => $score,
      'errors' => $result['error-codes'] ?? [],
      'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);

    return [
      'ok' => false,
      'message' => 'Odeslání bylo vyhodnoceno jako podezřelé. Zkuste to prosím později.',
    ];
  }

  return ['ok' => true, 'message' => ''];
}

function send_contact_email(array $values, array $config): bool
{
  $subject = 'Nová zpráva z webu Bazény Brand';
  $host = safe_mail_header($_SERVER['HTTP_HOST'] ?? 'web');
  $replyName = safe_mail_header($values['name']);
  $replyEmail = safe_mail_header($values['email']);
  $fromEmail = safe_mail_header($config['from_email']);
  $toEmail = safe_mail_header($config['to_email']);

  $body = implode("\n", [
    'Nová zpráva z kontaktního formuláře',
    '',
    'Jméno: ' . $values['name'],
    'Telefon: ' . $values['phone'],
    'E-mail: ' . $values['email'],
    '',
    'Zpráva:',
    $values['message'],
    '',
    'Odesláno: ' . date('d.m.Y H:i:s'),
    'Web: ' . $host,
    'IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'neznámá'),
    'User-Agent: ' . ($_SERVER['HTTP_USER_AGENT'] ?? 'neznámý'),
  ]);

  $headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'From: Bazény Brand <' . $fromEmail . '>',
    'Reply-To: "' . addcslashes($replyName, '"\\') . '" <' . $replyEmail . '>',
    'X-Mailer: PHP/' . phpversion(),
  ];

  if ((string) ($config['smtp_host'] ?? '') !== '') {
    return send_smtp_email($toEmail, $fromEmail, $subject, $headers, $body, $config);
  }

  $sent = mail($toEmail, encode_mail_subject($subject), $body, implode("\r\n", $headers));

  if (!$sent) {
    log_form_security_event('mail_function_failed', [
      'to' => $toEmail,
      'from' => $fromEmail,
    ]);
  }

  return $sent;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
  $contactValues = [
    'name' => read_post_value('name'),
    'phone' => read_post_value('phone'),
    'email' => read_post_value('email'),
    'message' => read_post_value('message'),
  ];

  $csrfToken = (string) ($_POST['csrf_token'] ?? '');
  $honeypot = read_post_value('company');
  $recaptchaToken = read_post_value('recaptcha_token');

  if (!hash_equals($_SESSION['contact_csrf'], $csrfToken)) {
    log_form_security_event('csrf_mismatch', [
      'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
  }

  if ($honeypot !== '') {
    $contactErrors[] = 'Formulář se nepodařilo odeslat.';
  }

  if (string_length($contactValues['name']) < 2 || string_length($contactValues['name']) > 120) {
    $contactErrors[] = 'Vyplňte prosím jméno v délce 2 až 120 znaků.';
  }

  $normalizedPhone = normalize_czech_phone($contactValues['phone']);

  if ($normalizedPhone === null) {
    $contactErrors[] = 'Vyplňte prosím platný český telefon, například 774 305 155 nebo +420 774 305 155.';
  } else {
    $contactValues['phone'] = $normalizedPhone;
  }

  if (!filter_var($contactValues['email'], FILTER_VALIDATE_EMAIL)) {
    $contactErrors[] = 'Vyplňte prosím platnou e-mailovou adresu.';
  }

  if (string_length($contactValues['message']) < 10 || string_length($contactValues['message']) > 3000) {
    $contactErrors[] = 'Zpráva musí mít 10 až 3000 znaků.';
  }

  if ($contactErrors === []) {
    $recaptchaResult = verify_recaptcha($recaptchaToken, $contactConfig);

    if (!$recaptchaResult['ok']) {
      $contactErrors[] = $recaptchaResult['message'];
    }
  }

  if ($contactErrors === [] && send_contact_email($contactValues, $contactConfig)) {
    $_SESSION['contact_notice'] = [
      'type' => 'success',
      'message' => 'Děkujeme, zpráva byla odeslána. Ozveme se vám co nejdříve.',
    ];
    $_SESSION['contact_csrf'] = bin2hex(random_bytes(32));
    header('Location: ' . strtok((string) ($_SERVER['REQUEST_URI'] ?? 'index.php'), '?') . '?odeslano=1#contact');
    exit;
  }

  if ($contactErrors === []) {
    $contactErrors[] = 'Zprávu se nepodařilo odeslat. Zkuste to prosím později nebo zavolejte.';
  }

  $technicalErrors = [
    'Ochrana formuláře není na serveru nakonfigurovaná. Kontaktujte nás prosím telefonicky.',
    'Nepodařilo se ověřit ochranu proti spamu. Zkuste formulář odeslat znovu.',
    'Ověření proti spamu selhalo. Zkuste to prosím znovu.',
    'Odeslání bylo vyhodnoceno jako podezřelé. Zkuste to prosím později.',
    'Zprávu se nepodařilo odeslat. Zkuste to prosím později nebo zavolejte.',
  ];
  $contactNoticeMessage = 'Formulář obsahuje chyby. Zkontrolujte prosím zvýrazněné informace.';

  if (count($contactErrors) === 1 && in_array($contactErrors[0], $technicalErrors, true)) {
    $contactNoticeMessage = 'Formulář se nepodařilo odeslat.';
  }

  $contactNotice = [
    'type' => 'error',
    'message' => $contactNoticeMessage,
  ];
}

$recaptchaSiteKey = (string) $contactConfig['recaptcha_site_key'];
?>
<!DOCTYPE html>
<html lang="cs">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Bazény & Klimatizace Brand | Homepage koncept</title>
    <meta
      name="description"
      content="Statický HTML/CSS návrh homepage pro Bazény & Klimatizace Brand. Sortiment, služby, realizace, informace o firmě a kontaktní sekce."
    />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Outfit:wght@600;700;800&amp;family=Plus+Jakarta+Sans:wght@400;500;600;700;800&amp;display=swap"
      rel="stylesheet"
    />
    <script>
      document.documentElement.classList.add("js");
    </script>
    <link rel="stylesheet" href="styles.css" />
  </head>
  <body>
    <svg class="visually-hidden" aria-hidden="true">
      <symbol id="icon-arrow" viewBox="0 0 24 24">
        <path
          d="M5 12h14m-6-6 6 6-6 6"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
        />
      </symbol>
      <symbol id="icon-phone" viewBox="0 0 24 24">
        <path
          d="M6.6 3.8 9.4 3c.6-.2 1.2.1 1.5.7l1.2 2.8c.2.5.1 1-.3 1.4l-1.6 1.4a15.5 15.5 0 0 0 4.5 4.5l1.4-1.6c.4-.4.9-.5 1.4-.3l2.8 1.2c.6.3.9.9.7 1.5l-.8 2.8c-.2.7-.9 1.1-1.6 1.1C10.1 20.5 3.5 13.9 3.5 5.4c0-.7.4-1.4 1.1-1.6Z"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-shield" viewBox="0 0 24 24">
        <path
          d="M12 3 5.5 5.5v5.3c0 4.2 2.8 8.1 6.5 9.2 3.7-1.1 6.5-5 6.5-9.2V5.5L12 3Z"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
        <path
          d="m9.2 12.2 1.8 1.8 3.9-4"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-box" viewBox="0 0 24 24">
        <path
          d="m12 3 7 4-7 4-7-4 7-4Zm7 4v8l-7 4-7-4V7m7 4v8"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-users" viewBox="0 0 24 24">
        <path
          d="M15.5 20v-1.2c0-2-1.7-3.6-3.8-3.6H7.8C5.7 15.2 4 16.8 4 18.8V20m13-8.2a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm2.8 8.4v-1c0-1.5-1-2.9-2.5-3.4M9.7 11.6a3.6 3.6 0 1 0 0-7.2 3.6 3.6 0 0 0 0 7.2Z"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-pool" viewBox="0 0 24 24">
        <path
          d="M7 4v6m0-4h4m-4 4c-2.2 0-4 1.8-4 4m6-4v4m8 4c-1 0-1.8-.4-2.6-.8-.8-.4-1.6-.8-2.6-.8s-1.8.4-2.6.8c-.8.4-1.6.8-2.6.8s-1.8-.4-2.6-.8c-.8-.4-1.6-.8-2.6-.8m18 4c-1 0-1.8-.4-2.6-.8-.8-.4-1.6-.8-2.6-.8s-1.8.4-2.6.8c-.8.4-1.6.8-2.6.8s-1.8-.4-2.6-.8c-.8-.4-1.6-.8-2.6-.8"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-flask" viewBox="0 0 24 24">
        <path
          d="M10 3h4m-3 0v6.1l-5.6 9.5a1.5 1.5 0 0 0 1.3 2.2h10.6a1.5 1.5 0 0 0 1.3-2.2L13 9.1V3"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
        <path
          d="M9.5 13.8c1 .8 2 .8 3 0 1-.8 2-.8 3 0"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-pipe" viewBox="0 0 24 24">
        <path
          d="M7 5h8v5m-8 9H5v-8h5m9-1h-6v9h6v-9Zm-8 1v3"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-snow" viewBox="0 0 24 24">
        <path
          d="m12 2 1.6 3.8L17 4.4l-1.1 4 4.1.7-3.5 2.1 2.7 2.7-4-.7.6 4.1-3-2-3 2 .6-4.1-4 .7 2.7-2.7L4 9l4.1-.7-1.1-4 3.4 1.4L12 2Zm0 4.8V17.2"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.6"
        />
      </symbol>
      <symbol id="icon-store" viewBox="0 0 24 24">
        <path
          d="M4 9.5 6 4h12l2 5.5M5 9.5h14v9.5H5V9.5Zm3 0v2a2 2 0 0 0 4 0v-2m0 0v2a2 2 0 0 0 4 0v-2"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-stack" viewBox="0 0 24 24">
        <path
          d="m12 4 7 3.5-7 3.5-7-3.5L12 4Zm7 7-7 3.5L5 11m14 4-7 3.5L5 15"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-user-focus" viewBox="0 0 24 24">
        <path
          d="M8 4H5a1 1 0 0 0-1 1v3m15-4h-3a1 1 0 0 0-1 1m4 11v3a1 1 0 0 1-1 1h-3m-7 0H5a1 1 0 0 1-1-1v-3"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
        <path
          d="M12 13a3.2 3.2 0 1 0 0-6.4A3.2 3.2 0 0 0 12 13Zm-5.2 6c.7-2 2.8-3.2 5.2-3.2s4.5 1.2 5.2 3.2"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-wrench" viewBox="0 0 24 24">
        <path
          d="m14.5 5.2 2.4-2.4a4 4 0 0 1 4.1 5.1l-3 3-3.5-.5-.5-3.5Zm-1.1 4.7L4 19.3a1.8 1.8 0 0 0 2.5 2.5l9.4-9.4"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-clock" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.8" />
        <path
          d="M12 7.4v5.2l3.6 2.1"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-mail" viewBox="0 0 24 24">
        <path
          d="M4 6.5h16v11H4v-11Zm0 .7L12 13l8-5.8"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
      </symbol>
      <symbol id="icon-pin" viewBox="0 0 24 24">
        <path
          d="M12 20s6-5.2 6-10a6 6 0 1 0-12 0c0 4.8 6 10 6 10Z"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.8"
        />
        <circle cx="12" cy="10" r="2.2" fill="none" stroke="currentColor" stroke-width="1.8" />
      </symbol>
      <symbol id="icon-logo" viewBox="0 0 64 64">
        <path
          d="M18 10c6 8 10 14 10 21a10 10 0 1 1-20 0c0-7 4-13 10-21Z"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="3"
        />
        <path
          d="M42 17a8 8 0 0 1 7.2 4.6 8 8 0 1 1-10.4 10.3 8 8 0 1 1 3.2-14.9Z"
          fill="none"
          stroke="currentColor"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="3"
        />
      </symbol>
    </svg>

    <header class="site-header">
      <div class="container site-header__inner">
        <a class="brand" href="#hero" aria-label="Bazény & Klimatizace Brand">
          <img class="brand__logo" src="assets/logo_brand.svg" alt="" />
        </a>

        <button
          class="menu-toggle"
          type="button"
          aria-expanded="false"
          aria-controls="site-nav"
          aria-label="Otevřít navigaci"
        >
          <span aria-hidden="true">&#8203;</span>
          <span aria-hidden="true">&#8203;</span>
          <span aria-hidden="true">&#8203;</span>
        </button>

        <nav class="site-nav" id="site-nav" aria-label="Hlavní navigace">
          <a href="#services">Služby</a>
          <a href="#realizations">Realizace</a>
          <a href="#about">O nás</a>
          <a href="#contact">Kontakt</a>
        </nav>

        <a class="button button--primary header-cta" href="#contact">
          Poptat řešení
        </a>
      </div>
    </header>

    <main>
      <section class="hero" id="hero">
        <div class="container hero__layout">
          <div class="hero__content reveal">
            <h1>
              Vše pro <span>bazény</span>,<br />
              bazénovou chemii<br />
              a <span>klimatizace</span>
            </h1>
            <p class="hero__text">
              Dodáváme kvalitní produkty, poskytujeme odborné poradenství a
              zajišťujeme servis i montáž.
            </p>

            <div class="hero__actions">
              <a class="button button--primary" href="#services">
                Naše služby
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-arrow"></use>
                </svg>
              </a>
              <a class="button button--secondary" href="#contact">
                Kontaktovat nás
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-phone"></use>
                </svg>
              </a>
            </div>

            <ul class="hero-points">
              <li>
                <span class="icon-badge icon-badge--small">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <use href="#icon-shield"></use>
                  </svg>
                </span>
                <div>
                  <strong>Ověřená kvalita</strong>
                  <span>prověřené značky</span>
                </div>
              </li>
              <li>
                <span class="icon-badge icon-badge--small">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <use href="#icon-box"></use>
                  </svg>
                </span>
                <div>
                  <strong>Skladem</strong>
                  <span>ihned k odběru</span>
                </div>
              </li>
              <li>
                <span class="icon-badge icon-badge--small">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <use href="#icon-users"></use>
                  </svg>
                </span>
                <div>
                  <strong>Odborné poradenství</strong>
                  <span>a individuální přístup</span>
                </div>
              </li>
            </ul>
          </div>

          <div class="hero-stage reveal delay-1">
            <img
              class="hero-stage__image"
              src="assets/hero-podklad-wide.png"
              alt=""
              loading="eager"
            />
            <div class="hero-stage__veil" aria-hidden="true"></div>
          </div>
        </div>

        <a class="hero-scroll-hint" href="#services" aria-label="Přejít na sekci Naše služby">
          <span class="hero-scroll-hint__button" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <use href="#icon-arrow"></use>
            </svg>
          </span>
        </a>
      </section>

      <section class="section" id="services" data-section>
        <div class="container">
          <div class="section-heading section-heading--center reveal">
            <p class="eyebrow">Naše služby</p>
            <h2>Kompletní nabídka pro bazény i klimatizace</h2>
          </div>

          <div class="services-grid reveal delay-1">
            <article class="info-card">
              <span class="icon-badge">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-pool"></use>
                </svg>
              </span>
              <h3>Bazény</h3>
              <p>
                Kompletní řešení pro váš bazén od příslušenství přes
                technologii po pravidelnou údržbu.
              </p>
            </article>

            <article class="info-card">
              <span class="icon-badge">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-flask"></use>
                </svg>
              </span>
              <h3>Bazénová chemie</h3>
              <p>
                Široká nabídka kvalitní chemie pro čistou, průzračnou a zdravou
                vodu po celou sezónu.
              </p>
            </article>

            <article class="info-card">
              <span class="icon-badge">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-pipe"></use>
                </svg>
              </span>
              <h3>Příslušenství a fitinky</h3>
              <p>
                Hadice, trysky, spojky, PVC fitinky a vše pro bezproblémový
                provoz bazénu.
              </p>
            </article>

            <article class="info-card">
              <span class="icon-badge">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-snow"></use>
                </svg>
              </span>
              <h3>Klimatizace</h3>
              <p>
                Prodej, montáž a servis klimatizačních jednotek pro domácnosti,
                firmy i komerční provoz.
              </p>
            </article>
          </div>
        </div>
      </section>

      <section class="section section--tint" id="realizations" data-section>
        <div class="container">
          <div class="section-heading section-heading--center reveal">
            <p class="eyebrow">Proč si vybrat nás</p>
            <h2>Kamenná prodejna, vlastní sklad a servisní zázemí</h2>
          </div>

          <div class="advantage-grid reveal delay-1">
            <article class="advantage-item">
              <span class="icon-badge icon-badge--ghost">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-users"></use>
                </svg>
              </span>
              <h3>Odborné poradenství</h3>
              <p>Zkušenosti a znalosti, na které se můžete spolehnout.</p>
            </article>

            <article class="advantage-item">
              <span class="icon-badge icon-badge--ghost">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-store"></use>
                </svg>
              </span>
              <h3>Kamenná prodejna</h3>
              <p>Osobní přístup a možnost rychlé konzultace na místě.</p>
            </article>

            <article class="advantage-item">
              <span class="icon-badge icon-badge--ghost">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-stack"></use>
                </svg>
              </span>
              <h3>Široký sortiment skladem</h3>
              <p>Velkou část zboží máme připravenou k okamžitému odběru.</p>
            </article>

            <article class="advantage-item">
              <span class="icon-badge icon-badge--ghost">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-user-focus"></use>
                </svg>
              </span>
              <h3>Individuální přístup</h3>
              <p>Řešení navrhujeme podle konkrétního provozu i rozpočtu.</p>
            </article>

            <article class="advantage-item">
              <span class="icon-badge icon-badge--ghost">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-wrench"></use>
                </svg>
              </span>
              <h3>Servis a montáž</h3>
              <p>Dodávku umíme doplnit o instalaci i pravidelný servis.</p>
            </article>
          </div>

          <div class="story-grid">
            <div class="realization-gallery reveal delay-2" aria-label="Ukázky vlastních realizací bazénů">
              <button
                class="realization-tile realization-tile--large"
                type="button"
                data-gallery-index="0"
                aria-label="Zobrazit realizaci bazénu ve větším náhledu"
              >
                <img
                  src="assets/realizace/realizace-01.jpg"
                  alt="Dokončený bazén se šedou fólií a napuštěnou vodou"
                  loading="lazy"
                />
                <span>Vlastní realizace</span>
              </button>

              <button
                class="realization-tile"
                type="button"
                data-gallery-index="8"
                aria-label="Zobrazit čistý modrý bazén ve větším náhledu"
              >
                <img
                  src="assets/realizace/realizace-09.jpg"
                  alt="Čistý modrý bazén po servisním zásahu"
                  loading="lazy"
                />
              </button>

              <button
                class="realization-tile"
                type="button"
                data-gallery-index="12"
                aria-label="Zobrazit vyčištěný bazén ve větším náhledu"
              >
                <img
                  src="assets/realizace/realizace-13.jpg"
                  alt="Vyčištěný bazén pod zastřešením"
                  loading="lazy"
                />
              </button>

              <button
                class="realization-tile"
                type="button"
                data-gallery-index="10"
                aria-label="Zobrazit bazén před servisem ve větším náhledu"
              >
                <img
                  src="assets/realizace/realizace-11.jpg"
                  alt="Bazén před čištěním se znečištěnou vodou"
                  loading="lazy"
                />
              </button>

              <button
                class="realization-tile realization-tile--more"
                type="button"
                data-gallery-index="5"
                aria-label="Zobrazit další fotografie realizací"
              >
                <img
                  src="assets/realizace/realizace-06.jpg"
                  alt="Rozpracovaná realizace zapuštěného bazénu"
                  loading="lazy"
                />
                <span>+10 dalších</span>
              </button>
            </div>

            <article class="about-card reveal delay-3" id="about" data-section>
              <p class="eyebrow">O nás</p>
              <h2>Jsme specialisté na bazény, chemii a klimatizace</h2>
              <p>
                Zajišťujeme prodej bazénové technologie, chemie i příslušenství
                a navazující servis u zákazníků. Umíme pomoci s běžnou údržbou,
                čištěním i technickým řešením konkrétního bazénu.
              </p>
              <p>
                V galerii najdete ukázky vlastních zakázek od servisních zásahů
                až po realizace bazénů v různých fázích práce.
              </p>

              <div class="stats-grid">
                <div>
                  <strong>10+</strong>
                  <span>let zkušeností</span>
                </div>
                <div>
                  <strong>100+</strong>
                  <span>spokojených zákazníků</span>
                </div>
                <div>
                  <strong>500+</strong>
                  <span>produktů skladem</span>
                </div>
              </div>
            </article>
          </div>
        </div>
      </section>

      <section class="section section--contact" id="contact" data-section>
        <div class="container">
          <div class="contact-grid">
            <article class="hours-card reveal">
              <p class="eyebrow eyebrow--light">Otevírací doba</p>
              <h2>Zastavte se u nás nebo zavolejte</h2>

              <a
                class="hours-card__map"
                href="https://mapy.com/s/kakusetura"
                target="_blank"
                rel="noopener"
                aria-label="Otevřít polohu prodejny v mapě"
              >
                <img
                  src="assets/map-hliniky-prostejov.svg"
                  alt="Mapa polohy ulice Hliníky v Prostějově"
                  loading="lazy"
                />
                <span>Otevřít mapu</span>
              </a>

              <ul class="hours-list">
                <li>
                  <span>
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <use href="#icon-clock"></use>
                    </svg>
                    Pondělí - Pátek
                  </span>
                  <strong>9:00 - 17:00</strong>
                </li>
                <li>
                  <span>
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <use href="#icon-clock"></use>
                    </svg>
                    Sobota
                  </span>
                  <strong>9:00 - 12:00</strong>
                </li>
                <li>
                  <span>
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <use href="#icon-clock"></use>
                    </svg>
                    Neděle
                  </span>
                  <strong>dle tel. domluvy</strong>
                </li>
              </ul>

              <a class="hours-card__phone" href="tel:+420774305155">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-phone"></use>
                </svg>
                Telefon: 774 305 155
              </a>

              <p class="hours-card__address">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <use href="#icon-pin"></use>
                </svg>
                ulice Hliníky (20m od ul. Plumlovská), Prostějov
              </p>
            </article>

            <article class="form-card reveal delay-1">
              <p class="eyebrow">Máte dotaz? Napište mi:</p>
              <h2>Kontaktní formulář</h2>

              <?php if ($contactNotice !== null): ?>
                <div
                  class="form-status form-status--<?php echo h($contactNotice['type']); ?>"
                  role="<?php echo $contactNotice['type'] === 'success' ? 'status' : 'alert'; ?>"
                >
                  <?php echo h($contactNotice['message']); ?>
                </div>
              <?php endif; ?>

              <?php if ($contactErrors !== []): ?>
                <ul class="form-errors" role="alert">
                  <?php foreach ($contactErrors as $error): ?>
                    <li><?php echo h($error); ?></li>
                  <?php endforeach; ?>
                </ul>
              <?php endif; ?>

              <form class="contact-form" action="index.php#contact" method="post">
                <input type="hidden" name="csrf_token" value="<?php echo h($_SESSION['contact_csrf']); ?>" />
                <input type="hidden" name="recaptcha_token" value="" />
                <label class="contact-form__trap">
                  <span>Firma</span>
                  <input type="text" name="company" tabindex="-1" autocomplete="off" />
                </label>

                <label>
                  <span>Jméno a příjmení</span>
                  <input
                    type="text"
                    name="name"
                    placeholder="Jméno a příjmení"
                    value="<?php echo h($contactValues['name']); ?>"
                    autocomplete="name"
                    required
                  />
                </label>
                <label>
                  <span>Telefon</span>
                  <input
                    type="tel"
                    name="phone"
                    placeholder="Telefon"
                    value="<?php echo h($contactValues['phone']); ?>"
                    autocomplete="tel"
                    required
                  />
                </label>
                <label>
                  <span>E-mail</span>
                  <input
                    type="email"
                    name="email"
                    placeholder="E-mail"
                    value="<?php echo h($contactValues['email']); ?>"
                    autocomplete="email"
                    required
                  />
                </label>
                <label class="contact-form__message">
                  <span>Vaše zpráva</span>
                  <textarea
                    name="message"
                    rows="6"
                    placeholder="Napište stručně, co řešíte."
                    required
                  ><?php echo h($contactValues['message']); ?></textarea>
                </label>

                <button class="button button--primary" type="submit">
                  Odeslat zprávu
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <use href="#icon-arrow"></use>
                  </svg>
                </button>
              </form>
            </article>
          </div>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div class="container site-footer__grid">
        <div class="site-footer__brand">
          <a class="brand brand--footer" href="#hero" aria-label="Bazény & Klimatizace Brand">
            <span class="brand__icon">
              <svg viewBox="0 0 64 64" role="img" aria-hidden="true">
                <use href="#icon-logo"></use>
              </svg>
            </span>
            <span class="brand__copy">
              <span class="brand__kicker">Bazény & Klimatizace</span>
              <strong>BRAND</strong>
            </span>
          </a>
          <p>
            Vše pro bazény a klimatizace na jednom místě. Kvalitní produkty,
            odborné poradenství, servis a individuální přístup.
          </p>
        </div>

        <div>
          <h3>Rychlé odkazy</h3>
          <ul class="footer-links">
            <li><a href="#services">Služby</a></li>
            <li><a href="#realizations">Realizace</a></li>
            <li><a href="#about">O nás</a></li>
            <li><a href="#contact">Kontakt</a></li>
          </ul>
        </div>

        <div>
          <h3>Sortiment</h3>
          <ul class="footer-links">
            <li><span>Bazénová chemie</span></li>
            <li><span>Příslušenství a fitinky</span></li>
            <li><span>Čerpadla a filtrace</span></li>
            <li><span>Testery a měření</span></li>
            <li><span>Údržba bazénu</span></li>
          </ul>
        </div>

        <div>
          <h3>Kontakt</h3>
          <ul class="footer-contact">
            <li>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <use href="#icon-phone"></use>
              </svg>
              <a href="tel:+420774305155">774 305 155</a>
            </li>
            <li>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <use href="#icon-pin"></use>
              </svg>
              <span>ulice Hliníky (20m od ul. Plumlovská), Prostějov</span>
            </li>
            <li>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <use href="#icon-user-focus"></use>
              </svg>
              <span>Odpovědný vedoucí: Vlastimil Brandstetter</span>
            </li>
          </ul>
        </div>
      </div>

      <div class="container site-footer__bottom">
        <p>© 2026 Bazény & Klimatizace Brand</p>
        <p>
          <a href="https://agenturavendi.cz" target="_blank" rel="noopener">
            Web &amp; Marketing - Agentura VENDI
          </a>
        </p>
      </div>
    </footer>

    <div
      class="lightbox"
      id="realization-lightbox"
      role="dialog"
      aria-hidden="true"
      aria-label="Galerie realizací bazénů"
      hidden
      data-lightbox
    >
      <button class="lightbox__close" type="button" aria-label="Zavřít galerii" data-lightbox-close>
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="m6 6 12 12M18 6 6 18"
            fill="none"
            stroke="currentColor"
            stroke-linecap="round"
            stroke-width="2"
          />
        </svg>
      </button>

      <button
        class="lightbox__nav lightbox__nav--prev"
        type="button"
        aria-label="Předchozí fotografie"
        data-lightbox-prev
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <use href="#icon-arrow"></use>
        </svg>
      </button>

      <figure class="lightbox__figure">
        <img
          class="lightbox__image"
          src="assets/realizace/realizace-01.jpg"
          alt="Dokončený bazén se šedou fólií a napuštěnou vodou"
          data-lightbox-image
        />
        <figcaption class="lightbox__meta">
          <span data-lightbox-caption>Dokončená realizace fóliového bazénu se šedým povrchem.</span>
          <strong data-lightbox-counter>1 / 15</strong>
        </figcaption>
      </figure>

      <button
        class="lightbox__nav lightbox__nav--next"
        type="button"
        aria-label="Další fotografie"
        data-lightbox-next
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <use href="#icon-arrow"></use>
        </svg>
      </button>
    </div>

    <script>
      window.contactFormConfig = {
        recaptchaSiteKey: <?php echo json_encode($recaptchaSiteKey, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>
      };
    </script>
    <?php if ($recaptchaSiteKey !== ''): ?>
      <script
        src="https://www.google.com/recaptcha/api.js?render=<?php echo h(rawurlencode($recaptchaSiteKey)); ?>"
        async
        defer
      ></script>
    <?php endif; ?>
    <script src="app.js"></script>
  </body>
</html>
