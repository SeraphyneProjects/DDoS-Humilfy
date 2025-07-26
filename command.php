<?php
$filename = "command.json";
$input = json_decode(file_get_contents("php://input"), true);

if (!isset($input["command"])) {
    http_response_code(400);
    echo json_encode(["error" => "Missing command"]);
    exit;
}

if (file_exists($filename)) {
    $existing = json_decode(file_get_contents($filename), true);
} else {
    $existing = ["command" => []];
}

$existing["command"] = array_merge($existing["command"], $input["command"]);

// Simpan kembali
file_put_contents($filename, json_encode($existing, JSON_PRETTY_PRINT));
echo json_encode(["status" => "Command added"]);
?>
