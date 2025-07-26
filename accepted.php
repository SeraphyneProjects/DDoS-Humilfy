<?php
$filename = "command.json";
$input = json_decode(file_get_contents("php://input"), true);

if (!isset($input["request-id"])) {
    http_response_code(400);
    echo json_encode(["error" => "Missing request-id"]);
    exit;
}

if (!file_exists($filename)) {
    echo json_encode(["status" => "No command file"]);
    exit;
}

$data = json_decode(file_get_contents($filename), true);

$data["command"] = array_values(array_filter($data["command"], function($cmd) use ($input) {
    return $cmd["request-id"] !== $input["request-id"];
}));

file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT));

echo json_encode(["status" => "Command with request-id removed"]);
?>
