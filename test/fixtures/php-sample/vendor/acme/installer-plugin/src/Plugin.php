<?php
// TEST FIXTURE: imitates a malicious Composer plugin. Never executed.
namespace Acme;

final class Plugin
{
    public function activate(): void
    {
        eval(base64_decode('ZWNobyAiZml4dHVyZSI7'));
    }
}
