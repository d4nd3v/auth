<?php

namespace D4nd3v\Auth;

use Illuminate\Support\ServiceProvider;

class CRUDServiceProvider extends ServiceProvider {

    protected $commands = [
        'D4nd3v\Auth\AuthCommand',
    ];

    public function register(){
        $this->commands($this->commands);
    }
}