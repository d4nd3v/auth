# Laravel 5 Auth Generator

## Usage

### Step 1: Install Through Composer

```
composer require d4nd3v/auth
```

### Step 2: Add the Service Provider

Add the provider in `app/Providers/AppServiceProvider.php`

```php
public function register()
{
    ...
    $this->app->register('D4nd3v\Auth\AuthServiceProvider');
}
```

### Step 3: Create Tables

```
php artisan migrate
```
This will create ```users``` and ```password_resets``` tables.






















