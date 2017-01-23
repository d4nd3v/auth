# Laravel 5 Auth Generator (Web & API)

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



### Step x: Generate Auth

```php artisan generate:auth```





### Step 3: Create Tables

```
php artisan migrate --path=/database/migrations/auth/
```
This will create ```users```, ```password_resets``` and ```activations``` tables.





### Step x: If you user API Auth:
https://github.com/tymondesigns/jwt-auth/wiki/Installation  
In header must be set: Accept: application/json  



Flow:  
```  
  
> Register (/register)  
    > ActivateAccount Notification (Send Mail)  
        > Activate (From Mail) (GET /account/activate/token)   

> Forgot password? (GET /password/reset)
        > PasswordReset Notification (Send Mail)     
            > Change password form (From Mail) (GET /password/reset/token)
                > Action change password (/password/reset)



> Login Form (GET /login)
    > Login (POST /login)
        > Form Resend activation code   (GET /account/reactivate/)
            > Action Resend activation code   (POST /account/reactivate/)
    > Change Password (GET /password/change)
        > Set New Password (POST /password/change)
         
 
> Logout (GET /logout)

            
```













