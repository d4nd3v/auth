# Laravel 5 Auth Generator (Web & API)

## Usage

### Step 1: Install Through Composer

```
composer require d4nd3v/auth:dev-master
```

### Step 2: Add the Service Provider

Add the provider in `app/Providers/AppServiceProvider.php`

```php
public function register()
{
    ...
	if ($this->app->environment() !== 'production') {
		$this->app->register('D4nd3v\Auth\AuthServiceProvider');
	}
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

### Step x:
Go to ```config/auth.php``` and change ```App\User:class``` to ```App\Models\User::class```.



### Step x: Add Web routes:

```
    Route::get('register', 'AuthController@showRegisterForm')->name('registerForm');
    Route::post('register', 'AuthController@register')->name('register');

    Route::get('account/activate/', 'AuthController@showActivateMessage')->name('activate');
    Route::get('account/activate/{token}', 'AuthController@activate');

    Route::get('account/reactivate/', 'AuthController@showResendActivationCode')->name('reactivateForm');
    Route::post('account/reactivate/', 'AuthController@resendActivationCode')->name('reactivate');

    Route::get('login', 'AuthController@showLoginForm')->name('loginForm');
    Route::post('login', 'AuthController@authenticate')->name('login');

    Route::get('logout', 'AuthController@logout')->name('logout');

    Route::get('password/reset', 'AuthController@showLinkRequestForm');
    Route::post('password/email', 'AuthController@sendEmailWithResetPasswordLink');
    Route::get('password/reset/{token}', 'AuthController@showResetForm')->name('showResetForm');
    Route::post('password/reset', 'AuthController@resetPassword');

    Route::group(['middleware' => 'auth'], function () {
        Route::get('password/change', 'AuthController@showChangePasswordForm')->name('showChangePasswordForm');
        Route::post('password/change', 'AuthController@changePassword')->name('changePassword');
    });
```








## Flow:  
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









