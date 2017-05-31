<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Support\Facades\Validator;
use App\Libraries\ApiResponse;
use App\Models\User;
use App\Models\Activation;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Requests\ChangePasswordRequest;
use Illuminate\Routing\Controller as BaseController;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;

use App\Exceptions\ApiException;

class AuthController extends BaseController
{
    use ValidatesRequests;

    protected $maxLoginAttempts = 10; // Amount of bad attempts user can make
    protected $lockoutTime = 300; // Time for which user is going to be blocked in seconds


    public function showLoginForm()
    {
        return view('auth.login');
    }


    public function authenticate()
    {
        $validator = Validator::make(request()->all(), [
            'email' => 'required|email|max:255',
            'password' => 'required',
        ]);

        $credentials = [
            'email'    => request()->input('email'),
            'password' => request()->input('password'),
        ];

        if ($validator->fails()) {
            if (request()->expectsJson()) {
                throw new ApiException("validation", array_combine($validator->errors()->keys(), $validator->errors()->all()));
            } else {
                return redirect(route('login'))
                    ->withInput(request()->only('email', 'remember'))
                    ->withErrors($validator->errors());
            }
        }


        // Preventing Brute-Force Attacks
        if($this->maxLoginAttempts > 0) {

            if ( ! $user = User::where(['email' => $credentials['email']])->first()) {
                //throw new Exception user not found
            } else {
                // check and log user login fail attempt
                if ($user->login_attempts + 1 > $this->maxLoginAttempts)
                {
                    $secondsFromLastFail =  Carbon::now()->diffInSeconds(Carbon::parse($user->last_login_attempt));
                    if ($secondsFromLastFail < $this->lockoutTime)
                    {
                        // trow new Exception to wait a while
                        if (request()->expectsJson()) {
                            throw new ApiException("throttle", null, trans('authdd.throttle', ['seconds' => $this->lockoutTime-$secondsFromLastFail]));
                        } else {
                            return redirect(route('login'))
                                ->withInput(request()->only('email', 'remember'))
                                ->withErrors([ 'throttle' => trans('authdd.throttle', ['seconds' => $this->lockoutTime-$secondsFromLastFail]) ]);
                        }
                    }
                }
                if ( ! Auth::validate($credentials))
                {
                    $user->login_attempts++;
                    $user->last_login_attempt = Carbon::now();
                } else {
                    // corect credentials
                    $user->login_attempts = 0;
                }
                $user->save();
            }
        }



        if (!Auth::validate($credentials)) {
            if (request()->expectsJson()) {
                throw new ApiException("invalid_credentials");
            } else {
                return redirect(route('login'))
                    ->withInput(request()->only('email', 'remember'))
                    ->withErrors([ 'invalid_credentials' => trans('authdd.invalid_credentials') ]);
            }
        } else {
            $user = Auth::getLastAttempted();
            if ($user->account_disabled) {
                if (request()->expectsJson()) {
                    throw new ApiException("account_disabled");
                } else {
                    return redirect(route('login'))
                        ->withInput(request()->only('email', 'remember'))
                        ->withErrors([ 'account_disabled' => trans('authdd.account_disabled') ]);
                }
            } else if (!($user->active)) {
                if (request()->expectsJson()) {
                    throw new ApiException("email_not_confirmed");
                } else {
                    return redirect(route('login'))
                        ->withInput(request()->only('email', 'remember'))
                        ->withErrors([ 'email_not_confirmed' => trans('authdd.email_not_confirmed') ]);
                }
            } else {
                // succes
                if (request()->expectsJson()) {
                     try {
                        if (! $token = \JWTAuth::attempt($credentials)) {
                            throw new ApiException("invalid_credentials");
                        } else {

                            // succes API
                            $user->last_login = Carbon::now();
                            $user->save();

                            return response()->json([ 'data' => ['token'=>$token] ], 200);
                        }
                     } catch (JWTException $e) {
                         throw new ApiException("could_not_create_token");
                     }
                } else {

                    Auth::login($user, request()->has('remember'));

                    // succes WEB
                    $user->last_login = Carbon::now();
                    $user->save();

                    // redirect admin users in admin section
					$defaultRedirect = null;
					// if($user->hasAnyRole('admin', 'superadmin')) {
					// 	$defaultRedirect = "/admin";
					// }

                    return redirect()->intended($defaultRedirect);
                }
            }
        }
    }


    public function logout()
    {
        if (request()->expectsJson()) {
            // api logout here...
        } else {
            Auth::logout();
            return redirect()->route('login');
        }
    }


    public function showRegisterForm()
    {
        return view('auth.register');
    }


    public function register()
    {

        $validator = Validator::make(request()->all(), [
            'email'                 => 'unique:users|required|max:255|email',
            'password'              => 'required|min:6',
            'password_confirmation' => 'required|same:password'
        ]);


        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if (request()->expectsJson()) {
                throw new ApiException("validation", array_combine($validator->errors()->keys(), $validator->errors()->all()));
            } else {
                return redirect(route('register'))
                    ->withInput(request()->except('password', 'password_confirmation'))
                    ->withErrors([ 'login_error' => $errorMessages[0], 'validator_errors' => $errorMessages, ]);
            }

        }

        $newUser = request()->except('password');
        $newUser['password'] = bcrypt(request()->input('password'));
        $user = User::create(array_filter($newUser));


        $activationToken = str_random(60);
        Activation::create([
            'user_id' => $user->id,
            'token'   => $activationToken
        ]);



        $user->notify(new \App\Notifications\ActivateAccount($activationToken));

        if (request()->expectsJson()) {
            return response()->json(['data' => ['message' => trans('authdd.activation_mail_sent_again')]], 200);
        } else {
            return redirect(route('activate'));
        }

    }


    public function showActivateMessage()
    {
        return view('auth.activate');
    }


    public function activate($token)
    {
        $activation = Activation::where('token', $token)
            ->where('completed', false)
            ->first();

        if (! $activation) {
            abort(404);
        }

        $activation->completed = true;
        $activation->completed_at = Carbon::now();
        $activation->save();

        $user = User::find($activation->user_id);
        $user->active = 1;
        $user->save();

        return view('auth.activated');
    }


    public function showLinkRequestForm()
    {
        return view('auth.email');
    }


    public function sendEmailWithResetPasswordLink()
    {

        $validator = Validator::make(request()->all(), [
            'email' => 'required|email|max:255'
        ]);

        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if (request()->expectsJson()) {
                throw new ApiException("validation", array_combine($validator->errors()->keys(), $validator->errors()->all()));
            } else {
                return back()->withInput(request()->all())->withErrors([ 'login_error' => $errorMessages[0], 'validator_errors' => $errorMessages, ]);
            }

        }

        $response = \Password::broker()->sendResetLink(request()->only('email'));

        if ($response === \Password::RESET_LINK_SENT) {
            if (request()->expectsJson()) {
                return response()->json([
                    'data' => [
                        'message' => trans('authdd.reset_email_sent')
                    ]], 200);
            } else {
                return back()->with('status', trans('authdd.reset_email_sent'));
            }
        }

        if (request()->expectsJson()) {
            throw new ApiException("reset_email_not_sent");
        } else {
            return back()->withErrors(['email' => trans('authdd.reset_email_not_sent')]);
        }
    }


    public function showResetForm($token = null)
    {
        return view('auth.reset')->with(
            ['token' => $token, 'email' => request()->email]
        );
    }


    public function resetPassword()
    {

        $validator = Validator::make(request()->all(), [
            'email'                 => 'required|max:255|email',
            'password'              => 'required|min:6',
            'password_confirmation' => 'required|same:password'
        ]);


        if ($validator->fails()) {
            if (request()->expectsJson()) {
                throw new ApiException("validation", array_combine($validator->errors()->keys(), $validator->errors()->all()));
            } else {
                $errorMessages = $validator->errors()->all();
                return redirect(route('password.reset', [request()->input('token')]))
                    ->withInput(request()->except('password', 'confirm_password'))
                    ->withErrors([
                        'login_error' => $errorMessages[0],
                        'validator_errors' => $errorMessages,
                    ]);
            }
        }

        $credentials = request()->only('email', 'password', 'password_confirmation', 'token');

        $response = \Password::broker()->reset(
            $credentials,
            function ($user, $password) {
                $user->forceFill([
                    'password' => bcrypt($password),
                    'remember_token' => str_random(60),
                ])->save();
            }
        );

        switch ($response) {
            case \Password::PASSWORD_RESET:
                if (request()->expectsJson()) {
                    return response()->json(['data' => [
                        'code' => 'password_changed',
                        'message' => trans('authdd.password_changed')
                    ]], 200);
                } else {
                    return view('auth.changed');
                }
            default:
                if (request()->expectsJson()) {
                    throw new ApiException("password_could_not_be_changed");
                } else {
                    return redirect(route('password.reset', [request()->input('token')]))
                        ->withInput(request()->except('password', 'confirm_password'))
                        ->withErrors(['password_could_not_be_changed' => trans('authdd.password_could_not_be_changed')]);
                }
        }




    }


    public function showResendActivationCode()
    {
        return view('auth.reactivate');
    }


    public function resendActivationCode()
    {

        $validator = Validator::make(request()->all(), [
            'email' => 'required|max:255|email',
        ]);


        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if (request()->expectsJson()) {
                throw new ApiException("validation", array_combine($validator->errors()->keys(), $validator->errors()->all()));
            } else {
                return redirect(route('reactivate'))->withErrors(['reactivate_error' => $errorMessages[0], 'validator_errors' => $errorMessages,]);
            }
        }



        $user = User::where(['email'=>request()->email, 'active'=>0])->first();
        if($user) {

            $user->notify(new \App\Notifications\ActivateAccount($user->activation->token));

            if (request()->expectsJson()) {
                return response()->json(['data' => ['message' => trans('authdd.account_created')]], 200);
            } else {
                return redirect(route('activate'));
            }


        } else {
            if (request()->expectsJson()) {
                throw new ApiException("reactivate_user_not_found");
            } else {
                return redirect(route('reactivate'))->withErrors(['reactivate_error' => trans('authdd.reactivate_user_not_found')]);
            }
        }


    }


    public function showChangePasswordForm()
    {
        return view('auth.change');
    }


    public function changePassword()
    {

        $validator = Validator::make(request()->all(), [
            'old_password' => 'required|min:6',
            'new_password' => 'required|min:6',
            'password_confirmation' => 'required|same:new_password',
        ]);

        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if (request()->expectsJson()) {
                throw new ApiException("validation", array_combine($validator->errors()->keys(), $validator->errors()->all()));
            } else {
                return redirect(route('showChangePasswordForm'))->withErrors(['reactivate_error' => $errorMessages[0], 'validator_errors' => $errorMessages,]);
            }
        }

        if (request()->expectsJson()) {
            $user = $this->getAuthenticatedUserApi();
        } else {
            $user = Auth::user();
        }

        $credentials = [
            'email' => $user->email,
            'password' => request()->get('old_password'),
        ];


        if (!Auth::validate($credentials)) {
            if (request()->expectsJson()) {
                throw new ApiException("password_could_not_be_changed");
            } else {
                return redirect(route('showChangePasswordForm'))
                    ->withErrors(['password_could_not_be_changed' => trans('authdd.password_could_not_be_changed')]);
            }
        } else {

            $user->password = Hash::make(request()->get('new_password'));
            $user->save();

            if (request()->expectsJson()) {
                return response()->json(['data' => [
                    'code' => 'password_changed',
                    'message' => trans('authdd.password_changed')
                ]], 200);
            } else {
                return view('auth.changed');
            }

        }
    }


    public function getAuthenticatedUserApi()
    {
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['token_absent'], $e->getStatusCode());
        }

        // $userId = $user->id;
        return $user;
    }












}

