<?php

namespace App\Http\Controllers;

use App\Libraries\Linkedin;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Support\Facades\Validator;


use App\Libraries\ApiResponse;
use App\Models\User;
use App\Models\Activation;

use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Requests\ChangePasswordRequest;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;


use Illuminate\Support\Facades\Auth;

use Illuminate\Support\Facades\Password;
use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;



class AuthController extends BaseController
{
    use ValidatesRequests;



/*

    Activation - Notification - Permsssion

    // WEB - Password reset
    Login -> link : Forgot password [Form] {AuthController@showLinkRequestForm--email.blade.php}
            -> POST:/password/email:AuthController@sendResetLinkEmail -> action:send_mail [Link]
                -> mail link:/password/reset/{token} : set new password [Form]
                    -> action : set new password
                        -> show : succes (view:password-changed.blade.php)





    // WEB - Register
    Form Register ->
        -> Activate Account



*/



    public function linkedinAuth(Request $request)
    {

        $userAccessToken = $request->input('code', '');
        if(empty($userAccessToken)) {
            return ApiResponse::error("bad_request", trans("messages.bad_request"), 400);
        } else {

            // get user data from user token
            echo Linkedin::getUserProfile($userAccessToken);

            // daca exista userul se updateaza informatiile

            // daca nu exista, se insereaza userul


            // se returneaza jwt pt id-ul userului creat/updatat

        }



    }










    public function showLoginForm(Request $request)
    {
        return view('auth.login');
    }


    public function authenticate(Request $request)
    {
        // $request->expectsJson = true <=> in header: Accept: application/json

        $validator = Validator::make($request->all(), [
            'email' => 'required|email|max:255',
            'password' => 'required',
        ]);

        $credentials = [
            'email'    => $request->input('email'),
            'password' => $request->input('password'),
        ];

        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                return redirect(route('login'))
                    ->withInput($request->only('email', 'remember'))
                    ->withErrors([ 'login_error' => $errorMessages[0], 'validator_errors' => $errorMessages, ]);
            }

        }

        if (!Auth::validate($credentials)) {
            if ($request->expectsJson()) {
                return ApiResponse::error("invalid_credentials", trans('messages.invalid_credentials'), 401);
            } else {
                return redirect(route('login'))
                    ->withInput($request->only('email', 'remember'))
                    ->withErrors([ 'invalid_credentials' => trans('messages.invalid_credentials') ]);
            }
        } else {
            $user = Auth::getLastAttempted();
            if ($user->account_disabled) {
                if ($request->expectsJson()) {
                    return ApiResponse::error("account_disabled", trans('messages.account_disabled'), 401);
                } else {
                    return redirect(route('login'))
                        ->withInput($request->only('email', 'remember'))
                        ->withErrors([ 'account_disabled' => trans('messages.account_disabled') ]);
                }
            } else if (empty($user->activated_at)) {
                if ($request->expectsJson()) {
                    return ApiResponse::error("email_not_confirmed", trans('messages.email_not_confirmed'), 401);
                } else {
                    return redirect(route('login'))
                        ->withInput($request->only('email', 'remember'))
                        ->withErrors([ 'email_not_confirmed' => trans('messages.email_not_confirmed') ]);
                }
            } else {
                // succes
                if ($request->expectsJson()) {
                     try {
                        if (! $token = \JWTAuth::attempt($credentials)) {
                            return ApiResponse::error("invalid_credentials", trans('messages.invalid_credentials'), 401);
                        } else {
                            return response()->json([ 'data' => ['token'=>$token] ], 200);
                        }
                     } catch (JWTException $e) {
                         return ApiResponse::error("could_not_create_token", trans('messages.could_not_create_token'), 500);
                     }
                } else {
                    Auth::login($user, $request->has('remember'));
                    return redirect()->intended();
                }
            }
        } // END if (!Auth::validate($credentials))
    }


    public function logout(Request $request)
    {
        if ($request->expectsJson()) {
            // api logout here...
        } else {
            Auth::logout();
            return redirect()->route('login');
        }
    }


    public function showRegisterForm(Request $request)
    {
        return view('auth.register');
    }


    public function register(Request $request)
    {
        // $request->expectsJson = true <=> in header: Accept: application/json

        $validator = Validator::make($request->all(), [
            'email'                 => 'unique:users|required|max:255|email',
            'password'              => 'required|min:6',
            'password_confirmation' => 'required|same:password'
        ]);


        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                return redirect(route('register'))
                    ->withInput($request->except('password', 'password_confirmation'))
                    ->withErrors([ 'login_error' => $errorMessages[0], 'validator_errors' => $errorMessages, ]);
            }

        }

        $newUser = $request->except('password');
        $newUser['password'] = bcrypt($request->input('password'));
        $activationToken = str_random(60);
        $newUser['activation_token'] =$activationToken;
        $user = User::create(array_filter($newUser));

        $user->notify(new \App\Notifications\ActivateAccount($activationToken));

        if ($request->expectsJson()) {
            return response()->json(['data' => ['message' => trans('messages.activation_mail_sent_again')]], 200);
        } else {
            return redirect(route('activate'));
        }

    }


    public function showActivateMessage(Request $request)
    {
        return view('auth.activate');
    }


    public function activate(Request $request, $token)
    {
        $user = User::where('activation_token', $token)->first();
        if (! $user) {
            abort(500);
        }
        $user->activated_at = Carbon::now();
        $user->save();
        return view('auth.activated');
    }


    public function showLinkRequestForm(Request $request)
    {
        return view('auth.email');
    }


    public function sendEmailWithResetPasswordLink(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|email|max:255'
        ]);

        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                return back()->withInput($request->all())->withErrors([ 'login_error' => $errorMessages[0], 'validator_errors' => $errorMessages, ]);
            }

        }

        $response = \Password::broker()->sendResetLink($request->only('email'));

        if ($response === \Password::RESET_LINK_SENT) {
            if ($request->expectsJson()) {
                return response()->json([
                    'data' => [
                        'message' => trans('messages.reset_email_sent')
                    ]], 200);
            } else {
                return back()->with('status', trans('messages.reset_email_sent'));
            }
        }

        if ($request->expectsJson()) {
            return ApiResponse::error("reset_email_not_sent", trans('messages.reset_email_not_sent'), 400);
        } else {
            return back()->withErrors(['email' => trans('messages.reset_email_not_sent')]);
        }
    }


    public function showResetForm(Request $request, $token = null)
    {
        return view('auth.reset')->with(
            ['token' => $token, 'email' => $request->email]
        );
    }


    public function resetPassword(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email'                 => 'required|max:255|email',
            'password'              => 'required|min:6',
            'password_confirmation' => 'required|same:password'
        ]);


        if ($validator->fails()) {
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                $errorMessages = $validator->errors()->all();
                return redirect(route('showResetForm', [$request->input('token')]))
                    ->withInput($request->except('password', 'confirm_password'))
                    ->withErrors([
                        'login_error' => $errorMessages[0],
                        'validator_errors' => $errorMessages,
                    ]);

            }
        }

        $credentials = $request->only('email', 'password', 'password_confirmation', 'token');

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
                if ($request->expectsJson()) {
                    return response()->json(['data' => [
                        'code' => 'password_changed',
                        'message' => trans('messages.password_changed')
                    ]], 200);
                } else {
                    return view('auth.changed');
                }
            default:
                if ($request->expectsJson()) {
                    return ApiResponse::error("password_could_not_be_changed", trans('messages.password_could_not_be_changed'), 400);
                } else {
                    return redirect(route('showResetForm', [$request->input('token')]))
                        ->withInput($request->except('password', 'confirm_password'))
                        ->withErrors(['password_could_not_be_changed' => trans('messages.password_could_not_be_changed')]);
                }
        }




    }


    public function showResendActivationCode(Request $request)
    {
        return view('auth.reactivate');
    }


    public function resendActivationCode(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|max:255|email',
        ]);


        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                return redirect(route('reactivate'))->withErrors(['reactivate_error' => $errorMessages[0], 'validator_errors' => $errorMessages,]);
            }
        }



        $user = User::where(['email'=>$request->email, 'activated_at'=>null])->first();
        if($user) {

            $user->notify(new \App\Notifications\ActivateAccount($user->activation_token));

            if ($request->expectsJson()) {
                return response()->json(['data' => ['message' => trans('messages.account_created')]], 200);
            } else {
                return redirect(route('activate'));
            }


        } else {
            if ($request->expectsJson()) {
                return ApiResponse::error("reactivate_user_not_found", trans('messages.reactivate_user_not_found'), 400);
            } else {
                return redirect(route('reactivate'))->withErrors(['reactivate_error' => trans('messages.reactivate_user_not_found')]);
            }
        }


    }


    public function showChangePasswordForm(Request $request)
    {
        return view('auth.change');
    }


    public function changePassword(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'old_password' => 'required|min:6',
            'new_password' => 'required|min:6',
            'password_confirmation' => 'required|same:new_password',
        ]);

        if ($validator->fails()) {
            $errorMessages = $validator->errors()->all();
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                return redirect(route('showChangePasswordForm'))->withErrors(['reactivate_error' => $errorMessages[0], 'validator_errors' => $errorMessages,]);
            }
        }

        if ($request->expectsJson()) {
            $user = $this->getAuthenticatedUserApi();
        } else {
            $user = Auth::user();
        }

        $credentials = [
            'email' => $user->email,
            'password' => $request->get('old_password'),
        ];


        if (!Auth::validate($credentials)) {
            if ($request->expectsJson()) {
                return ApiResponse::error("password_could_not_be_changed", trans('messages.password_could_not_be_changed'), 400);
            } else {
                return redirect(route('showChangePasswordForm'))
                    ->withErrors(['password_could_not_be_changed' => trans('messages.password_could_not_be_changed')]);
            }
        } else {

            $user->password = Hash::make($request->get('new_password'));
            $user->save();

            if ($request->expectsJson()) {
                return response()->json(['data' => [
                    'code' => 'password_changed',
                    'message' => trans('messages.password_changed')
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


