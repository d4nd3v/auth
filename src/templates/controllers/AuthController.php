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







    // return ApiResponse::error("bad_request", trans("messages.bad_request"), 400);

    public static function error($code, $message, $httpStatusCode, $errors=null, $extraProperties=null)
    {
        $error = ['code' => $code, 'message' => $message];
        if(!is_null($errors)) {
            $error['errors'] = $errors;
        }
        $responseJson = ['error' => $error];
        if(!is_null($extraProperties)) {
            $responseJson = array_merge($responseJson, $extraProperties);
        }
        return response()->json($responseJson, $httpStatusCode);
    }





    /* example:
    {
      "error": {
        "code": "validation_fails",
        "error": "First validation error - A human readable message providing more details.",
        "errors": {
          "validation": {
            "FIELD": "A human readable message providing more details about this field validation.",
            "FIELD2": "The FIELD2 field is required.",
            "password": "The password field is required."
          }
        }
      }
    }
    */
    public static function validationError($validator)
    {
        $errorMessages = $validator->errors()->all();
        $errors = ['validation' => array_combine($validator->errors()->keys(), $errorMessages)];
        return self::error("validation_fails", $errorMessages[0], 400, $errors);
    }

















    public function showLoginForm(Request $request)
    {
        return view('auth.login');
    }


    public function authenticate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|max:255',
            'password' => 'required',
        ]);

        $credentials = [
            'email'    => $request->input('email'),
            'password' => $request->input('password'),
        ];

        if ($validator->fails()) {
            if ($request->expectsJson()) {
                return ApiResponse::validationError($validator);
            } else {
                return redirect(route('login'))
                    ->withInput($request->only('email', 'remember'))
                    ->withErrors($validator->errors());
            }
        }

        if (!Auth::validate($credentials)) {
            if ($request->expectsJson()) {
                return ApiResponse::error("invalid_credentials", trans('auth-d4nd3v.invalid_credentials'), 401);
            } else {
                return redirect(route('login'))
                    ->withInput($request->only('email', 'remember'))
                    ->withErrors([ 'invalid_credentials' => trans('auth-d4nd3v.invalid_credentials') ]);
            }
        } else {
            $user = Auth::getLastAttempted();
            if ($user->account_disabled) {
                if ($request->expectsJson()) {
                    return ApiResponse::error("account_disabled", trans('auth-d4nd3v.account_disabled'), 401);
                } else {
                    return redirect(route('login'))
                        ->withInput($request->only('email', 'remember'))
                        ->withErrors([ 'account_disabled' => trans('auth-d4nd3v.account_disabled') ]);
                }
            } else if (!($user->active)) {
                if ($request->expectsJson()) {
                    return ApiResponse::error("email_not_confirmed", trans('auth-d4nd3v.email_not_confirmed'), 401);
                } else {
                    return redirect(route('login'))
                        ->withInput($request->only('email', 'remember'))
                        ->withErrors([ 'email_not_confirmed' => trans('auth-d4nd3v.email_not_confirmed') ]);
                }
            } else {
                // succes
                if ($request->expectsJson()) {
                     try {
                        if (! $token = \JWTAuth::attempt($credentials)) {
                            return ApiResponse::error("invalid_credentials", trans('auth-d4nd3v.invalid_credentials'), 401);
                        } else {
                            return response()->json([ 'data' => ['token'=>$token] ], 200);
                        }
                     } catch (JWTException $e) {
                         return ApiResponse::error("could_not_create_token", trans('auth-d4nd3v.could_not_create_token'), 500);
                     }
                } else {
                    Auth::login($user, $request->has('remember'));
                    return redirect()->intended();
                }
            }
        }
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
        $user = User::create(array_filter($newUser));


        $activationToken = str_random(60);
        Activation::create([
            'user_id' => $user->id,
            'token'   => $activationToken
        ]);



        $user->notify(new \App\Notifications\ActivateAccount($activationToken));

        if ($request->expectsJson()) {
            return response()->json(['data' => ['message' => trans('auth-d4nd3v.activation_mail_sent_again')]], 200);
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
                        'message' => trans('auth-d4nd3v.reset_email_sent')
                    ]], 200);
            } else {
                return back()->with('status', trans('auth-d4nd3v.reset_email_sent'));
            }
        }

        if ($request->expectsJson()) {
            return ApiResponse::error("reset_email_not_sent", trans('auth-d4nd3v.reset_email_not_sent'), 400);
        } else {
            return back()->withErrors(['email' => trans('auth-d4nd3v.reset_email_not_sent')]);
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
                        'message' => trans('auth-d4nd3v.password_changed')
                    ]], 200);
                } else {
                    return view('auth.changed');
                }
            default:
                if ($request->expectsJson()) {
                    return ApiResponse::error("password_could_not_be_changed", trans('auth-d4nd3v.password_could_not_be_changed'), 400);
                } else {
                    return redirect(route('showResetForm', [$request->input('token')]))
                        ->withInput($request->except('password', 'confirm_password'))
                        ->withErrors(['password_could_not_be_changed' => trans('auth-d4nd3v.password_could_not_be_changed')]);
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



        $user = User::where(['email'=>$request->email, 'active'=>0])->first();
        if($user) {

            $user->notify(new \App\Notifications\ActivateAccount($user->activation->token));

            if ($request->expectsJson()) {
                return response()->json(['data' => ['message' => trans('auth-d4nd3v.account_created')]], 200);
            } else {
                return redirect(route('activate'));
            }


        } else {
            if ($request->expectsJson()) {
                return ApiResponse::error("reactivate_user_not_found", trans('auth-d4nd3v.reactivate_user_not_found'), 400);
            } else {
                return redirect(route('reactivate'))->withErrors(['reactivate_error' => trans('auth-d4nd3v.reactivate_user_not_found')]);
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
                return ApiResponse::error("password_could_not_be_changed", trans('auth-d4nd3v.password_could_not_be_changed'), 400);
            } else {
                return redirect(route('showChangePasswordForm'))
                    ->withErrors(['password_could_not_be_changed' => trans('auth-d4nd3v.password_could_not_be_changed')]);
            }
        } else {

            $user->password = Hash::make($request->get('new_password'));
            $user->save();

            if ($request->expectsJson()) {
                return response()->json(['data' => [
                    'code' => 'password_changed',
                    'message' => trans('auth-d4nd3v.password_changed')
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


