<?php

namespace App\Exceptions;

use Exception;

class ApiException extends Exception
{

    public $apiExceptionResponse;

    public function __construct($code, $errors=null, $customMessage=null, $httpStatusCode=null)
    {

        if ($code=="validation") {
            $message = isset($errors) ? (reset($errors)) : ""; // first element
            $httpStatusCode = 422; // 422 Unprocessable Entity
        } else if ($code=="bad_request") {
            $message = trans("auth2.bad_request");
            $httpStatusCode = 400; // 400 Bad Request
        } else if($code=="token_not_provided") {
            $message = trans("auth2.token_not_provided");
            $httpStatusCode = 400; // 400 Bad Request
        } else if($code=="token_expired") {
            $message = trans("auth2.token_expired");
            $httpStatusCode = 401; // 401 Unauthorized (unauthenticated)
        } else if($code=="token_invalid") {
            $message = trans("auth2.token_invalid");
            $httpStatusCode = 401; // 401 Unauthorized (unauthenticated)
        } else if($code=="unauthenticated") {
            $message = trans("auth2.unauthenticated");
            $httpStatusCode = 401; // 401 Unauthorized (unauthenticated)
        } else if($code=="not_found") {
            $message = trans("auth2.not_found");
            $httpStatusCode = 404; // 404 Not Found
        } else if($code=="pdo_exception") {
            $message = trans("auth2.pdo_exception");
            $httpStatusCode = 500; // 500 Internal Server Error
        } else if($code=="invalid_role") {
            $message = trans("auth2.invalid_role");
            $httpStatusCode = 403; // 403 Forbidden
        } else if($code=="invalid_permission") {
            $message = trans("auth2.invalid_permission");
            $httpStatusCode = 403; // 403 Forbidden
        } else if($code=="invalid_credentials") {
            $message = trans("auth2.invalid_credentials");
            $httpStatusCode = 401; // 401 Unauthorized (unauthenticated)
        } else if($code=="account_inactive") {
            $message = trans("auth2.account_inactive");
            $httpStatusCode = 403;
        } else if($code=="could_not_create_token") {
            $message = trans("auth2.could_not_create_token");
            $httpStatusCode = 500;
        } else if($code=="reset_email_not_sent") {
            $message = trans("auth2.reset_email_not_sent");
            $httpStatusCode = 400; // 400 Bad Request
        } else if($code=="password_could_not_be_changed") {
            $message = trans("auth2.password_could_not_be_changed");
            $httpStatusCode = 400; // 400 Bad Request
        } else if($code=="account_disabled") {
            $message = trans("auth2.account_disabled");
            $httpStatusCode = 403;
        } else if($code=="email_not_confirmed") {
            $message = trans("auth2.email_not_confirmed");
            $httpStatusCode = 403;
        } else if($code=="reactivate_user_not_found") {
            $message = trans("auth2.reactivate_user_not_found");
            $httpStatusCode = 400;
        } else if($code=="throttle") {
            $message = trans("auth2.throttle");
            $httpStatusCode = 400;
        }  else {
            $message = trans("auth2.exception");
            $httpStatusCode = 500;
        }

        if(!is_null($customMessage)) {
            $message = $customMessage;
        }

        $responseJson = ['error' => ['code' => $code, 'message' => $message]];
        if(!is_null($errors)) {
            $responseJson['error']['errors'] = $errors;
        }


        if(false) {
            $apiErrorLog = new ApiErrorLog;
            $apiErrorLog->url = (request()->url());
            $apiErrorLog->method = (request()->method());
            $apiErrorLog->user_id = (Auth::check() ? Auth::user()->id : null);
            $apiErrorLog->response = json_encode($responseJson);
            $apiErrorLog->request_data = json_encode(request()->all());
            $apiErrorLog->headers = json_encode(request()->header());
            $apiErrorLog->ip = request()->ip();
            $apiErrorLog->inserted_at = Carbon::now();
            $apiErrorLog->save();
        }




        $this->apiExceptionResponse = response()->json($responseJson, $httpStatusCode);
    }



}