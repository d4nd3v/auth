@extends('layouts.master')



@section('content')

    <p>
        Before you can login, you must active your account with the code sent to your email address.
        <br>
        Please check your email and click the link.

        <br>

        <br>

        <div class="alert alert-success alert-dismissible" role="alert">
            <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            Activation mail sent.
        </div>


        If you did not receive this email, please check your junk/spam folder.
        <br>
        Click <a href="{{ route('reactivate') }}">here</a> to resend the activation email.
    </p>


@stop



















