@extends('layouts.master')


@section('content')


    @if($errors->any())
        <div class="alert alert-danger alert-dismissible" role="alert">
          <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
          {{$errors->first()}}
        </div>
    @endif


    <form action="{{ url('/password/reset') }}" method="post" style="margin-top: 20px;">
        {{ csrf_field() }}
        <input type="hidden" name="token" value="{{ $token }}">

        <div class="form-group @if ($errors->has('email')) has-error @endif">
            <input type="text" name="email" class="form-control" required="required" value="{{ old('email') }}" placeholder="Email address">
            <span style="color: #e51c23;">{{ $errors->first('email') }}</span>
        </div>

        <div class="form-group @if ($errors->has('password')) has-error @endif">
            <input type="password" name="password" class="form-control" required="required" placeholder="New password">
            <span style="color: #e51c23;">{{ $errors->first('password') }}</span>
        </div>

        <div class="form-group @if ($errors->has('password_confirmation')) has-error @endif">
            <input type="password" name="password_confirmation" class="form-control"
                   required="required" placeholder="Confirm new password">
            <span style="color: #e51c23;">{{ $errors->first('password_confirmation') }}</span>
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 20px;">Change password</button>
    </form>


@stop









