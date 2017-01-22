@extends('layouts.master')



@section('content')


        @if($errors->any())
            <div class="alert alert-danger alert-dismissible" role="alert">
              <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
              {{$errors->first()}}
            </div>
        @endif


        <form action="{{ route('changePassword') }}" method="post" style="margin-top: 20px;">
            {{ csrf_field() }}

            <div class="form-group">
                <input type="password" id="old_password" name="old_password" class="form-control" required="required"
                       value="" placeholder="Current Password">
            </div>

            <div class="form-group">
                <input type="password" id="new_password" name="new_password"
                       class="form-control" required="required" placeholder="New Password">
            </div>

            <div class="form-group">
                <input type="password" id="password_confirmation" name="password_confirmation"
                       class="form-control" required="required" placeholder="Password Confirmation">
            </div>


            <div class="form-group">
                <button type="submit" class="btn btn-primary btn-sm">Change password</button>
            </div>

        </form>



@stop





