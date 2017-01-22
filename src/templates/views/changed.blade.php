@extends('layouts.master')


@section('content')



    <div class="alert alert-success alert-dismissible" role="alert">
        <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
        Your password has been changed.
    </div>

    <a href="{{ route('login') }}">Proceed with the login process</a>



@stop


