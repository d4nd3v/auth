@extends('layouts.master')


@section('content')


        @if($errors->any())
            <div class="alert alert-danger alert-dismissible" role="alert">
              <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
              {{$errors->first()}}
            </div>
        @endif


        <form action="{{ route('reactivate') }}" method="post" style="margin-top: 20px;">
            {{ csrf_field() }}

            <div class="form-group">
                <input type="text" id="email" name="email" class="form-control" required="required"
                       value="{{ old('email') }}" placeholder="Email address">
            </div>

            <div class="form-group">

                <button type="submit" class="btn btn-primary btn-sm">Send</button>

            </div>

        </form>



        <a href="{{ route('login') }}">Back to login</a>


@stop





