@extends('layouts.master')

@section('content')


        @if($errors->any())
            <div class="alert alert-danger alert-dismissible" role="alert">
              <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
              {{$errors->first()}}
            </div>
        @endif

        @if (session('status'))

            <div class="alert alert-success alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                {{ session('status') }}
            </div>

            <a href="{{ route('login') }}">Proceed with the login process</a>

        @else


            <form class="form-horizontal" role="form" method="POST" action="{{ url('/password/email') }}">
                {{ csrf_field() }}

                <div class="form-group">
                    <div>
                        <input placeholder="Email address" id="email" class="form-control" name="email" value="{{ old('email') }}" required>
                    </div>
                </div>

                <div class="form-group">
                    <button type="submit" class="btn btn-primary">
                        Send password reset link
                    </button>
                </div>
            </form>


            <a href="{{ route('login') }}">Back to login</a>


        @endif


@stop









