@extends('layouts.master')

@section('content')


            @if($errors->any())
                <div class="alert alert-danger alert-dismissible" role="alert">
                  <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                  {{$errors->first()}}
                </div>
            @endif



            @if($errors->has('email_not_confirmed'))
                Click <a href="{{ route('reactivate') }}">here</a> to resend the activation email.
            @endif



            <form action="{{ route('login') }}" method="post" style="margin-top: 20px;">
                {{ csrf_field() }}

                <div class="form-group">
                    <input type="text" id="email" name="email" class="form-control" required="required"
                           value="{{ old('email') }}" placeholder="Email address">
                </div>

                <div class="form-group">
                    <input type="password" id="password" name="password"
                           class="form-control" required="required" placeholder="Password">
                </div>


                <div class="row">

                    <div class="col-xs-6">

                        <div class="checkbox" style="margin-top:0px;">
                            <label>
                                <input type="checkbox" name="remember" checked="checked">Remember me
                            </label>
                        </div>

                    </div>

                    <div class="col-xs-6" style="text-align: right;">


                        <a href="{{ url('/password/reset') }}">
                            Forgot password?
                        </a>

                    </div>




                </div>



                <div class="form-group">

                    <button type="submit" class="btn btn-primary btn-sm">Log in</button>


                </div>

            </form>



        Test users:
        <a href="javasript:;" onclick="$('#email').val('super@x.x'); $('#password').val('xxxxxx');">super@x.x</a>






@stop





