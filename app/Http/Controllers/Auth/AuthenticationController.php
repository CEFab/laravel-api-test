<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;



class AuthenticationController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $request->validated();

        $userData = $request->only('name', 'username', 'email', 'password');

        // $userData['password'] = bcrypt($userData['password']);

        $user = User::create($userData);
        $token = $user->createToken('auth_token')->plainTextToken;
            
        return response()->json([
            // 'access_token' => $token,
            // 'token_type' => 'Bearer',
            'user' => $user,
            'token' => $token
        ], 201);
    }

}
