<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use Illuminate\Support\Facades\Hash;



class AuthenticationController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $request->validated();

        $userData = $request->only('name', 'username', 'email', 'password');

        $userData['password'] = bcrypt($userData['password']);

        $user = User::create($userData);
        $token = $user->createToken('auth_token')->plainTextToken;
            
        return response()->json([
            // 'access_token' => $token,
            // 'token_type' => 'Bearer',
            'user' => $user,
            'token' => $token
        ], 201);
    }

    public function login(LoginRequest $request)
    {
        $request->validated();

        $user= User::whereUsername($request->username)->first();
        if(!$user || !Hash::check($request->password, $user->password)){
            return response([
                'message' => ['These credentials do not match our records.']
            ], 422);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response([
            // 'access_token' => $token,
            // 'token_type' => 'Bearer',
            'user' => $user,
            'token' => $token
        ], 200);

        // $credentials = $request->only('username', 'password');

        // if (!Auth::attempt($credentials)) {
        //     return response()->json([
        //         'message' => 'Invalid credentials'
        //     ], 401);
        // }

        // $user = User::where('username', $credentials['username'])->first();
        // $token = $user->createToken('auth_token')->plainTextToken;

        // return response()->json([
        //     // 'access_token' => $token,
        //     // 'token_type' => 'Bearer',
        //     'user' => $user,
        //     'token' => $token
        // ], 200);
    }

}
