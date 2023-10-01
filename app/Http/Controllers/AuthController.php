<?php

namespace App\Http\Controllers;

use App\Models\User;
use Auth;
use Hash;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        //validar la informaacion del cliente
        $validatedData = $request->validate([
            'name' => 'required|string|max:50',
            'password' => 'required|string|min:8',
            'phone' => 'required|string|min:1',
        ]);

        $user = User::create([
            'name' => $validatedData['name'],
            'password' => Hash::make($validatedData['password']),
            'phone' => $validatedData['phone'],
        ]);

        //se crea token de acceso personal para el usuario
        $token = $user->createToken('auth_token')->plainTextToken;

        //se devuelve una respuesta JSON con el token generado y el tipo de token
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer'
        ]);
    }

    public function login(Request $request)
    {
        //valida las credenciales del usuario
        if (!Auth::attempt($request->only('phone', 'password'))) {
            return response()->json([
                'message' => 'Invalid access credentials'
            ], 401);
        }

        //Busca al usuario en la base de datos
        $user = User::where('phone', $request['phone'])->firstOrFail();

        //Genera un nuevo token para el usuario
        $token = $user->createToken('auth_token')->plainTextToken;

        //devuelve una respuesta JSON con el token generado y el tipo de token
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer'
        ]);
    }

    public function getUserData(Request $request)
    {
        // obtener informacion a travess de un modelo 
        return $request->user();
    }
}