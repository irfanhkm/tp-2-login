<?php
namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;

class LoginController {

    public function viewHome() {
        return view("welcome");
    }

    public function viewLogin() {
        if (Auth::check()) {
            return redirect()->route('home');
        }
        return view("login");
    }

    public function viewResetPassword() {
        return view("reset_password");
    }

    public function viewRegister(Request $request) {
        if (Auth::check()) {
            return redirect()->route('home');
        }
        return view("register");
    }

    public function logout() {
        Auth::logout();
        return redirect()->route('login');
    }

    public function login(Request $request) {
        if (
            Auth::attempt(['email' => $request->email, 'password' => $request->password])
        ) {
            return redirect()->route('home');
        }

        $hashEmail = md5($request->get('email'));


        $cookieEmail = Cookie::get($hashEmail);
        if ($cookieEmail != null) {
            return redirect()
                ->route('login')
                ->withErrors([
                    'error' => 'to much try password, please wait'
                ])
                ->cookie($cookieEmail);
        }


        if (User::where('email', $request->email)->exists()) {
            session()->increment($hashEmail);
            if (session()->get($hashEmail) == 3) {
                $cookie = cookie($hashEmail, 'value', 0.2);
                session()->forget($hashEmail);
                return redirect()
                    ->route('login')
                    ->withErrors([
                        'error' => 'email / password wrong'
                    ])
                    ->cookie($cookie);
            }
        }

        return redirect()
            ->route('login')
            ->withErrors([
                'error' => 'email / password wrong'
            ]);
    }

    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'password' => [
                'required',
                'string',
                'min:10',
                'max:25',
                'regex:/(^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$)/u'
            ],
        ], [
            'password.regex' =>
                'Password consists of a combination of lowercase letters, uppercase letters, numbers, and symbols'
        ]);

        if ($validator->fails()) {
            return redirect()
                ->route('register')
                ->withErrors([
                    'error' => implode(" ", $validator->messages()->all())
                ]);
        }

        $isExists = User::query()->where(['email' => $request->email])->exists();
        if ($isExists) {
            return redirect()
                ->route('register')
                ->withErrors([
                    'error' => 'email already registered'
                ]);
        }

        User::query()->create([
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);
        return redirect()->route('login')
            ->with([
                'success' => 'register success'
            ]);
    }

    public function resetPassword(Request $request) {
        $validator = Validator::make($request->all(), [
            'current_password' => ['required'],
            'password' => [
                'required',
                'string',
                'min:10',
                'max:25',
                'regex:/(^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$)/u',
                'confirmed'
            ],
        ], [
            'password.regex' =>
                'Password consists of a combination of lowercase letters, uppercase letters, numbers, and symbols'
        ]);

        if (!Hash::check($request->get('current_password'), Auth::user()->password)) {
            return redirect()
                ->route('reset-password')
                ->withErrors([
                    'error' => 'Current password not same'
                ]);
        }

        if ($validator->fails()) {
            return redirect()
                ->route('reset-password')
                ->withErrors([
                    'error' => implode(" ", $validator->messages()->all())
                ]);
        }

        Auth::user()->update([
            'password' => Hash::make($request->get('password'))
        ]);
        return redirect()->route('reset-password')
            ->with([
                'success' => 'reset password success'
            ]);
    }
}
