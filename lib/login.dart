import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'home.dart'; // تأكد من أن هذا الاستيراد صحيح ويتطابق مع المسار الصحيح لصفحة الرئيسية

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  LoginPageState createState() => LoginPageState();
}

class LoginPageState extends State<LoginPage> {
  final TextEditingController _usernameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  String _errorMessage = '';
  String? _token; // تخزين التوكن

  Future<void> _login() async {
    setState(() {
      _errorMessage = '';
    });

    try {
      final response = await http.post(
        Uri.parse('http://192.168.88.25:8082/api/login'),
        headers: <String, String>{
          'Content-Type': 'application/json; charset=UTF-8',
        },
        body: jsonEncode(<String, String>{
          'username': _usernameController.text,
          'password': _passwordController.text,
        }),
      );

      if (!mounted) return;

      if (response.statusCode == 200) {
        final responseBody = jsonDecode(utf8.decode(response.bodyBytes));
        if (responseBody['status'] == 'success') {
          _token = responseBody['access_token']; // الحصول على التوكن
          SharedPreferences prefs = await SharedPreferences.getInstance();
          await prefs.setString('access_token', _token!);

          // التنقل إلى HomePage مع تمرير اسم المستخدم والتوكن
          Navigator.pushReplacement(
            // ignore: use_build_context_synchronously
            context,
            MaterialPageRoute(
              builder: (context) =>
                  HomePage(userName: responseBody['name'], token: _token!),
            ),
          );
        } else {
          setState(() {
            _errorMessage = responseBody['error'] ?? 'Unknown error occurred';
          });
        }
      } else {
        setState(() {
          _errorMessage = jsonDecode(utf8.decode(response.bodyBytes))['error'];
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Error: Could not connect to server: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1A1A1A),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              Image.asset(
                'assets/logo.png',
                height: 200,
              ),
              const SizedBox(height: 5),
              const Text(
                'Tasleem',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Color.fromARGB(255, 6, 137, 76),
                ),
              ),
              const SizedBox(height: 15),
              TextField(
                controller: _usernameController,
                style: const TextStyle(color: Colors.white),
                decoration: const InputDecoration(
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.all(Radius.circular(10)),
                  ),
                  labelText: 'Username',
                  labelStyle: TextStyle(color: Colors.white),
                  prefixIcon: Icon(Icons.person, color: Color(0xFF53BBD7)),
                  filled: true,
                  fillColor: Color(0xFF333333),
                  focusedBorder: OutlineInputBorder(
                    borderSide: BorderSide(color: Color(0xFF53BBD7)),
                    borderRadius: BorderRadius.all(Radius.circular(10)),
                  ),
                ),
              ),
              const SizedBox(height: 15),
              TextField(
                controller: _passwordController,
                obscureText: true,
                style: const TextStyle(color: Colors.white),
                decoration: const InputDecoration(
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.all(Radius.circular(10)),
                  ),
                  labelText: 'Password',
                  labelStyle: TextStyle(color: Colors.white),
                  prefixIcon: Icon(Icons.lock, color: Color(0xFF53BBD7)),
                  filled: true,
                  fillColor: Color(0xFF333333),
                  focusedBorder: OutlineInputBorder(
                    borderSide: BorderSide(color: Color(0xFF53BBD7)),
                    borderRadius: BorderRadius.all(Radius.circular(10)),
                  ),
                ),
              ),
              const SizedBox(height: 20),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF53BBD7),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 50, vertical: 15),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
                onPressed: _login,
                child: const Text(
                  'Login',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
              ),
              const SizedBox(height: 15),
              Text(
                _errorMessage,
                style: const TextStyle(color: Colors.red),
              ),
              const SizedBox(height: 10),
              TextButton(
                onPressed: () {
                  // Navigate to Forgot Password page
                },
                child: const Text(
                  'Forgot Password?',
                  style: TextStyle(
                    color: Color(0xFF53BBD7),
                    decoration: TextDecoration.underline,
                  ),
                ),
              ),
              TextButton(
                onPressed: () {
                  // Navigate to Create Account page
                },
                child: const Text(
                  'Create Account',
                  style: TextStyle(
                    color: Color(0xFF53BBD7),
                    decoration: TextDecoration.underline,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
