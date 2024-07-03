import 'package:flutter/material.dart';
import 'login.dart'; // تأكد من أن هذا الاستيراد صحيح ويتطابق مع اسم الملف الذي يحتوي على LoginPage

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Taslim',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const LoginPage(), // توجيه المستخدم إلى واجهة تسجيل الدخول مباشرة
      debugShowCheckedModeBanner: false, // إلغاء عرض علامة الديباغ
    );
  }
}
