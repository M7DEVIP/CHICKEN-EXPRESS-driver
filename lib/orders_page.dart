import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:logger/logger.dart';
import 'package:url_launcher/url_launcher.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Orders App',
      theme: ThemeData(
        primarySwatch: Colors.deepPurple,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: const OrdersPage(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class OrdersPage extends StatefulWidget {
  const OrdersPage({super.key});

  @override
  OrdersPageState createState() => OrdersPageState();
}

class OrdersPageState extends State<OrdersPage> {
  final Logger logger = Logger();
  List orders = [];
  bool isLoading = true;

  @override
  void initState() {
    super.initState();
    fetchOrders();
  }

  Future<void> fetchOrders() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    String? accessToken = prefs.getString('access_token');

    if (accessToken == null) {
      logger.e('Access token is missing.');
      throw Exception('Access token is missing');
    }

    final response = await http.get(
      Uri.parse('http://192.168.88.25:8082/api/orders'),
      headers: <String, String>{
        'Content-Type': 'application/json; charset=UTF-8',
        'Authorization': 'Bearer $accessToken',
      },
    );

    if (response.statusCode == 200) {
      setState(() {
        orders = json.decode(response.body);
        isLoading = false;
      });
    } else {
      logger.e('Failed to load orders. Status code: ${response.statusCode}');
      logger.e('Response body: ${response.body}');
      throw Exception('Failed to load orders');
    }
  }

  void showOrderDetails(BuildContext context, Map order) {
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(25.0)),
      ),
      isScrollControlled: true,
      builder: (BuildContext context) {
        return Container(
          padding: const EdgeInsets.all(20.0),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius:
                const BorderRadius.vertical(top: Radius.circular(25.0)),
            boxShadow: [
              BoxShadow(
                color: Colors.grey.withOpacity(0.5),
                spreadRadius: 5,
                blurRadius: 7,
                offset: const Offset(0, 3),
              ),
            ],
          ),
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Center(
                  child: Text(
                    'Order #${order['ordercode']}',
                    style: const TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      color: Colors.deepPurple,
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                Container(
                  padding: const EdgeInsets.all(15.0),
                  decoration: BoxDecoration(
                    color: Colors.deepPurple.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      buildOrderDetailRow(
                          Icons.phone, 'رقم الهاتف:', order['phone'],
                          isPhone: true),
                      const SizedBox(height: 10),
                      buildOrderDetailRow(
                          Icons.location_on, 'العنوان:', order['address_dec'],
                          isLocation: true, hiddenText: order['address']),
                    ],
                  ),
                ),
                const SizedBox(height: 20),
                Container(
                  padding: const EdgeInsets.all(15.0),
                  decoration: BoxDecoration(
                    color: Colors.yellow.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: buildOrderDetailRow(Icons.attach_money,
                      'التكلفة الإجمالية:', '${order['total_cost']} دينار'),
                ),
                const SizedBox(height: 20),
                Container(
                  padding: const EdgeInsets.all(15.0),
                  decoration: BoxDecoration(
                    color: Colors.green.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'الطلب:',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: Colors.black,
                        ),
                      ),
                      const SizedBox(height: 10),
                      ConstrainedBox(
                        constraints: const BoxConstraints(
                          maxHeight:
                              150.0, // تحديد ارتفاع مناسب لتمرير الطلبات الطويلة
                        ),
                        child: SingleChildScrollView(
                          child: Text(
                            order['order'],
                            style: const TextStyle(
                                fontSize: 16, color: Colors.black),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 20),
                Center(
                  child: GestureDetector(
                    onLongPress: () {
                      handleOrderAcceptance(order['ordercode']);
                      Navigator.pop(context);
                    },
                    child: InkWell(
                      onTap: () {}, // لجعل InkWell يستجيب للتفاعلات البصرية
                      child: Container(
                        decoration: BoxDecoration(
                          color: Colors.deepPurple,
                          borderRadius: BorderRadius.circular(30),
                        ),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 50, vertical: 15),
                        child: const Column(
                          children: [
                            Text(
                              'حجز الطلب',
                              style:
                                  TextStyle(fontSize: 16, color: Colors.white),
                            ),
                            Text(
                              '(اضغط مطولا للتأكيد)',
                              style: TextStyle(
                                  fontSize: 12, color: Colors.white70),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget buildOrderDetailRow(IconData icon, String label, String text,
      {bool isPhone = false, bool isLocation = false, String? hiddenText}) {
    return Row(
      children: [
        Icon(icon, color: Colors.deepPurple),
        const SizedBox(width: 10),
        Text(
          label,
          style: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Colors.black54,
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: GestureDetector(
            onTap: () => isPhone
                ? _launchCaller(text)
                : isLocation
                    ? _launchMap(hiddenText ?? text)
                    : null,
            child: Text(
              text,
              style: const TextStyle(
                fontSize: 16,
                color: Colors.blue,
                decoration: TextDecoration.underline,
              ),
            ),
          ),
        ),
      ],
    );
  }

  void _launchCaller(String number) async {
    final Uri url = Uri(scheme: 'tel', path: number);
    if (await canLaunchUrl(url)) {
      await launchUrl(url);
    } else {
      logger.e('Could not launch $url');
    }
  }

  Future<void> _launchMap(String address) async {
    final coordinates = address.split(',');
    final lat = coordinates[0].trim();
    final lng = coordinates[1].trim();

    final Uri url = Uri.parse("https://waze.com/ul?ll=$lat,$lng&navigate=yes");
    if (await canLaunchUrl(url)) {
      await launchUrl(url);
    } else {
      logger.e('Could not launch $url');
    }
  }

  void handleOrderAcceptance(String orderCode) {
    logger.i('Order #$orderCode has been accepted');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.black,
        title: const Center(
          child: Text(
            'Orders',
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
        ),
      ),
      body: isLoading
          ? const Center(child: CircularProgressIndicator())
          : ListView.builder(
              itemCount: orders.length,
              itemBuilder: (context, index) {
                final order = orders[index];
                return Padding(
                  padding: const EdgeInsets.symmetric(
                      vertical: 8.0, horizontal: 16.0),
                  child: Card(
                    elevation: 4,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(15.0),
                    ),
                    child: ListTile(
                      contentPadding: const EdgeInsets.all(16.0),
                      leading: Container(
                        padding: const EdgeInsets.all(8.0),
                        decoration: BoxDecoration(
                          color: Colors.deepPurple.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(10.0),
                        ),
                        child: const Icon(
                          Icons.restaurant_menu,
                          color: Colors.deepPurple,
                          size: 30,
                        ),
                      ),
                      title: Text(
                        'Order #${order['ordercode']}',
                        style: const TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      subtitle: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const SizedBox(height: 5),
                          Row(
                            children: [
                              const Icon(Icons.location_on, color: Colors.red),
                              const SizedBox(width: 5),
                              Expanded(
                                child: GestureDetector(
                                  onTap: () => _launchMap(order['address']),
                                  child: Text(
                                    order['address_dec'],
                                    style: const TextStyle(
                                      fontSize: 16,
                                      color: Colors.blue,
                                      decoration: TextDecoration.underline,
                                    ),
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 5),
                          Row(
                            children: [
                              const Icon(Icons.phone, color: Colors.blue),
                              const SizedBox(width: 5),
                              Text(
                                order['phone'],
                                style: const TextStyle(fontSize: 16),
                              ),
                            ],
                          ),
                        ],
                      ),
                      trailing: Container(
                        decoration: BoxDecoration(
                          color: Colors.deepPurple,
                          borderRadius: BorderRadius.circular(10.0),
                        ),
                        padding: const EdgeInsets.all(8.0),
                        child: const Icon(
                          Icons.arrow_forward_ios,
                          color: Colors.white,
                        ),
                      ),
                      onTap: () {
                        showOrderDetails(context, order);
                      },
                    ),
                  ),
                );
              },
            ),
    );
  }
}
